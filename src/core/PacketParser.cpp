#include "core/PacketParser.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <utility>
#include <vector>

namespace netobserver {
namespace {

std::uint16_t readU16(const std::uint8_t* data)
{
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8U) |
        static_cast<std::uint16_t>(data[1]));
}

std::uint32_t readU32(const std::uint8_t* data)
{
    return
        (static_cast<std::uint32_t>(data[0]) << 24U) |
        (static_cast<std::uint32_t>(data[1]) << 16U) |
        (static_cast<std::uint32_t>(data[2]) << 8U) |
        static_cast<std::uint32_t>(data[3]);
}

std::string macToString(const std::uint8_t* data)
{
    char buffer[18]{};
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        data[0], data[1], data[2], data[3], data[4], data[5]);
    return buffer;
}

std::string ipv4ToString(const std::uint8_t* data)
{
    char buffer[16]{};
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%u.%u.%u.%u",
        static_cast<unsigned>(data[0]),
        static_cast<unsigned>(data[1]),
        static_cast<unsigned>(data[2]),
        static_cast<unsigned>(data[3]));
    return buffer;
}

std::string ipv6ToString(const std::uint8_t* data)
{
    std::array<std::uint16_t, 8> words{};
    for (std::size_t index = 0; index < words.size(); ++index)
        words[index] = readU16(data + index * 2);

    std::size_t bestStart = words.size();
    std::size_t bestLength = 0;
    for (std::size_t index = 0; index < words.size();) {
        if (words[index] != 0) {
            ++index;
            continue;
        }
        const std::size_t start = index;
        while (index < words.size() && words[index] == 0)
            ++index;
        const std::size_t length = index - start;
        if (length >= 2 && length > bestLength) {
            bestStart = start;
            bestLength = length;
        }
    }

    std::ostringstream output;
    output << std::hex;
    for (std::size_t index = 0; index < words.size();) {
        if (index == bestStart) {
            output << "::";
            index += bestLength;
            continue;
        }
        if (output.tellp() > 0 && !(bestStart == index - bestLength))
            output << ':';
        output << words[index];
        ++index;
    }
    std::string result = output.str();
    if (result.empty())
        return "::";
    if (result.rfind(":::", 0) == 0)
        result.erase(0, 1);
    return result;
}

std::string hex16(std::uint16_t value)
{
    char buffer[7]{};
    std::snprintf(buffer, sizeof(buffer), "0x%04X", value);
    return buffer;
}

std::string protocolName(std::uint8_t protocol)
{
    switch (protocol) {
    case 1:
        return "ICMP";
    case 2:
        return "IGMP";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 58:
        return "ICMPv6";
    default:
        return "IPv4-" + std::to_string(protocol);
    }
}

std::string tcpFlagsToString(std::uint8_t flags)
{
    std::string text;
    const auto append = [&text](bool enabled, const char* name) {
        if (!enabled)
            return;
        if (!text.empty())
            text += ',';
        text += name;
    };

    append((flags & 0x01U) != 0, "FIN");
    append((flags & 0x02U) != 0, "SYN");
    append((flags & 0x04U) != 0, "RST");
    append((flags & 0x08U) != 0, "PSH");
    append((flags & 0x10U) != 0, "ACK");
    append((flags & 0x20U) != 0, "URG");
    return text.empty() ? "none" : text;
}

std::string icmpTypeName(std::uint8_t type)
{
    switch (type) {
    case 0:
        return "Echo Reply";
    case 3:
        return "Destination Unreachable";
    case 8:
        return "Echo Request";
    case 11:
        return "Time Exceeded";
    default:
        return "Type " + std::to_string(type);
    }
}

std::string igmpTypeName(std::uint8_t type)
{
    switch (type) {
    case 0x11:
        return "Membership Query";
    case 0x12:
        return "IGMPv1 Membership Report";
    case 0x16:
        return "IGMPv2 Membership Report";
    case 0x17:
        return "Leave Group";
    case 0x22:
        return "IGMPv3 Membership Report";
    default:
        return "Type " + std::to_string(type);
    }
}

std::string textLine(const std::uint8_t* data, std::size_t length)
{
    std::string line;
    line.reserve(std::min<std::size_t>(length, 192));

    for (std::size_t index = 0; index < length && line.size() < 192; ++index) {
        const auto character = data[index];
        if (character == '\r') {
            if (index + 1 < length && data[index + 1] == '\n')
                continue;
            break;
        }
        if (character == '\n')
            break;
        if (character >= 32 && character <= 126)
            line.push_back(static_cast<char>(character));
        else if (character == '\t')
            line.push_back(' ');
        else
            line.push_back('.');
    }
    return line;
}

bool startsWith(const std::string& value, const char* prefix)
{
    return value.rfind(prefix, 0) == 0;
}

std::string lowerAscii(std::string value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

std::string trim(std::string value)
{
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.front())))
        value.erase(value.begin());
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    return value;
}

bool parseDnsName(
    const std::uint8_t* data,
    std::size_t length,
    std::size_t& offset,
    std::string& name,
    int depth = 0)
{
    if (depth > 8 || offset >= length)
        return false;

    std::string result;
    std::size_t cursor = offset;
    std::size_t nextOffset = offset;
    bool jumped = false;

    while (cursor < length) {
        const std::uint8_t labelLength = data[cursor];
        if (labelLength == 0) {
            if (!jumped)
                nextOffset = cursor + 1;
            break;
        }
        if ((labelLength & 0xC0U) == 0xC0U) {
            if (cursor + 1 >= length)
                return false;
            const std::size_t pointer =
                (static_cast<std::size_t>(labelLength & 0x3FU) << 8U) |
                data[cursor + 1];
            if (!jumped)
                nextOffset = cursor + 2;
            jumped = true;
            std::string suffix;
            std::size_t pointerOffset = pointer;
            if (!parseDnsName(
                    data,
                    length,
                    pointerOffset,
                    suffix,
                    depth + 1)) {
                return false;
            }
            if (!result.empty() && !suffix.empty())
                result += '.';
            result += suffix;
            break;
        }
        if ((labelLength & 0xC0U) != 0 || cursor + 1 + labelLength > length)
            return false;
        if (!result.empty())
            result += '.';
        result.append(
            reinterpret_cast<const char*>(data + cursor + 1),
            labelLength);
        cursor += 1 + labelLength;
        if (result.size() > 253)
            return false;
    }

    if (!jumped)
        nextOffset = cursor + 1;
    offset = nextOffset;
    name = result;
    return true;
}

void parseDns(
    ParsedPacket& packet,
    const std::uint8_t* payload,
    std::size_t length,
    bool tcp)
{
    if (!payload)
        return;
    if (tcp) {
        if (length < 2)
            return;
        const std::size_t declared = readU16(payload);
        payload += 2;
        length = std::min(length - 2, declared);
    }
    if (length < 12)
        return;

    packet.applicationProtocol = "DNS";
    packet.dnsTransactionId = readU16(payload);
    const std::uint16_t flags = readU16(payload + 2);
    packet.dnsResponse = (flags & 0x8000U) != 0;
    packet.dnsResponseCode = static_cast<std::uint8_t>(flags & 0x000FU);
    const std::uint16_t questionCount = readU16(payload + 4);
    const std::uint16_t answerCount = readU16(payload + 6);

    std::size_t offset = 12;
    std::string names;
    for (std::uint16_t index = 0;
         index < questionCount && index < 8;
         ++index) {
        std::string name;
        if (!parseDnsName(payload, length, offset, name))
            break;
        if (!names.empty())
            names += ", ";
        names += name;
        if (packet.dnsQueryName.empty())
            packet.dnsQueryName = name;
        if (offset + 4 > length)
            break;
        offset += 4;
    }

    std::string answers;
    for (std::uint16_t index = 0;
         index < answerCount && index < 8;
         ++index) {
        std::string owner;
        if (!parseDnsName(payload, length, offset, owner))
            break;
        if (offset + 10 > length)
            break;
        const std::uint16_t type = readU16(payload + offset);
        offset += 8;
        const std::uint16_t dataLength = readU16(payload + offset);
        offset += 2;
        if (offset + dataLength > length)
            break;

        std::string value;
        if (type == 1 && dataLength == 4) {
            value = ipv4ToString(payload + offset);
        } else if (type == 28 && dataLength == 16) {
            value = ipv6ToString(payload + offset);
        } else if (type == 5) {
            std::size_t nameOffset = offset;
            parseDnsName(payload, length, nameOffset, value);
        }
        if (!value.empty()) {
            if (!answers.empty())
                answers += ", ";
            answers += owner + " -> " + value;
        }
        offset += dataLength;
    }

    packet.dnsAnswers = answers;
    packet.applicationSummary =
        (packet.dnsResponse ? "Response " : "Query ") +
        (names.empty() ? std::string("<unknown>") : names) +
        (answers.empty() ? std::string() : "  Answers: " + answers);
    packet.layers.push_back({
        "DNS",
        {
            {"事务 ID", hex16(packet.dnsTransactionId)},
            {"类型", packet.dnsResponse ? "Response" : "Query"},
            {"响应码", std::to_string(packet.dnsResponseCode)},
            {"问题", names},
            {"答案", answers},
        },
    });
}

void parseHttp(
    ParsedPacket& packet,
    const std::uint8_t* payload,
    std::size_t payloadLength)
{
    const std::size_t visibleLength = std::min<std::size_t>(payloadLength, 8192);
    std::string text;
    text.reserve(visibleLength);
    for (std::size_t index = 0; index < visibleLength; ++index) {
        const auto value = payload[index];
        text.push_back(
            (value == '\r' || value == '\n' || value == '\t' ||
             (value >= 32 && value <= 126))
                ? static_cast<char>(value)
                : '.');
    }

    const std::size_t firstEnd = text.find_first_of("\r\n");
    const std::string firstLine =
        firstEnd == std::string::npos ? text : text.substr(0, firstEnd);
    if (firstLine.empty())
        return;

    if (startsWith(firstLine, "HTTP/")) {
        const std::size_t firstSpace = firstLine.find(' ');
        if (firstSpace != std::string::npos) {
            const std::size_t secondSpace = firstLine.find(' ', firstSpace + 1);
            const std::string code = firstLine.substr(
                firstSpace + 1,
                secondSpace == std::string::npos
                    ? std::string::npos
                    : secondSpace - firstSpace - 1);
            try {
                packet.httpStatusCode = std::stoi(code);
            } catch (...) {
                packet.httpStatusCode = 0;
            }
            if (secondSpace != std::string::npos)
                packet.httpStatusText = firstLine.substr(secondSpace + 1);
            packet.applicationSummary =
                firstLine;
        }
    } else {
        const std::size_t firstSpace = firstLine.find(' ');
        const std::size_t secondSpace =
            firstSpace == std::string::npos
                ? std::string::npos
                : firstLine.find(' ', firstSpace + 1);
        if (firstSpace != std::string::npos) {
            packet.httpMethod = firstLine.substr(0, firstSpace);
            packet.httpUri = firstLine.substr(
                firstSpace + 1,
                secondSpace == std::string::npos
                    ? std::string::npos
                    : secondSpace - firstSpace - 1);
            packet.applicationSummary = firstLine;
        }
    }

    std::size_t cursor =
        firstEnd == std::string::npos ? text.size() : firstEnd;
    while (cursor < text.size()) {
        while (cursor < text.size() &&
               (text[cursor] == '\r' || text[cursor] == '\n'))
            ++cursor;
        const std::size_t end = text.find_first_of("\r\n", cursor);
        if (end == std::string::npos)
            break;
        const std::string line = text.substr(cursor, end - cursor);
        if (line.empty())
            break;
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            const std::string name = lowerAscii(trim(line.substr(0, colon)));
            const std::string value = trim(line.substr(colon + 1));
            if (name == "host")
                packet.httpHost = value;
            else if (name == "content-type")
                packet.httpContentType = value;
        }
        cursor = end;
    }

    packet.applicationProtocol = "HTTP";
    packet.layers.push_back({
        "HTTP",
        {
            {"类型", packet.httpMethod.empty() ? "Response" : "Request"},
            {"方法", packet.httpMethod},
            {"URI", packet.httpUri},
            {"Host", packet.httpHost},
            {"状态码", packet.httpStatusCode == 0
                ? std::string()
                : std::to_string(packet.httpStatusCode)},
            {"状态文本", packet.httpStatusText},
            {"Content-Type", packet.httpContentType},
            {"可见文本长度", std::to_string(payloadLength)},
        },
    });
}

void parseApplicationLayer(
    ParsedPacket& packet,
    const std::uint8_t* payload,
    std::size_t payloadLength)
{
    if (!payload || payloadLength == 0)
        return;

    const std::string line = textLine(payload, payloadLength);
    if (line.empty())
        return;

    const bool likelyHttp =
        packet.sourcePort == 80 ||
        packet.destinationPort == 80 ||
        packet.sourcePort == 8080 ||
        packet.destinationPort == 8080 ||
        startsWith(line, "GET ") ||
        startsWith(line, "POST ") ||
        startsWith(line, "HEAD ") ||
        startsWith(line, "PUT ") ||
        startsWith(line, "DELETE ") ||
        startsWith(line, "HTTP/");

    if (likelyHttp) {
        parseHttp(packet, payload, payloadLength);
        return;
    }

    if (packet.sourcePort == 21 || packet.destinationPort == 21) {
        packet.applicationProtocol = "FTP";
        packet.applicationSummary = line;
        packet.layers.push_back({
            "FTP",
            {{"响应或命令", line}},
        });
    }
}

void setParserError(ParsedPacket& packet, const std::string& message)
{
    packet.parseError = message;
    packet.summary = "解析失败: " + message;
}

void parseIpv4(
    ParsedPacket& packet,
    const std::uint8_t* data,
    std::size_t capturedLength,
    std::size_t l3Offset)
{
    if (capturedLength < l3Offset + 20) {
        setParserError(packet, "IPv4 首部不完整");
        return;
    }

    const std::uint8_t* ip = data + l3Offset;
    const std::uint8_t version = ip[0] >> 4U;
    const std::size_t headerLength =
        static_cast<std::size_t>(ip[0] & 0x0FU) * 4U;
    const std::uint16_t totalLength = readU16(ip + 2);

    if (version != 4 || headerLength < 20) {
        setParserError(packet, "IPv4 版本或首部长度无效");
        return;
    }
    if (totalLength < headerLength) {
        setParserError(packet, "IPv4 总长度小于首部长度");
        return;
    }
    if (capturedLength < l3Offset + headerLength) {
        setParserError(packet, "IPv4 选项字段不完整");
        return;
    }

    packet.hasIpv4 = true;
    packet.ipVersion = 4;
    packet.sourceIp = ipv4ToString(ip + 12);
    packet.destinationIp = ipv4ToString(ip + 16);
    packet.ttl = ip[8];
    packet.ipProtocol = ip[9];
    packet.protocol = protocolName(packet.ipProtocol);

    const std::uint16_t flagsAndFragment = readU16(ip + 6);
    const std::uint16_t fragmentOffset = flagsAndFragment & 0x1FFFU;
    packet.layers.push_back({
        "IPv4",
        {
            {"版本", std::to_string(version)},
            {"首部长度", std::to_string(headerLength) + " bytes"},
            {"总长度", std::to_string(totalLength) + " bytes"},
            {"标识", hex16(readU16(ip + 4))},
            {"TTL", std::to_string(packet.ttl)},
            {"协议", packet.protocol + " (" +
                std::to_string(packet.ipProtocol) + ")"},
            {"源 IP", packet.sourceIp},
            {"目的 IP", packet.destinationIp},
            {"分片偏移", std::to_string(fragmentOffset)},
        },
    });

    if (fragmentOffset != 0) {
        packet.protocol = "IPv4 Fragment";
        return;
    }

    const std::size_t l4Offset = l3Offset + headerLength;
    const std::size_t ipPayloadLength =
        static_cast<std::size_t>(totalLength) - headerLength;
    const std::size_t capturedIpPayloadLength =
        capturedLength > l4Offset ? capturedLength - l4Offset : 0;
    const std::size_t l4Available =
        std::min(ipPayloadLength, capturedIpPayloadLength);

    if (packet.ipProtocol == 6) {
        if (l4Available < 20) {
            setParserError(packet, "TCP 首部不完整");
            return;
        }
        const std::uint8_t* tcp = data + l4Offset;
        const std::size_t tcpHeaderLength =
            static_cast<std::size_t>(tcp[12] >> 4U) * 4U;
        if (tcpHeaderLength < 20 || tcpHeaderLength > l4Available) {
            setParserError(packet, "TCP 首部长度无效");
            return;
        }

        packet.hasPorts = true;
        packet.sourcePort = readU16(tcp);
        packet.destinationPort = readU16(tcp + 2);
        packet.tcpSequence = readU32(tcp + 4);
        packet.tcpAcknowledgment = readU32(tcp + 8);
        packet.tcpFlags = tcp[13];
        packet.layers.push_back({
            "TCP",
            {
                {"源端口", std::to_string(packet.sourcePort)},
                {"目的端口", std::to_string(packet.destinationPort)},
                {"序列号", std::to_string(packet.tcpSequence)},
                {"确认号", std::to_string(packet.tcpAcknowledgment)},
                {"首部长度", std::to_string(tcpHeaderLength) + " bytes"},
                {"标志位", tcpFlagsToString(packet.tcpFlags)},
            },
        });

        const std::size_t payloadOffset = l4Offset + tcpHeaderLength;
        std::size_t payloadLength = 0;
        if (payloadOffset < capturedLength) {
            payloadLength = std::min(
                l4Available - tcpHeaderLength,
                capturedLength - payloadOffset);
        }
        packet.transportPayloadOffset = payloadOffset;
        packet.transportPayloadLength = payloadLength;
        if (payloadLength > 0 &&
            (packet.sourcePort == 53 || packet.destinationPort == 53)) {
            parseDns(
                packet,
                data + payloadOffset,
                payloadLength,
                true);
        } else {
            parseApplicationLayer(
                packet,
                data + payloadOffset,
                payloadLength);
        }
        return;
    }

    if (packet.ipProtocol == 17) {
        if (l4Available < 8) {
            setParserError(packet, "UDP 首部不完整");
            return;
        }
        const std::uint8_t* udp = data + l4Offset;
        packet.hasPorts = true;
        packet.sourcePort = readU16(udp);
        packet.destinationPort = readU16(udp + 2);
        const std::uint16_t udpLength = readU16(udp + 4);
        packet.layers.push_back({
            "UDP",
            {
                {"源端口", std::to_string(packet.sourcePort)},
                {"目的端口", std::to_string(packet.destinationPort)},
                {"长度", std::to_string(udpLength) + " bytes"},
            },
        });

        if (udpLength >= 8) {
            const std::size_t declaredPayloadLength =
                static_cast<std::size_t>(udpLength) - 8;
            const std::size_t capturedPayloadLength =
                capturedLength - l4Offset - 8;
            const std::size_t payloadLength =
                std::min(declaredPayloadLength, capturedPayloadLength);
            packet.transportPayloadOffset = l4Offset + 8;
            packet.transportPayloadLength = payloadLength;
            if (packet.sourcePort == 53 || packet.destinationPort == 53) {
                parseDns(packet, udp + 8, payloadLength, false);
            } else {
                parseApplicationLayer(packet, udp + 8, payloadLength);
            }
        }
        return;
    }

    if (packet.ipProtocol == 1) {
        if (l4Available < 4)
            return;
        const std::uint8_t* icmp = data + l4Offset;
        packet.layers.push_back({
            "ICMP",
            {
                {"类型", icmpTypeName(icmp[0])},
                {"代码", std::to_string(icmp[1])},
            },
        });
        return;
    }

    if (packet.ipProtocol == 2 && l4Available >= 8) {
        const std::uint8_t* igmp = data + l4Offset;
        packet.layers.push_back({
            "IGMP",
            {
                {"类型", igmpTypeName(igmp[0])},
                {"组播地址", ipv4ToString(igmp + 4)},
            },
        });
    }
}

void parseIpv6(
    ParsedPacket& packet,
    const std::uint8_t* data,
    std::size_t capturedLength,
    std::size_t l3Offset)
{
    if (capturedLength < l3Offset + 40) {
        setParserError(packet, "IPv6 首部不完整");
        return;
    }

    const std::uint8_t* ip = data + l3Offset;
    const std::uint8_t version = ip[0] >> 4U;
    if (version != 6) {
        setParserError(packet, "IPv6 版本字段无效");
        return;
    }

    const std::uint16_t payloadLength = readU16(ip + 4);
    std::uint8_t nextHeader = ip[6];
    packet.hasIpv6 = true;
    packet.ipVersion = 6;
    packet.sourceIp = ipv6ToString(ip + 8);
    packet.destinationIp = ipv6ToString(ip + 24);
    packet.ttl = ip[7];
    packet.ipProtocol = nextHeader;
    packet.protocol = protocolName(nextHeader);

    packet.layers.push_back({
        "IPv6",
        {
            {"版本", "6"},
            {"载荷长度", std::to_string(payloadLength) + " bytes"},
            {"下一首部", protocolName(nextHeader) +
                " (" + std::to_string(nextHeader) + ")"},
            {"Hop Limit", std::to_string(packet.ttl)},
            {"源 IPv6", packet.sourceIp},
            {"目的 IPv6", packet.destinationIp},
        },
    });

    std::size_t l4Offset = l3Offset + 40;
    const std::size_t ipPayloadLength =
        static_cast<std::size_t>(payloadLength);
    const std::size_t capturedIpPayloadLength =
        capturedLength > l4Offset ? capturedLength - l4Offset : 0;
    std::size_t l4Available =
        std::min(ipPayloadLength, capturedIpPayloadLength);
    bool fragmented = false;

    for (int extensionCount = 0; extensionCount < 8; ++extensionCount) {
        if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60) {
            if (l4Available < 2)
                return;
            const std::size_t extensionLength =
                (static_cast<std::size_t>(data[l4Offset + 1]) + 1U) * 8U;
            if (extensionLength > l4Available)
                return;
            nextHeader = data[l4Offset];
            l4Offset += extensionLength;
            l4Available -= extensionLength;
            continue;
        }
        if (nextHeader == 51) {
            if (l4Available < 2)
                return;
            const std::size_t extensionLength =
                (static_cast<std::size_t>(data[l4Offset + 1]) + 2U) * 4U;
            if (extensionLength > l4Available)
                return;
            nextHeader = data[l4Offset];
            l4Offset += extensionLength;
            l4Available -= extensionLength;
            continue;
        }
        if (nextHeader == 44) {
            if (l4Available < 8)
                return;
            const std::uint16_t fragmentField = readU16(data + l4Offset + 2);
            fragmented = (fragmentField & 0xFFF8U) != 0;
            nextHeader = data[l4Offset];
            l4Offset += 8;
            l4Available -= 8;
            continue;
        }
        break;
    }

    packet.ipProtocol = nextHeader;
    packet.protocol = protocolName(nextHeader);
    if (fragmented) {
        packet.protocol = "IPv6 Fragment";
        return;
    }

    if (nextHeader == 6) {
        if (l4Available < 20) {
            setParserError(packet, "IPv6 TCP 首部不完整");
            return;
        }
        const std::uint8_t* tcp = data + l4Offset;
        const std::size_t tcpHeaderLength =
            static_cast<std::size_t>(tcp[12] >> 4U) * 4U;
        if (tcpHeaderLength < 20 || tcpHeaderLength > l4Available) {
            setParserError(packet, "IPv6 TCP 首部长度无效");
            return;
        }
        packet.hasPorts = true;
        packet.sourcePort = readU16(tcp);
        packet.destinationPort = readU16(tcp + 2);
        packet.tcpSequence = readU32(tcp + 4);
        packet.tcpAcknowledgment = readU32(tcp + 8);
        packet.tcpFlags = tcp[13];
        packet.layers.push_back({
            "TCP",
            {
                {"源端口", std::to_string(packet.sourcePort)},
                {"目的端口", std::to_string(packet.destinationPort)},
                {"序列号", std::to_string(packet.tcpSequence)},
                {"确认号", std::to_string(packet.tcpAcknowledgment)},
                {"首部长度", std::to_string(tcpHeaderLength) + " bytes"},
                {"标志位", tcpFlagsToString(packet.tcpFlags)},
            },
        });
        const std::size_t payloadOffset = l4Offset + tcpHeaderLength;
        const std::size_t tcpPayloadLength =
            payloadOffset < capturedLength
                ? std::min(
                    l4Available - tcpHeaderLength,
                    capturedLength - payloadOffset)
                : 0;
        packet.transportPayloadOffset = payloadOffset;
        packet.transportPayloadLength = tcpPayloadLength;
        if (tcpPayloadLength > 0 &&
            (packet.sourcePort == 53 || packet.destinationPort == 53)) {
            parseDns(packet, data + payloadOffset, tcpPayloadLength, true);
        } else {
            parseApplicationLayer(packet, data + payloadOffset, tcpPayloadLength);
        }
        return;
    }

    if (nextHeader == 17) {
        if (l4Available < 8) {
            setParserError(packet, "IPv6 UDP 首部不完整");
            return;
        }
        const std::uint8_t* udp = data + l4Offset;
        packet.hasPorts = true;
        packet.sourcePort = readU16(udp);
        packet.destinationPort = readU16(udp + 2);
        const std::uint16_t udpLength = readU16(udp + 4);
        packet.layers.push_back({
            "UDP",
            {
                {"源端口", std::to_string(packet.sourcePort)},
                {"目的端口", std::to_string(packet.destinationPort)},
                {"长度", std::to_string(udpLength) + " bytes"},
            },
        });
        if (udpLength >= 8) {
            const std::size_t udpPayloadLength = std::min<std::size_t>(
                static_cast<std::size_t>(udpLength) - 8,
                capturedLength - l4Offset - 8);
            packet.transportPayloadOffset = l4Offset + 8;
            packet.transportPayloadLength = udpPayloadLength;
            if (packet.sourcePort == 53 || packet.destinationPort == 53) {
                parseDns(packet, udp + 8, udpPayloadLength, false);
            } else {
                parseApplicationLayer(packet, udp + 8, udpPayloadLength);
            }
        }
        return;
    }

    if (nextHeader == 58 && l4Available >= 4) {
        const std::uint8_t* icmp = data + l4Offset;
        packet.layers.push_back({
            "ICMPv6",
            {
                {"类型", std::to_string(icmp[0])},
                {"代码", std::to_string(icmp[1])},
            },
        });
    }
}

void parseArp(
    ParsedPacket& packet,
    const std::uint8_t* data,
    std::size_t capturedLength,
    std::size_t l3Offset)
{
    if (capturedLength < l3Offset + 28) {
        setParserError(packet, "ARP 数据不完整");
        return;
    }

    const std::uint8_t* arp = data + l3Offset;
    const std::uint16_t hardwareType = readU16(arp);
    const std::uint16_t protocolType = readU16(arp + 2);
    const std::uint8_t hardwareLength = arp[4];
    const std::uint8_t protocolLength = arp[5];
    const std::uint16_t operation = readU16(arp + 6);
    packet.protocol = "ARP";
    packet.ipVersion = 4;

    if (hardwareType != 1 ||
        protocolType != 0x0800 ||
        hardwareLength != 6 ||
        protocolLength != 4) {
        packet.layers.push_back({
            "ARP",
            {
                {"硬件类型", std::to_string(hardwareType)},
                {"协议类型", hex16(protocolType)},
                {"操作码", std::to_string(operation)},
                {"说明", "非标准 Ethernet/IPv4 ARP"},
            },
        });
        return;
    }

    const std::string senderMac = macToString(arp + 8);
    const std::string senderIp = ipv4ToString(arp + 14);
    const std::string targetMac = macToString(arp + 18);
    const std::string targetIp = ipv4ToString(arp + 24);
    packet.sourceIp = senderIp;
    packet.destinationIp = targetIp;
    packet.layers.push_back({
        "ARP",
        {
            {"操作", operation == 1 ? "Request (1)" :
                operation == 2 ? "Reply (2)" : std::to_string(operation)},
            {"发送方 MAC", senderMac},
            {"发送方 IP", senderIp},
            {"目标 MAC", targetMac},
            {"目标 IP", targetIp},
        },
    });

    if (operation == 1)
        packet.summary = "Who has " + targetIp + "? Tell " + senderIp;
    else if (operation == 2)
        packet.summary = senderIp + " is at " + senderMac;
}

void finalizeSummary(ParsedPacket& packet)
{
    if (!packet.summary.empty())
        return;

    std::ostringstream summary;
    if (!packet.sourceMacText.empty())
        summary << packet.sourceMacText << " -> " << packet.destinationMacText;
    if (!packet.sourceIp.empty()) {
        if (summary.tellp() > 0)
            summary << "  ";
        summary << packet.sourceIp << " -> " << packet.destinationIp;
    }
    if (summary.tellp() > 0)
        summary << "  ";
    summary << packet.protocol;
    if (packet.hasPorts)
        summary << "  " << packet.sourcePort << " -> " << packet.destinationPort;
    if (!packet.applicationProtocol.empty())
        summary << "  " << packet.applicationProtocol;
    packet.summary = summary.str();
}

} // namespace

ParsedPacket PacketParser::parseEthernet(
    const std::uint8_t* data,
    std::size_t capturedLength,
    std::uint32_t originalLength)
{
    ParsedPacket packet;
    packet.capturedLength = static_cast<std::uint32_t>(capturedLength);
    packet.originalLength = originalLength == 0
        ? static_cast<std::uint32_t>(capturedLength)
        : originalLength;

    if (!data || capturedLength < 14) {
        setParserError(packet, "以太网帧不足 14 字节");
        return packet;
    }

    std::copy(data, data + 6, packet.destinationMac.begin());
    std::copy(data + 6, data + 12, packet.sourceMac.begin());
    packet.destinationMacText = macToString(data);
    packet.sourceMacText = macToString(data + 6);

    std::uint16_t currentType = readU16(data + 12);
    std::size_t l3Offset = 14;
    std::vector<std::pair<std::uint16_t, std::uint16_t>> vlanTags;

    while (currentType == 0x8100 || currentType == 0x88A8) {
        if (capturedLength < l3Offset + 4) {
            setParserError(packet, "VLAN 标签不完整");
            return packet;
        }
        const std::uint16_t tagControl = readU16(data + l3Offset);
        const std::uint16_t nextType = readU16(data + l3Offset + 2);
        vlanTags.emplace_back(tagControl, nextType);
        currentType = nextType;
        l3Offset += 4;
    }

    packet.etherType = currentType;
    ProtocolLayer ethernetLayer{
        "Ethernet II",
        {
            {"目的 MAC", packet.destinationMacText},
            {"源 MAC", packet.sourceMacText},
            {"类型", hex16(packet.etherType)},
            {"帧长度", std::to_string(packet.originalLength) + " bytes"},
            {"捕获长度", std::to_string(packet.capturedLength) + " bytes"},
        },
    };
    for (std::size_t index = 0; index < vlanTags.size(); ++index) {
        ethernetLayer.fields.push_back({
            "VLAN " + std::to_string(index + 1),
            "TCI=" + hex16(vlanTags[index].first) +
                ", Type=" + hex16(vlanTags[index].second),
        });
    }
    packet.layers.push_back(std::move(ethernetLayer));

    if (packet.etherType == 0x0800)
        parseIpv4(packet, data, capturedLength, l3Offset);
    else if (packet.etherType == 0x0806)
        parseArp(packet, data, capturedLength, l3Offset);
    else if (packet.etherType == 0x86DD)
        parseIpv6(packet, data, capturedLength, l3Offset);
    else {
        packet.protocol = "EtherType " + hex16(packet.etherType);
    }

    finalizeSummary(packet);
    return packet;
}

ParsedPacket PacketParser::parsePacket(
    const std::uint8_t* data,
    std::size_t capturedLength,
    std::uint32_t originalLength,
    int dataLinkType)
{
    constexpr int dltNull = 0;
    constexpr int dltEthernet = 1;
    constexpr int dltLoop = 108;

    if (dataLinkType == dltEthernet)
        return parseEthernet(data, capturedLength, originalLength);

    ParsedPacket packet;
    packet.capturedLength = static_cast<std::uint32_t>(capturedLength);
    packet.originalLength = originalLength == 0
        ? static_cast<std::uint32_t>(capturedLength)
        : originalLength;

    if (dataLinkType != dltNull && dataLinkType != dltLoop) {
        setParserError(
            packet,
            "暂不支持链路层类型 " + std::to_string(dataLinkType));
        return packet;
    }

    packet.sourceMacText = "loopback";
    packet.destinationMacText = "loopback";
    if (!data || capturedLength < 4) {
        setParserError(packet, "回环链路头不完整");
        return packet;
    }

    const std::uint32_t familyLittleEndian =
        static_cast<std::uint32_t>(data[0]) |
        (static_cast<std::uint32_t>(data[1]) << 8U) |
        (static_cast<std::uint32_t>(data[2]) << 16U) |
        (static_cast<std::uint32_t>(data[3]) << 24U);
    const std::uint32_t familyBigEndian =
        (static_cast<std::uint32_t>(data[0]) << 24U) |
        (static_cast<std::uint32_t>(data[1]) << 16U) |
        (static_cast<std::uint32_t>(data[2]) << 8U) |
        static_cast<std::uint32_t>(data[3]);
    const std::uint32_t family =
        familyLittleEndian == 2 || familyLittleEndian == 23
            ? familyLittleEndian
            : familyBigEndian;

    packet.layers.push_back({
        "Loopback",
        {
            {"地址族", std::to_string(family)},
            {"格式", dataLinkType == dltLoop ? "DLT_LOOP" : "DLT_NULL"},
        },
    });

    if (family == 2) {
        packet.etherType = 0x0800;
        parseIpv4(packet, data, capturedLength, 4);
    } else if (family == 23) {
        packet.etherType = 0x86DD;
        parseIpv6(packet, data, capturedLength, 4);
    } else {
        packet.protocol = "Loopback family " + std::to_string(family);
    }

    finalizeSummary(packet);
    return packet;
}

} // namespace netobserver
