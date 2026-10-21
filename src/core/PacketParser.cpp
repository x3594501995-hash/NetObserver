#include "core/PacketParser.h"

#include <algorithm>
#include <array>
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
        packet.applicationProtocol = "HTTP";
        packet.applicationSummary = line;
        packet.layers.push_back({
            "HTTP",
            {{"首行", line}, {"可见文本长度", std::to_string(payloadLength)}},
        });
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
        if (payloadOffset < capturedLength) {
            const std::size_t payloadLength = std::min(
                l4Available - tcpHeaderLength,
                capturedLength - payloadOffset);
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
            parseApplicationLayer(
                packet,
                udp + 8,
                std::min(declaredPayloadLength, capturedPayloadLength));
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
    else if (packet.etherType == 0x86DD) {
        packet.protocol = "IPv6";
        packet.summary = "IPv6 packet (当前版本仅显示基础信息)";
    } else {
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
    } else {
        packet.protocol = "Loopback family " + std::to_string(family);
    }

    finalizeSummary(packet);
    return packet;
}

} // namespace netobserver
