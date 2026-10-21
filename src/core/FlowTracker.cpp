#include "core/FlowTracker.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace netobserver {
namespace {

constexpr std::size_t kMaximumStreamBytes = 1024U * 1024U;
constexpr std::size_t kMaximumPendingSegments = 256;
constexpr std::size_t kMaximumFlows = 2000;

struct Endpoint {
    std::string ip;
    std::uint16_t port = 0;
};

std::string endpointText(const Endpoint& endpoint)
{
    if (endpoint.ip.find(':') != std::string::npos)
        return "[" + endpoint.ip + "]:" + std::to_string(endpoint.port);
    return endpoint.ip + ":" + std::to_string(endpoint.port);
}

bool endpointLess(const Endpoint& left, const Endpoint& right)
{
    if (left.ip != right.ip)
        return left.ip < right.ip;
    return left.port < right.port;
}

std::size_t printableCount(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end)
{
    std::size_t count = 0;
    for (std::size_t index = begin; index < end; ++index) {
        const std::uint8_t value = data[index];
        if (value == '\r' || value == '\n' || value == '\t' ||
            (value >= 32 && value <= 126)) {
            ++count;
        }
    }
    return count;
}

std::string renderText(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end)
{
    constexpr std::size_t maximumTextBytes = 256U * 1024U;
    end = std::min(end, begin + maximumTextBytes);
    std::string output;
    output.reserve(end - begin + 32);
    for (std::size_t index = begin; index < end; ++index) {
        const std::uint8_t value = data[index];
        if (value == '\r') {
            if (index + 1 < end && data[index + 1] == '\n')
                continue;
            output.push_back('\n');
        } else if (value == '\n' || value == '\t' ||
                   (value >= 32 && value <= 126)) {
            output.push_back(static_cast<char>(value));
        } else {
            output.push_back('.');
        }
    }
    if (data.size() > maximumTextBytes && begin == 0)
        output += "\r\n[文本已截断]";
    return output;
}

std::string hexPreview(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end,
    std::size_t maximumBytes = 256)
{
    std::ostringstream output;
    output << std::hex << std::uppercase;
    const std::size_t shownEnd = std::min(end, begin + maximumBytes);
    for (std::size_t offset = begin; offset < shownEnd; offset += 16) {
        output << std::setw(8) << std::setfill('0')
               << static_cast<std::uint32_t>(offset - begin) << "  ";
        for (std::size_t index = 0; index < 16; ++index) {
            if (offset + index < shownEnd) {
                output << std::setw(2)
                       << static_cast<unsigned>(data[offset + index]) << ' ';
            } else {
                output << "   ";
            }
        }
        output << " ";
        for (std::size_t index = 0;
             index < 16 && offset + index < shownEnd;
             ++index) {
            const std::uint8_t value = data[offset + index];
            output << static_cast<char>(
                value >= 32 && value <= 126 ? value : '.');
        }
        output << "\r\n";
    }
    if (end - begin > maximumBytes)
        output << "... 其余 " << std::dec << (end - begin - maximumBytes)
               << " 字节未显示\r\n";
    return output.str();
}

std::string lowerPrefix(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end)
{
    std::string output;
    for (std::size_t index = begin;
         index < end && output.size() < 4096;
         ++index) {
        output.push_back(static_cast<char>(data[index]));
    }
    std::transform(
        output.begin(),
        output.end(),
        output.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return output;
}

std::string renderStream(const std::vector<std::uint8_t>& data)
{
    if (data.empty())
        return "[无数据]";

    const std::string prefix = lowerPrefix(data, 0, data.size());
    const bool httpLike =
        prefix.rfind("get ", 0) == 0 ||
        prefix.rfind("post ", 0) == 0 ||
        prefix.rfind("head ", 0) == 0 ||
        prefix.rfind("put ", 0) == 0 ||
        prefix.rfind("http/", 0) == 0;
    const std::string separator = "\r\n\r\n";
    std::size_t bodyStart = std::string::npos;
    if (httpLike) {
        for (std::size_t index = 0; index + 3 < data.size(); ++index) {
            if (data[index] == '\r' && data[index + 1] == '\n' &&
                data[index + 2] == '\r' && data[index + 3] == '\n') {
                bodyStart = index + 4;
                break;
            }
        }
    }

    if (bodyStart != std::string::npos) {
        std::string output = renderText(data, 0, bodyStart);
        output += "\r\n[响应体 " +
            std::to_string(data.size() - bodyStart) + " bytes]\r\n";
        const std::size_t printable =
            printableCount(data, bodyStart, data.size());
        const std::size_t bodySize = data.size() - bodyStart;
        const bool encoded =
            prefix.find("content-encoding: gzip") != std::string::npos ||
            prefix.find("content-encoding: br") != std::string::npos ||
            prefix.find("content-encoding: deflate") != std::string::npos;
        const bool likelyBinary =
            bodySize > 0 && printable * 100 / bodySize < 75;
        if (encoded || likelyBinary) {
            output += "[压缩或二进制内容，显示十六进制预览]\r\n";
            output += hexPreview(data, bodyStart, data.size());
        } else {
            output += renderText(data, bodyStart, data.size());
        }
        return output;
    }

    const std::size_t printable = printableCount(data, 0, data.size());
    if (printable * 100 / data.size() >= 78)
        return renderText(data, 0, data.size());

    return "[二进制或加密封装数据，共 " +
        std::to_string(data.size()) + " bytes]\r\n" +
        hexPreview(data, 0, data.size());
}

struct DirectionState {
    bool sequenceInitialized = false;
    std::uint32_t nextSequence = 0;
    std::vector<std::uint8_t> stream;
    std::map<std::uint32_t, std::vector<std::uint8_t>> pending;

    void append(
        std::uint32_t sequence,
        const std::uint8_t* data,
        std::size_t length)
    {
        if (!data || length == 0 || stream.size() >= kMaximumStreamBytes)
            return;

        if (!sequenceInitialized) {
            sequenceInitialized = true;
            nextSequence = sequence;
        }

        std::int32_t difference =
            static_cast<std::int32_t>(sequence - nextSequence);
        if (difference < 0) {
            const std::size_t overlap =
                static_cast<std::size_t>(-static_cast<std::int64_t>(difference));
            if (overlap >= length)
                return;
            data += overlap;
            length -= overlap;
            sequence += static_cast<std::uint32_t>(overlap);
            difference = 0;
        }

        if (difference == 0) {
            appendContiguous(data, length);
            bool progressed = true;
            while (progressed) {
                progressed = false;
                const auto iterator = pending.find(nextSequence);
                if (iterator == pending.end())
                    break;
                const auto segment = iterator->second;
                pending.erase(iterator);
                appendContiguous(segment.data(), segment.size());
                progressed = true;
            }
        } else if (pending.size() < kMaximumPendingSegments) {
            pending.emplace(
                sequence,
                std::vector<std::uint8_t>(data, data + length));
        }
    }

    void appendContiguous(const std::uint8_t* data, std::size_t length)
    {
        const std::size_t available =
            kMaximumStreamBytes - stream.size();
        const std::size_t accepted = std::min(length, available);
        stream.insert(stream.end(), data, data + accepted);
        nextSequence += static_cast<std::uint32_t>(accepted);
    }
};

struct Flow {
    std::string key;
    std::string protocol;
    Endpoint endpointA;
    Endpoint endpointB;
    std::uint64_t packetsAToB = 0;
    std::uint64_t packetsBToA = 0;
    std::uint64_t bytesAToB = 0;
    std::uint64_t bytesBToA = 0;
    std::int64_t firstTimestampSeconds = 0;
    std::int64_t lastTimestampSeconds = 0;
    DirectionState aToB;
    DirectionState bToA;
};

} // namespace

struct FlowTracker::Impl {
    std::unordered_map<std::string, Flow> flows;
};

FlowTracker::FlowTracker()
    : impl_(std::make_unique<Impl>())
{
}

FlowTracker::~FlowTracker() = default;

std::string FlowTracker::flowKey(const ParsedPacket& packet)
{
    if (!packet.hasPorts ||
        packet.sourceIp.empty() ||
        packet.destinationIp.empty() ||
        (packet.protocol != "TCP" && packet.protocol != "UDP")) {
        return {};
    }

    Endpoint source{packet.sourceIp, packet.sourcePort};
    Endpoint destination{packet.destinationIp, packet.destinationPort};
    if (endpointLess(destination, source))
        std::swap(source, destination);
    return packet.protocol + "|" + endpointText(source) +
        "|" + endpointText(destination);
}

void FlowTracker::addPacket(
    const ParsedPacket& packet,
    const std::uint8_t* packetData,
    std::size_t packetLength)
{
    const std::string key = flowKey(packet);
    if (key.empty())
        return;

    auto iterator = impl_->flows.find(key);
    if (iterator == impl_->flows.end()) {
        if (impl_->flows.size() >= kMaximumFlows)
            return;

        Flow flow;
        flow.key = key;
        flow.protocol = packet.protocol;
        Endpoint source{packet.sourceIp, packet.sourcePort};
        Endpoint destination{packet.destinationIp, packet.destinationPort};
        if (endpointLess(destination, source))
            std::swap(source, destination);
        flow.endpointA = source;
        flow.endpointB = destination;
        flow.firstTimestampSeconds = packet.timestampSeconds;
        flow.lastTimestampSeconds = packet.timestampSeconds;
        iterator = impl_->flows.emplace(key, std::move(flow)).first;
    }

    Flow& flow = iterator->second;
    const Endpoint source{packet.sourceIp, packet.sourcePort};
    const bool fromA =
        source.ip == flow.endpointA.ip && source.port == flow.endpointA.port;
    if (fromA) {
        ++flow.packetsAToB;
        flow.bytesAToB += packet.capturedLength;
    } else {
        ++flow.packetsBToA;
        flow.bytesBToA += packet.capturedLength;
    }
    flow.lastTimestampSeconds = packet.timestampSeconds;

    if (packet.protocol != "TCP" ||
        packet.transportPayloadOffset >= packetLength ||
        packet.transportPayloadLength == 0) {
        return;
    }

    const std::size_t available =
        packetLength - packet.transportPayloadOffset;
    const std::size_t length =
        std::min(available, packet.transportPayloadLength);
    std::uint32_t sequence = packet.tcpSequence;
    if ((packet.tcpFlags & 0x02U) != 0)
        ++sequence;
    DirectionState& direction = fromA ? flow.aToB : flow.bToA;
    direction.append(
        sequence,
        packetData + packet.transportPayloadOffset,
        length);
}

void FlowTracker::clear()
{
    impl_->flows.clear();
}

std::vector<FlowStatistics> FlowTracker::statistics() const
{
    std::vector<FlowStatistics> result;
    result.reserve(impl_->flows.size());
    for (const auto& entry : impl_->flows) {
        const Flow& flow = entry.second;
        FlowStatistics statistics;
        statistics.key = flow.key;
        statistics.protocol = flow.protocol;
        statistics.endpointA = endpointText(flow.endpointA);
        statistics.endpointB = endpointText(flow.endpointB);
        statistics.packetsAToB = flow.packetsAToB;
        statistics.packetsBToA = flow.packetsBToA;
        statistics.bytesAToB = flow.bytesAToB;
        statistics.bytesBToA = flow.bytesBToA;
        statistics.firstTimestampSeconds = flow.firstTimestampSeconds;
        statistics.lastTimestampSeconds = flow.lastTimestampSeconds;
        statistics.tcpStreamAvailable =
            flow.protocol == "TCP" &&
            (!flow.aToB.stream.empty() || !flow.bToA.stream.empty());
        result.push_back(std::move(statistics));
    }
    std::sort(
        result.begin(),
        result.end(),
        [](const FlowStatistics& left, const FlowStatistics& right) {
            return left.bytesAToB + left.bytesBToA >
                right.bytesAToB + right.bytesBToA;
        });
    return result;
}

std::string FlowTracker::followStream(const std::string& key) const
{
    const auto iterator = impl_->flows.find(key);
    if (iterator == impl_->flows.end())
        return "未找到该会话。";
    const Flow& flow = iterator->second;

    std::ostringstream output;
    output << "协议: " << flow.protocol << "\r\n"
           << "A: " << endpointText(flow.endpointA) << "\r\n"
           << "B: " << endpointText(flow.endpointB) << "\r\n\r\n";

    if (flow.protocol != "TCP") {
        output << "Follow Stream 当前仅支持 TCP。\r\n";
        return output.str();
    }

    output << "===== A -> B =====\r\n"
           << renderStream(flow.aToB.stream)
           << "\r\n\r\n===== B -> A =====\r\n"
           << renderStream(flow.bToA.stream)
           << "\r\n";
    return output.str();
}

} // namespace netobserver

