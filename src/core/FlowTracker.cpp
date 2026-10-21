#include "core/FlowTracker.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <utility>

#include <windows.h>

namespace netobserver {
namespace {

constexpr std::size_t kMaximumStreamBytes = 1024U * 1024U;
constexpr std::size_t kMaximumPendingBytesPerDirection = 256U * 1024U;
constexpr std::size_t kMaximumPendingSegments = 128;
constexpr std::size_t kMaximumTotalStreamBytes = 128U * 1024U * 1024U;
constexpr std::size_t kMaximumTotalPendingBytes = 64U * 1024U * 1024U;
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

bool hasExcessiveControls(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end)
{
    std::size_t controls = 0;
    for (std::size_t index = begin; index < end; ++index) {
        const std::uint8_t value = data[index];
        if ((value < 32 && value != '\r' && value != '\n' && value != '\t') ||
            value == 127) {
            ++controls;
        }
    }
    return end > begin && controls * 100 / (end - begin) > 3;
}

bool convertToUtf8(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end,
    UINT codePage,
    std::string& output)
{
    if (begin >= end)
        return false;
    const int sourceLength = static_cast<int>(end - begin);
    const int wideLength = MultiByteToWideChar(
        codePage,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<LPCCH>(data.data() + begin),
        sourceLength,
        nullptr,
        0);
    if (wideLength <= 0)
        return false;

    std::wstring wide(static_cast<std::size_t>(wideLength), L'\0');
    if (MultiByteToWideChar(
            codePage,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<LPCCH>(data.data() + begin),
            sourceLength,
            wide.data(),
            wideLength) <= 0) {
        return false;
    }

    const int utf8Length = WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), wideLength, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0)
        return false;
    output.assign(static_cast<std::size_t>(utf8Length), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        wide.data(),
        wideLength,
        output.data(),
        utf8Length,
        nullptr,
        nullptr);
    return true;
}

bool isTextual(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end,
    std::string& converted)
{
    if (begin >= end || hasExcessiveControls(data, begin, end))
        return false;
    if (convertToUtf8(data, begin, end, CP_UTF8, converted))
        return true;
    return convertToUtf8(data, begin, end, CP_ACP, converted);
}

std::string renderText(
    const std::vector<std::uint8_t>& data,
    std::size_t begin,
    std::size_t end,
    bool fullContent)
{
    constexpr std::size_t maximumTextBytes = 256U * 1024U;
    if (!fullContent)
        end = std::min(end, begin + maximumTextBytes);

    std::string converted;
    if (!isTextual(data, begin, end, converted)) {
        converted.assign(
            reinterpret_cast<const char*>(data.data() + begin),
            end - begin);
    }

    std::string output;
    output.reserve(converted.size() + 32);
    for (std::size_t index = 0; index < converted.size(); ++index) {
        const unsigned char value =
            static_cast<unsigned char>(converted[index]);
        if (value == '\r') {
            if (index + 1 < converted.size() && converted[index + 1] == '\n')
                continue;
            output.push_back('\n');
        } else if (value == '\n' || value == '\t' ||
                   value >= 32) {
            output.push_back(static_cast<char>(value));
        } else {
            output.push_back('.');
        }
    }
    if (!fullContent && data.size() > maximumTextBytes && begin == 0)
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

std::string renderStream(
    const std::vector<std::uint8_t>& data,
    bool fullContent)
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
        std::string output = renderText(data, 0, bodyStart, fullContent);
        output += "\r\n[响应体 " +
            std::to_string(data.size() - bodyStart) + " bytes]\r\n";
        const std::size_t bodySize = data.size() - bodyStart;
        const bool encoded =
            prefix.find("content-encoding: gzip") != std::string::npos ||
            prefix.find("content-encoding: br") != std::string::npos ||
            prefix.find("content-encoding: deflate") != std::string::npos;
        const bool likelyBinary =
            bodySize > 0 &&
            hasExcessiveControls(data, bodyStart, data.size());
        if (encoded || likelyBinary) {
            output +=
                (fullContent
                    ? "[压缩或二进制响应体，显示完整十六进制，共 "
                    : "[压缩或二进制内容，共 ") +
                std::to_string(bodySize) +
                (fullContent
                    ? " bytes]\r\n"
                    : " bytes；仅预览前 32 字节]\r\n");
            output += hexPreview(
                data,
                bodyStart,
                data.size(),
                fullContent ? bodySize : 32);
        } else {
            output += renderText(data, bodyStart, data.size(), fullContent);
        }
        return output;
    }

    std::string converted;
    if (isTextual(data, 0, data.size(), converted))
        return renderText(data, 0, data.size(), fullContent);

    return
        (fullContent
            ? "[加密或二进制 TCP 载荷，显示完整十六进制，共 "
            : "[加密或二进制 TCP 载荷，共 ") +
        std::to_string(data.size()) + " bytes]\r\n" +
        (fullContent
            ? "完整原始字节：\r\n"
            : "无法还原为可读文本，仅预览前 32 字节：\r\n") +
        hexPreview(
            data,
            0,
            data.size(),
            fullContent ? data.size() : 32);
}

struct DirectionState {
    bool sequenceInitialized = false;
    std::uint32_t nextSequence = 0;
    std::vector<std::uint8_t> stream;
    std::map<std::uint32_t, std::vector<std::uint8_t>> pending;
    std::size_t pendingBytes = 0;

    std::size_t append(
        std::uint32_t sequence,
        const std::uint8_t* data,
        std::size_t length,
        std::size_t& streamBudget,
        std::size_t& pendingBudget)
    {
        if (!data || length == 0 || stream.size() >= kMaximumStreamBytes)
            return 0;

        if (!sequenceInitialized) {
            sequenceInitialized = true;
            nextSequence = sequence;
        }

        std::size_t appended = 0;
        std::int32_t difference =
            static_cast<std::int32_t>(sequence - nextSequence);
        if (difference < 0) {
            const std::size_t overlap =
                static_cast<std::size_t>(-static_cast<std::int64_t>(difference));
            if (overlap >= length)
                return 0;
            data += overlap;
            length -= overlap;
            sequence += static_cast<std::uint32_t>(overlap);
            difference = 0;
        }

        if (difference == 0) {
            appended += appendContiguous(data, length, streamBudget);
            while (streamBudget > 0 && stream.size() < kMaximumStreamBytes) {
                auto best = pending.end();
                std::size_t bestOverlap = 0;
                for (auto iterator = pending.begin();
                     iterator != pending.end();
                     ++iterator) {
                    const std::int32_t offset = static_cast<std::int32_t>(
                        iterator->first - nextSequence);
                    if (offset > 0)
                        continue;
                    const std::size_t overlap =
                        static_cast<std::size_t>(
                            -static_cast<std::int64_t>(offset));
                    if (overlap >= iterator->second.size())
                        continue;
                    if (best == pending.end() || overlap < bestOverlap) {
                        best = iterator;
                        bestOverlap = overlap;
                    }
                }
                if (best == pending.end())
                    break;

                auto segment = std::move(best->second);
                pendingBudget += segment.size();
                pendingBytes -= segment.size();
                pending.erase(best);
                appended += appendContiguous(
                    segment.data() + bestOverlap,
                    segment.size() - bestOverlap,
                    streamBudget);
            }
            return appended;
        }

        auto existing = pending.find(sequence);
        if (existing != pending.end()) {
            if (existing->second.size() >= length)
                return 0;
            pendingBytes -= existing->second.size();
            pendingBudget += existing->second.size();
            pending.erase(existing);
        }

        const std::size_t perDirectionAvailable =
            kMaximumPendingBytesPerDirection - pendingBytes;
        const std::size_t accepted =
            std::min({length, perDirectionAvailable, pendingBudget});
        if (accepted > 0 &&
            pending.size() < kMaximumPendingSegments) {
            pending.emplace(
                sequence,
                std::vector<std::uint8_t>(data, data + accepted));
            pendingBytes += accepted;
            pendingBudget -= accepted;
        }
        return 0;
    }

    std::size_t appendContiguous(
        const std::uint8_t* data,
        std::size_t length,
        std::size_t& streamBudget)
    {
        const std::size_t available =
            kMaximumStreamBytes - stream.size();
        const std::size_t accepted =
            std::min({length, available, streamBudget});
        stream.insert(stream.end(), data, data + accepted);
        nextSequence += static_cast<std::uint32_t>(accepted);
        streamBudget -= accepted;
        return accepted;
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
    std::size_t streamBytes = 0;
    std::size_t pendingBytes = 0;
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
    std::size_t streamBudget =
        kMaximumTotalStreamBytes - impl_->streamBytes;
    std::size_t pendingBudget =
        kMaximumTotalPendingBytes - impl_->pendingBytes;
    const std::size_t appended = direction.append(
        sequence,
        packetData + packet.transportPayloadOffset,
        length,
        streamBudget,
        pendingBudget);
    impl_->streamBytes += appended;
    impl_->pendingBytes =
        kMaximumTotalPendingBytes - pendingBudget;
}

void FlowTracker::clear()
{
    impl_->flows.clear();
    impl_->streamBytes = 0;
    impl_->pendingBytes = 0;
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

std::string FlowTracker::followStream(
    const std::string& key,
    bool fullContent) const
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
           << renderStream(flow.aToB.stream, fullContent)
           << "\r\n\r\n===== B -> A =====\r\n"
           << renderStream(flow.bToA.stream, fullContent)
           << "\r\n";
    return output.str();
}

} // namespace netobserver

