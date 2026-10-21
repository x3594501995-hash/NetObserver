#pragma once

#include "core/PacketTypes.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace netobserver {

struct FlowStatistics {
    std::string key;
    std::string protocol;
    std::string endpointA;
    std::string endpointB;
    std::uint64_t packetsAToB = 0;
    std::uint64_t packetsBToA = 0;
    std::uint64_t bytesAToB = 0;
    std::uint64_t bytesBToA = 0;
    std::int64_t firstTimestampSeconds = 0;
    std::int64_t lastTimestampSeconds = 0;
    bool tcpStreamAvailable = false;
};

class FlowTracker {
public:
    FlowTracker();
    FlowTracker(const FlowTracker&) = delete;
    FlowTracker& operator=(const FlowTracker&) = delete;
    ~FlowTracker();

    void addPacket(
        const ParsedPacket& packet,
        const std::uint8_t* packetData,
        std::size_t packetLength);
    void clear();

    static std::string flowKey(const ParsedPacket& packet);
    std::vector<FlowStatistics> statistics() const;
    std::string followStream(
        const std::string& key,
        bool fullContent = false) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace netobserver

