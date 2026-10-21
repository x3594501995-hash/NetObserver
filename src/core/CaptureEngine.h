#pragma once

#include "core/PacketTypes.h"

#include <cstdint>
#include <string>
#include <vector>

namespace netobserver {

struct AdapterInfo {
    std::string name;
    std::string description;
};

struct CaptureOptions {
    int snapshotLength = 65535;
    bool promiscuous = true;
    int readTimeoutMilliseconds = 1000;
};

enum class CaptureResult {
    Packet,
    Timeout,
    End,
    Error,
};

class CaptureEngine {
public:
    CaptureEngine() = default;
    CaptureEngine(const CaptureEngine&) = delete;
    CaptureEngine& operator=(const CaptureEngine&) = delete;
    ~CaptureEngine();

    static bool listAdapters(
        std::vector<AdapterInfo>& adapters,
        std::string& error);

    bool open(
        const AdapterInfo& adapter,
        std::string& error,
        const CaptureOptions& options = {});
    bool setFilter(const std::string& bpfExpression, std::string& error);
    bool startPcapDump(const std::string& filePath, std::string& error);

    CaptureResult next(
        std::vector<std::uint8_t>& packetData,
        ParsedPacket& metadata,
        std::string& error);

    bool statistics(CaptureStatistics& statistics, std::string& error) const;
    void breakLoop();
    void close();

    bool isOpen() const noexcept;
    int dataLinkType() const noexcept;
    const std::string& adapterName() const noexcept;

private:
    void* handle_ = nullptr;
    void* dumper_ = nullptr;
    std::string adapterName_;
    std::string adapterDescription_;
    std::uint64_t nextPacketNumber_ = 1;
};

} // namespace netobserver
