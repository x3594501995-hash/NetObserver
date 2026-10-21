#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace netobserver {

class PcapNgWriter {
public:
    PcapNgWriter();
    PcapNgWriter(const PcapNgWriter&) = delete;
    PcapNgWriter& operator=(const PcapNgWriter&) = delete;
    ~PcapNgWriter();

    bool open(
        const std::string& filePath,
        std::uint16_t linkType,
        std::uint32_t snapshotLength,
        std::string& error);
    void writePacket(
        std::int64_t seconds,
        std::int64_t microseconds,
        const std::uint8_t* data,
        std::uint32_t capturedLength,
        std::uint32_t originalLength);
    void close();
    bool isOpen() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace netobserver

