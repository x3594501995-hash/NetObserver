#pragma once

#include "core/PacketTypes.h"

#include <cstddef>
#include <cstdint>

namespace netobserver {

class PacketParser {
public:
    static ParsedPacket parseEthernet(
        const std::uint8_t* data,
        std::size_t capturedLength,
        std::uint32_t originalLength = 0);

    static ParsedPacket parsePacket(
        const std::uint8_t* data,
        std::size_t capturedLength,
        std::uint32_t originalLength,
        int dataLinkType);
};

} // namespace netobserver

