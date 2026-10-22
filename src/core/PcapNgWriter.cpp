#include "core/PcapNgWriter.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <system_error>
#include <vector>

namespace netobserver {

namespace {

void appendU16(std::vector<std::uint8_t>& output, std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void appendU32(std::vector<std::uint8_t>& output, std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
}

void appendU64(std::vector<std::uint8_t>& output, std::uint64_t value)
{
    appendU32(output, static_cast<std::uint32_t>(value));
    appendU32(output, static_cast<std::uint32_t>(value >> 32U));
}

void setU32(
    std::vector<std::uint8_t>& output,
    std::size_t offset,
    std::uint32_t value)
{
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 2] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 3] = static_cast<std::uint8_t>(value >> 24U);
}

void appendOption(
    std::vector<std::uint8_t>& block,
    std::uint16_t code,
    const std::vector<std::uint8_t>& value)
{
    appendU16(block, code);
    appendU16(block, static_cast<std::uint16_t>(value.size()));
    block.insert(block.end(), value.begin(), value.end());
    while (block.size() % 4 != 0)
        block.push_back(0);
}

bool finishBlock(
    std::vector<std::uint8_t>& block,
    std::ofstream& output)
{
    while (block.size() % 4 != 0)
        block.push_back(0);
    const std::uint32_t totalLength =
        static_cast<std::uint32_t>(block.size() + 4);
    setU32(block, 4, totalLength);
    appendU32(block, totalLength);
    output.write(
        reinterpret_cast<const char*>(block.data()),
        static_cast<std::streamsize>(block.size()));
    return static_cast<bool>(output);
}

std::vector<std::uint8_t> optionText(const char* text)
{
    return std::vector<std::uint8_t>(text, text + std::strlen(text));
}

} // namespace

struct PcapNgWriter::Impl {
    std::ofstream output;
    std::uint16_t linkType = 1;
    std::uint32_t snapshotLength = 65535;
    std::uint32_t packetCount = 0;
};

PcapNgWriter::PcapNgWriter()
    : impl_(std::make_unique<Impl>())
{
}

PcapNgWriter::~PcapNgWriter()
{
    close();
}

bool PcapNgWriter::open(
    const std::string& filePath,
    std::uint16_t linkType,
    std::uint32_t snapshotLength,
    std::string& error)
{
    error.clear();
    close();
    impl_->linkType = linkType;
    impl_->snapshotLength = snapshotLength;
    impl_->packetCount = 0;
    impl_->output.open(filePath, std::ios::binary | std::ios::trunc);
    if (!impl_->output) {
        error = std::error_code(errno, std::generic_category()).message();
        return false;
    }

    std::vector<std::uint8_t> shb;
    appendU32(shb, 0x0A0D0D0A);
    appendU32(shb, 0);
    appendU32(shb, 0x1A2B3C4D);
    appendU16(shb, 1);
    appendU16(shb, 0);
    appendU64(shb, 0xFFFFFFFFFFFFFFFFULL);
    appendOption(shb, 4, optionText("NetObserver 0.2.9"));
    appendU16(shb, 0);
    appendU16(shb, 0);
    if (!finishBlock(shb, impl_->output)) {
        error = "写入 pcapng Section Header 失败";
        close();
        return false;
    }

    std::vector<std::uint8_t> idb;
    appendU32(idb, 0x00000001);
    appendU32(idb, 0);
    appendU16(idb, linkType);
    appendU16(idb, 0);
    appendU32(idb, snapshotLength);
    appendOption(idb, 2, optionText("NetObserver capture"));
    appendOption(idb, 9, {6});
    appendU16(idb, 0);
    appendU16(idb, 0);
    if (!finishBlock(idb, impl_->output)) {
        error = "写入 pcapng Interface Description 失败";
        close();
        return false;
    }

    if (!impl_->output) {
        error = "写入 pcapng 文件头失败";
        close();
        return false;
    }
    impl_->output.flush();
    return true;
}

bool PcapNgWriter::writePacket(
    std::int64_t seconds,
    std::int64_t microseconds,
    const std::uint8_t* data,
    std::uint32_t capturedLength,
    std::uint32_t originalLength)
{
    if (!isOpen() || !data)
        return false;

    const std::uint64_t timestamp =
        static_cast<std::uint64_t>(
            seconds * 1000000LL + microseconds);
    std::vector<std::uint8_t> block;
    block.reserve(static_cast<std::size_t>(capturedLength) + 64);
    appendU32(block, 0x00000006);
    appendU32(block, 0);
    appendU32(block, 0);
    appendU32(block, static_cast<std::uint32_t>(timestamp >> 32U));
    appendU32(block, static_cast<std::uint32_t>(timestamp));
    appendU32(block, capturedLength);
    appendU32(block, originalLength);
    block.insert(block.end(), data, data + capturedLength);
    if (!finishBlock(block, impl_->output))
        return false;

    ++impl_->packetCount;
    if (impl_->packetCount % 32 == 0) {
        impl_->output.flush();
        return static_cast<bool>(impl_->output);
    }
    return true;
}

bool PcapNgWriter::flush(std::string& error)
{
    error.clear();
    if (!isOpen())
        return true;
    impl_->output.flush();
    if (!impl_->output) {
        error = "刷新 pcapng 文件失败";
        return false;
    }
    return true;
}

void PcapNgWriter::close()
{
    if (!impl_)
        return;
    if (impl_->output.is_open()) {
        impl_->output.flush();
        impl_->output.close();
    }
    impl_->packetCount = 0;
}

bool PcapNgWriter::isOpen() const noexcept
{
    return impl_ && impl_->output.is_open();
}

} // namespace netobserver
