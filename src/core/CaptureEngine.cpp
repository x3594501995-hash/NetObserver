#ifndef WPCAP
#define WPCAP
#endif

#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif

#include "core/CaptureEngine.h"
#include "core/PcapNgWriter.h"

#include <pcap.h>

#include <algorithm>
#include <cctype>
#include <utility>

namespace netobserver {
namespace {

bool hasPcapNgExtension(const std::string& filePath)
{
    if (filePath.size() < 7)
        return false;
    std::string extension = filePath.substr(filePath.size() - 7);
    std::transform(
        extension.begin(),
        extension.end(),
        extension.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return extension == ".pcapng";
}

} // namespace

CaptureEngine::CaptureEngine() = default;

CaptureEngine::~CaptureEngine()
{
    close();
}

bool CaptureEngine::listAdapters(
    std::vector<AdapterInfo>& adapters,
    std::string& error)
{
    adapters.clear();
    error.clear();

    pcap_if_t* devices = nullptr;
    char errorBuffer[PCAP_ERRBUF_SIZE]{};

    if (pcap_findalldevs(&devices, errorBuffer) == -1) {
        error = errorBuffer;
        return false;
    }

    for (pcap_if_t* device = devices;
         device != nullptr;
         device = device->next) {
        AdapterInfo adapter;
        adapter.name = device->name ? device->name : "";
        adapter.description =
            device->description ? device->description : "";
        if (!adapter.name.empty())
            adapters.push_back(std::move(adapter));
    }

    pcap_freealldevs(devices);
    if (adapters.empty()) {
        error = "未找到可用的抓包网卡";
        return false;
    }
    return true;
}

bool CaptureEngine::open(
    const AdapterInfo& adapter,
    std::string& error,
    const CaptureOptions& options)
{
    error.clear();
    close();

    if (adapter.name.empty()) {
        error = "网卡名称为空";
        return false;
    }
    if (options.snapshotLength <= 0 ||
        options.readTimeoutMilliseconds < 0) {
        error = "抓包参数无效";
        return false;
    }

    char errorBuffer[PCAP_ERRBUF_SIZE]{};
    handle_ = pcap_open_live(
        adapter.name.c_str(),
        options.snapshotLength,
        options.promiscuous ? 1 : 0,
        options.readTimeoutMilliseconds,
        errorBuffer);

    if (!handle_) {
        error = errorBuffer;
        return false;
    }

    char modeErrorBuffer[PCAP_ERRBUF_SIZE]{};
    nonBlocking_ =
        pcap_setnonblock(
            static_cast<pcap_t*>(handle_),
            1,
            modeErrorBuffer) == 0;

    adapterName_ = adapter.name;
    adapterDescription_ = adapter.description;
    nextPacketNumber_ = 1;
    offline_ = false;
    return true;
}

bool CaptureEngine::openOffline(
    const std::string& filePath,
    std::string& error)
{
    error.clear();
    close();
    if (filePath.empty()) {
        error = "抓包文件路径为空";
        return false;
    }

    char errorBuffer[PCAP_ERRBUF_SIZE]{};
    handle_ = pcap_open_offline(filePath.c_str(), errorBuffer);
    if (!handle_) {
        error = errorBuffer;
        return false;
    }

    adapterName_ = filePath;
    adapterDescription_ = "Offline capture";
    nextPacketNumber_ = 1;
    offline_ = true;
    nonBlocking_ = false;
    return true;
}

bool CaptureEngine::setFilter(
    const std::string& bpfExpression,
    std::string& error)
{
    error.clear();
    if (!handle_) {
        error = "抓包网卡尚未打开";
        return false;
    }
    if (offline_) {
        error = "离线抓包文件不能设置实时捕获过滤器";
        return false;
    }
    if (bpfExpression.empty())
        return true;

    auto* handle = static_cast<pcap_t*>(handle_);
    bpf_u_int32 network = 0;
    bpf_u_int32 netmask = 0;
    char errorBuffer[PCAP_ERRBUF_SIZE]{};

    if (pcap_lookupnet(
            adapterName_.c_str(),
            &network,
            &netmask,
            errorBuffer) == -1) {
        network = 0;
        netmask = 0;
    }

    bpf_program program{};
    if (pcap_compile(
            handle,
            &program,
            bpfExpression.c_str(),
            1,
            netmask) == -1) {
        error = pcap_geterr(handle);
        return false;
    }

    const int result = pcap_setfilter(handle, &program);
    if (result == -1)
        error = pcap_geterr(handle);
    pcap_freecode(&program);
    return result != -1;
}

bool CaptureEngine::startPcapDump(
    const std::string& filePath,
    std::string& error)
{
    error.clear();
    if (!handle_) {
        error = "抓包网卡尚未打开";
        return false;
    }
    if (offline_) {
        error = "不能向离线抓包文件写入新的捕获数据";
        return false;
    }
    if (dumper_) {
        pcap_dump_close(static_cast<pcap_dumper_t*>(dumper_));
        dumper_ = nullptr;
    }
    pcapngWriter_.reset();
    if (filePath.empty()) {
        error = "pcap 文件路径为空";
        return false;
    }

    auto* handle = static_cast<pcap_t*>(handle_);
    if (hasPcapNgExtension(filePath)) {
        pcapngWriter_ = std::make_unique<PcapNgWriter>();
        if (!pcapngWriter_->open(
                filePath,
                static_cast<std::uint16_t>(pcap_datalink(handle)),
                static_cast<std::uint32_t>(pcap_snapshot(handle)),
                error)) {
            pcapngWriter_.reset();
            return false;
        }
    } else {
        dumper_ = pcap_dump_open(handle, filePath.c_str());
        if (!dumper_) {
            error = pcap_geterr(handle);
            return false;
        }
    }
    return true;
}

CaptureResult CaptureEngine::next(
    std::vector<std::uint8_t>& packetData,
    ParsedPacket& metadata,
    std::string& error)
{
    packetData.clear();
    error.clear();
    if (!handle_) {
        error = "抓包网卡尚未打开";
        return CaptureResult::Error;
    }

    auto* handle = static_cast<pcap_t*>(handle_);
    pcap_pkthdr* packetHeader = nullptr;
    const u_char* rawPacket = nullptr;
    const int result = pcap_next_ex(handle, &packetHeader, &rawPacket);

    if (result == 0)
        return CaptureResult::Timeout;
    if (result == -2)
        return CaptureResult::End;
    if (result == -1) {
        error = pcap_geterr(handle);
        return CaptureResult::Error;
    }
    if (!packetHeader || !rawPacket) {
        error = "抓包库返回了空数据";
        return CaptureResult::Error;
    }

    if (pcapngWriter_) {
        if (!pcapngWriter_->writePacket(
                packetHeader->ts.tv_sec,
                packetHeader->ts.tv_usec,
                rawPacket,
                packetHeader->caplen,
                packetHeader->len)) {
            error = "写入 pcapng 文件失败；请检查磁盘空间和文件权限";
            return CaptureResult::Error;
        }
    } else if (dumper_) {
        pcap_dump(
            static_cast<u_char*>(dumper_),
            packetHeader,
            rawPacket);
    }

    packetData.assign(rawPacket, rawPacket + packetHeader->caplen);
    metadata = ParsedPacket{};
    metadata.number = nextPacketNumber_++;
    metadata.timestampSeconds =
        static_cast<std::int64_t>(packetHeader->ts.tv_sec);
    metadata.timestampMicroseconds =
        static_cast<std::int64_t>(packetHeader->ts.tv_usec);
    metadata.capturedLength = packetHeader->caplen;
    metadata.originalLength = packetHeader->len;
    return CaptureResult::Packet;
}

bool CaptureEngine::statistics(
    CaptureStatistics& statistics,
    std::string& error) const
{
    error.clear();
    statistics = CaptureStatistics{};
    if (!handle_) {
        error = "抓包网卡尚未打开";
        return false;
    }

    pcap_stat captureStatistics{};
    auto* handle = static_cast<pcap_t*>(handle_);
    if (pcap_stats(handle, &captureStatistics) == -1) {
        error = pcap_geterr(handle);
        return false;
    }

    statistics.received = captureStatistics.ps_recv;
    statistics.dropped = captureStatistics.ps_drop;
    statistics.interfaceDropped = captureStatistics.ps_ifdrop;
    return true;
}

bool CaptureEngine::flushOutput(std::string& error)
{
    error.clear();
    if (pcapngWriter_)
        return pcapngWriter_->flush(error);
    if (dumper_ && handle_) {
        if (pcap_dump_flush(static_cast<pcap_dumper_t*>(dumper_)) == -1) {
            error = pcap_geterr(static_cast<pcap_t*>(handle_));
            return false;
        }
    }
    return true;
}

void CaptureEngine::breakLoop()
{
    if (handle_)
        pcap_breakloop(static_cast<pcap_t*>(handle_));
}

void CaptureEngine::close()
{
    if (dumper_) {
        pcap_dump_close(static_cast<pcap_dumper_t*>(dumper_));
        dumper_ = nullptr;
    }
    pcapngWriter_.reset();
    if (handle_)
        pcap_close(static_cast<pcap_t*>(handle_));
    handle_ = nullptr;
    adapterName_.clear();
    adapterDescription_.clear();
    nextPacketNumber_ = 1;
    offline_ = false;
    nonBlocking_ = false;
}

bool CaptureEngine::isOpen() const noexcept
{
    return handle_ != nullptr;
}

bool CaptureEngine::isOffline() const noexcept
{
    return offline_;
}

int CaptureEngine::dataLinkType() const noexcept
{
    if (!handle_)
        return -1;
    return pcap_datalink(static_cast<pcap_t*>(handle_));
}

const std::string& CaptureEngine::adapterName() const noexcept
{
    return adapterName_;
}

} // namespace netobserver
