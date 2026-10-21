#include "core/CaptureEngine.h"
#include "core/PacketParser.h"

#include <windows.h>

#include <atomic>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

std::atomic_bool stopRequested{false};

BOOL WINAPI consoleControlHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        stopRequested.store(true);
        return TRUE;
    }
    return FALSE;
}

void printUsage()
{
    std::cout
        << "用法:\n"
        << "  netobserver-cli --list\n"
        << "  netobserver-cli [--adapter <序号>] [--filter <BPF表达式>]\n\n"
        << "示例:\n"
        << "  netobserver-cli --adapter 1 --filter \"tcp port 80\"\n";
}

bool parseInteger(const std::string& text, int& value)
{
    try {
        std::size_t consumed = 0;
        value = std::stoi(text, &consumed);
        return consumed == text.size();
    } catch (...) {
        return false;
    }
}

std::string adapterLabel(const netobserver::AdapterInfo& adapter)
{
    if (!adapter.description.empty())
        return adapter.description + " [" + adapter.name + "]";
    return adapter.name;
}

} // namespace

int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    int requestedAdapter = 0;
    std::string requestedFilter;
    bool listOnly = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--list") {
            listOnly = true;
        } else if (argument == "--adapter" && index + 1 < argc) {
            if (!parseInteger(argv[++index], requestedAdapter) ||
                requestedAdapter <= 0) {
                std::cerr << "网卡序号无效\n";
                return 2;
            }
        } else if (argument == "--filter" && index + 1 < argc) {
            requestedFilter = argv[++index];
        } else if (argument == "--help" || argument == "-h") {
            printUsage();
            return 0;
        } else {
            std::cerr << "未知参数: " << argument << "\n";
            printUsage();
            return 2;
        }
    }

    std::vector<netobserver::AdapterInfo> adapters;
    std::string error;
    if (!netobserver::CaptureEngine::listAdapters(adapters, error)) {
        std::cerr << "枚举网卡失败: " << error << "\n";
        return 1;
    }

    std::cout << "可用网卡:\n";
    for (std::size_t index = 0; index < adapters.size(); ++index) {
        std::cout << "  " << index + 1 << ". "
                  << adapterLabel(adapters[index]) << "\n";
    }
    if (listOnly)
        return 0;

    int adapterChoice = requestedAdapter;
    if (adapterChoice == 0) {
        std::cout << "选择网卡序号: ";
        if (!(std::cin >> adapterChoice) ||
            adapterChoice < 1 ||
            adapterChoice > static_cast<int>(adapters.size())) {
            std::cerr << "网卡序号无效\n";
            return 2;
        }
    } else if (adapterChoice > static_cast<int>(adapters.size())) {
        std::cerr << "网卡序号超出范围\n";
        return 2;
    }

    std::string filter = requestedFilter;
    if (filter.empty() && requestedAdapter == 0) {
        std::cin.ignore(
            std::numeric_limits<std::streamsize>::max(),
            '\n');
        std::cout << "输入 BPF 过滤器（直接回车表示不过滤）: ";
        std::getline(std::cin, filter);
    }

    netobserver::CaptureEngine engine;
    if (!engine.open(adapters[adapterChoice - 1], error)) {
        std::cerr << "打开网卡失败: " << error << "\n";
        return 1;
    }
    if (!engine.setFilter(filter, error)) {
        std::cerr << "设置过滤器失败: " << error << "\n";
        return 1;
    }

    SetConsoleCtrlHandler(consoleControlHandler, TRUE);
    std::cout
        << "\n开始抓包。按 Ctrl+C 停止。\n"
        << "过滤条件: " << (filter.empty() ? "<全部数据包>" : filter)
        << "\n\n";

    std::size_t parsedPackets = 0;
    while (!stopRequested.load()) {
        std::vector<std::uint8_t> packetData;
        netobserver::ParsedPacket metadata;
        const auto result = engine.next(packetData, metadata, error);

        if (result == netobserver::CaptureResult::Timeout)
            continue;
        if (result == netobserver::CaptureResult::End)
            break;
        if (result == netobserver::CaptureResult::Error) {
            std::cerr << "抓包失败: " << error << "\n";
            break;
        }

        auto packet = netobserver::PacketParser::parsePacket(
            packetData.data(),
            packetData.size(),
            metadata.originalLength,
            engine.dataLinkType());
        packet.number = metadata.number;
        packet.timestampSeconds = metadata.timestampSeconds;
        packet.timestampMicroseconds = metadata.timestampMicroseconds;

        ++parsedPackets;
        std::cout << "[" << packet.number << "] " << packet.summary
                  << " (" << packet.capturedLength << " bytes)\n";
        if (!packet.applicationSummary.empty()) {
            std::cout << "    " << packet.applicationProtocol
                      << ": " << packet.applicationSummary << "\n";
        }
    }

    netobserver::CaptureStatistics statistics;
    if (engine.statistics(statistics, error)) {
        std::cout
            << "\n抓包统计\n"
            << "  已显示: " << parsedPackets << "\n"
            << "  驱动接收: " << statistics.received << "\n"
            << "  驱动丢弃: " << statistics.dropped << "\n"
            << "  网卡丢弃: " << statistics.interfaceDropped << "\n";
    }

    engine.close();
    return 0;
}

