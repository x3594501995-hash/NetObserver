#include "core/CaptureEngine.h"
#include "core/DisplayFilter.h"
#include "core/PacketParser.h"

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iterator>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kWindowClass[] = L"NetObserverMainWindow";
constexpr wchar_t kWindowTitle[] = L"NetObserver - 网络协议分析器";
constexpr int kAppIcon = 101;

constexpr int kIdAdapter = 1001;
constexpr int kIdRefresh = 1002;
constexpr int kIdFilter = 1003;
constexpr int kIdStart = 1004;
constexpr int kIdStop = 1005;
constexpr int kIdPacketList = 1006;
constexpr int kIdDetailsTree = 1007;
constexpr int kIdHex = 1008;
constexpr int kIdStatus = 1009;
constexpr int kIdPresetFirst = 1010;
constexpr int kIdPresetLast = 1014;
constexpr int kIdClear = 1015;
constexpr int kIdTabs = 1016;
constexpr int kIdPcapPath = 1017;
constexpr int kIdStatistics = 1018;
constexpr int kIdDisplayFilter = 1019;
constexpr int kIdApplyFilter = 1020;
constexpr int kIdOpenPcap = 1021;

constexpr UINT kMessageStarted = WM_APP + 1;
constexpr UINT kMessageError = WM_APP + 2;
constexpr UINT kMessageStopped = WM_APP + 3;
constexpr UINT kMessagePacket = WM_APP + 4;
constexpr UINT kMessageOfflineLoaded = WM_APP + 5;

constexpr COLORREF kBackgroundColor = RGB(243, 246, 250);
constexpr COLORREF kHeaderColor = RGB(24, 42, 75);
constexpr COLORREF kTextColor = RGB(39, 49, 64);
constexpr COLORREF kMutedColor = RGB(104, 118, 138);
constexpr COLORREF kAccentColor = RGB(30, 101, 180);

struct FilterPreset {
    const wchar_t* label;
    const wchar_t* expression;
};

constexpr FilterPreset kPresets[] = {
    {L"ICMP", L"icmp"},
    {L"ARP", L"arp"},
    {L"DNS", L"udp port 53 or tcp port 53"},
    {L"TCP", L"tcp"},
    {L"HTTP", L"tcp port 80 or tcp port 8080"},
};

struct PacketRecord {
    std::vector<std::uint8_t> bytes;
    netobserver::ParsedPacket parsed;
};

struct AppState {
    HWND window = nullptr;
    HWND title = nullptr;
    HWND subtitle = nullptr;
    HWND state = nullptr;
    HWND setupGroup = nullptr;
    HWND statsGroup = nullptr;
    HWND adapterCombo = nullptr;
    HWND refreshButton = nullptr;
    HWND filterEdit = nullptr;
    HWND startButton = nullptr;
    HWND stopButton = nullptr;
    HWND clearButton = nullptr;
    HWND openButton = nullptr;
    HWND packetList = nullptr;
    HWND displayFilterEdit = nullptr;
    HWND applyFilterButton = nullptr;
    HWND tabs = nullptr;
    HWND detailsTree = nullptr;
    HWND hexEdit = nullptr;
    HWND statsLabel = nullptr;
    HWND pcapPath = nullptr;
    HWND statusLabel = nullptr;

    std::vector<netobserver::AdapterInfo> adapters;
    std::vector<std::unique_ptr<PacketRecord>> packets;
    netobserver::DisplayFilter displayFilter;
    std::atomic_bool running{false};
    bool loadingOffline = false;
    std::thread worker;
    std::mutex engineMutex;
    netobserver::CaptureEngine* activeEngine = nullptr;

    std::uint64_t totalPackets = 0;
    std::uint64_t visiblePackets = 0;
    std::uint64_t totalBytes = 0;
    std::uint64_t tcp = 0;
    std::uint64_t udp = 0;
    std::uint64_t arp = 0;
    std::uint64_t icmp = 0;
    std::uint64_t igmp = 0;
    int activeTab = 0;

    HFONT titleFont = nullptr;
    HFONT subtitleFont = nullptr;
    HFONT uiFont = nullptr;
    HFONT monoFont = nullptr;
    HBRUSH backgroundBrush = nullptr;
    HBRUSH headerBrush = nullptr;
};

AppState g_app;

HMENU controlId(int id)
{
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

std::wstring utf8ToWide(const std::string& input)
{
    if (input.empty())
        return {};
    const int size = MultiByteToWideChar(
        CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (size <= 0)
        return {};
    std::wstring output(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, input.data(), static_cast<int>(input.size()),
        output.data(), size);
    return output;
}

std::string windowTextUtf8(HWND window)
{
    const int length = GetWindowTextLengthW(window);
    if (length <= 0)
        return {};
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(window, text.data(), length + 1);
    const int size = WideCharToMultiByte(
        CP_UTF8, 0, text.data(), length, nullptr, 0, nullptr, nullptr);
    if (size <= 0)
        return {};
    std::string output(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, text.data(), length, output.data(), size, nullptr, nullptr);
    return output;
}

std::string wideToUtf8(const std::wstring& input)
{
    if (input.empty())
        return {};
    const int size = WideCharToMultiByte(
        CP_UTF8, 0, input.data(), static_cast<int>(input.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0)
        return {};
    std::string output(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, input.data(), static_cast<int>(input.size()),
        output.data(), size, nullptr, nullptr);
    return output;
}

void setStatus(const std::wstring& text)
{
    SetWindowTextW(g_app.statusLabel, text.c_str());
}

void setRunningUi(bool running)
{
    EnableWindow(g_app.adapterCombo, !running);
    EnableWindow(g_app.refreshButton, !running);
    EnableWindow(g_app.filterEdit, !running);
    EnableWindow(g_app.startButton, !running);
    EnableWindow(g_app.stopButton, running);
    EnableWindow(g_app.openButton, !running);
    for (int id = kIdPresetFirst; id <= kIdPresetLast; ++id)
        EnableWindow(GetDlgItem(g_app.window, id), !running);

    SetWindowTextW(g_app.state, running ? L"● 正在捕获" : L"● 就绪");
    InvalidateRect(g_app.state, nullptr, TRUE);
}

std::wstring clockText(const netobserver::ParsedPacket& packet)
{
    const std::time_t seconds =
        static_cast<std::time_t>(packet.timestampSeconds);
    std::tm value{};
    localtime_s(&value, &seconds);
    std::wostringstream output;
    output << std::setfill(L'0')
           << std::setw(2) << value.tm_hour << L":"
           << std::setw(2) << value.tm_min << L":"
           << std::setw(2) << value.tm_sec << L"."
           << std::setw(6) << packet.timestampMicroseconds;
    return output.str();
}

std::wstring statisticsText(
    bool includeDriver = false,
    netobserver::CaptureStatistics driver = {})
{
    std::wostringstream output;
    output << L"显示/捕获 " << g_app.visiblePackets
           << L" / " << g_app.totalPackets << L"\r\n"
           << L"总字节    " << g_app.totalBytes << L"\r\n"
           << L"TCP       " << g_app.tcp << L"\r\n"
           << L"UDP       " << g_app.udp << L"\r\n"
           << L"ICMP      " << g_app.icmp << L"\r\n"
           << L"ARP       " << g_app.arp << L"\r\n"
           << L"IGMP      " << g_app.igmp;
    if (includeDriver) {
        output << L"\r\n\r\n驱动接收  " << driver.received
               << L"\r\n驱动丢弃  " << driver.dropped
               << L"\r\n网卡丢弃  " << driver.interfaceDropped;
    }
    return output.str();
}

void refreshStatistics()
{
    const std::wstring text = statisticsText();
    SetWindowTextW(g_app.statsLabel, text.c_str());
}

void countPacket(const netobserver::ParsedPacket& packet)
{
    ++g_app.totalPackets;
    g_app.totalBytes += packet.capturedLength;
    if (packet.protocol == "TCP")
        ++g_app.tcp;
    else if (packet.protocol == "UDP")
        ++g_app.udp;
    else if (packet.protocol == "ARP")
        ++g_app.arp;
    else if (packet.protocol == "ICMP")
        ++g_app.icmp;
    else if (packet.protocol == "IGMP")
        ++g_app.igmp;
    refreshStatistics();
}

void populateAdapters()
{
    ComboBox_ResetContent(g_app.adapterCombo);
    g_app.adapters.clear();
    std::string error;
    if (!netobserver::CaptureEngine::listAdapters(g_app.adapters, error)) {
        setStatus(L"枚举网卡失败: " + utf8ToWide(error));
        return;
    }
    for (const auto& adapter : g_app.adapters) {
        std::wstring label = utf8ToWide(
            adapter.description.empty() ? adapter.name : adapter.description);
        label += L" [" + utf8ToWide(adapter.name) + L"]";
        ComboBox_AddString(g_app.adapterCombo, label.c_str());
    }
    if (!g_app.adapters.empty())
        ComboBox_SetCurSel(g_app.adapterCombo, 0);
    setStatus(L"选择网卡和过滤条件，然后开始捕获");
}

void setupList()
{
    ListView_SetExtendedListViewStyle(
        g_app.packetList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    const struct {
        const wchar_t* name;
        int width;
    } columns[] = {
        {L"序号", 64}, {L"时间", 112}, {L"源地址", 142},
        {L"目的地址", 142}, {L"协议", 76}, {L"源端口", 72},
        {L"目的端口", 76}, {L"长度", 68}, {L"摘要", 520},
    };
    for (int index = 0; index < static_cast<int>(std::size(columns)); ++index) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.pszText = const_cast<wchar_t*>(columns[index].name);
        column.cx = columns[index].width;
        column.iSubItem = index;
        ListView_InsertColumn(g_app.packetList, index, &column);
    }
}

void resetPackets()
{
    g_app.packets.clear();
    g_app.totalPackets = 0;
    g_app.visiblePackets = 0;
    g_app.totalBytes = 0;
    g_app.tcp = 0;
    g_app.udp = 0;
    g_app.arp = 0;
    g_app.icmp = 0;
    g_app.igmp = 0;
    ListView_DeleteAllItems(g_app.packetList);
    TreeView_DeleteAllItems(g_app.detailsTree);
    SetWindowTextW(g_app.hexEdit, L"");
    refreshStatistics();
}

std::wstring packetDetailsSummary(const PacketRecord& record)
{
    const auto& packet = record.parsed;
    std::wostringstream output;
    output << L"数据包 #" << packet.number
           << L"\r\n时间: " << clockText(packet)
           << L"\r\n捕获长度: " << packet.capturedLength
           << L" bytes，原始长度: " << packet.originalLength
           << L"\r\n摘要: " << utf8ToWide(packet.summary) << L"\r\n";
    if (!packet.parseError.empty())
        output << L"\r\n解析错误: " << utf8ToWide(packet.parseError) << L"\r\n";
    return output.str();
}

std::wstring packetHex(const PacketRecord& record)
{
    constexpr std::size_t bytesPerLine = 16;
    constexpr std::size_t limit = 8192;
    const std::size_t length = std::min(record.bytes.size(), limit);
    std::wostringstream output;
    output << std::hex << std::uppercase << std::setfill(L'0');
    for (std::size_t offset = 0; offset < length; offset += bytesPerLine) {
        output << std::setw(8) << static_cast<std::uint32_t>(offset) << L"  ";
        for (std::size_t index = 0; index < bytesPerLine; ++index) {
            if (offset + index < length) {
                output << std::setw(2)
                       << static_cast<unsigned>(record.bytes[offset + index])
                       << L' ';
            } else {
                output << L"   ";
            }
        }
        output << L" ";
        for (std::size_t index = 0; index < bytesPerLine; ++index) {
            if (offset + index >= length)
                break;
            const unsigned char value = record.bytes[offset + index];
            output << static_cast<wchar_t>(
                value >= 32 && value <= 126 ? value : '.');
        }
        output << L"\r\n";
    }
    if (record.bytes.size() > limit) {
        output << L"\r\n仅显示前 " << std::dec << limit
               << L" 字节，原始包为 " << record.bytes.size()
               << L" 字节。\r\n";
    }
    return output.str();
}

void populateDetailsTree(const PacketRecord& record)
{
    TreeView_DeleteAllItems(g_app.detailsTree);
    const std::wstring summary = packetDetailsSummary(record);
    TVINSERTSTRUCTW summaryItem{};
    summaryItem.hParent = TVI_ROOT;
    summaryItem.hInsertAfter = TVI_LAST;
    summaryItem.item.mask = TVIF_TEXT;
    summaryItem.item.pszText = const_cast<wchar_t*>(summary.c_str());
    TreeView_InsertItem(g_app.detailsTree, &summaryItem);

    for (const auto& layer : record.parsed.layers) {
        const std::wstring layerName = utf8ToWide(layer.name);
        TVINSERTSTRUCTW layerItem{};
        layerItem.hParent = TVI_ROOT;
        layerItem.hInsertAfter = TVI_LAST;
        layerItem.item.mask = TVIF_TEXT;
        layerItem.item.pszText = const_cast<wchar_t*>(layerName.c_str());
        HTREEITEM parent = TreeView_InsertItem(g_app.detailsTree, &layerItem);
        for (const auto& field : layer.fields) {
            const std::wstring fieldText =
                utf8ToWide(field.name) + L": " + utf8ToWide(field.value);
            TVINSERTSTRUCTW fieldItem{};
            fieldItem.hParent = parent;
            fieldItem.hInsertAfter = TVI_LAST;
            fieldItem.item.mask = TVIF_TEXT;
            fieldItem.item.pszText =
                const_cast<wchar_t*>(fieldText.c_str());
            TreeView_InsertItem(g_app.detailsTree, &fieldItem);
        }
        TreeView_Expand(g_app.detailsTree, parent, TVE_EXPAND);
    }
}

void addPacket(PacketRecord* record)
{
    const auto& packet = record->parsed;
    const int index = ListView_GetItemCount(g_app.packetList);
    const std::wstring source = utf8ToWide(
        packet.sourceIp.empty() ? packet.sourceMacText : packet.sourceIp);
    const std::wstring destination = utf8ToWide(
        packet.destinationIp.empty()
            ? packet.destinationMacText
            : packet.destinationIp);
    const std::wstring number = std::to_wstring(packet.number);
    const std::wstring time = clockText(packet);
    const std::wstring protocol = utf8ToWide(packet.protocol);
    const std::wstring sourcePort =
        packet.hasPorts ? std::to_wstring(packet.sourcePort) : L"";
    const std::wstring destinationPort =
        packet.hasPorts ? std::to_wstring(packet.destinationPort) : L"";
    const std::wstring length = std::to_wstring(packet.capturedLength);
    const std::wstring summary = utf8ToWide(
        packet.applicationSummary.empty()
            ? packet.summary
            : packet.applicationSummary);

    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = index;
    item.pszText = const_cast<wchar_t*>(number.c_str());
    item.lParam = reinterpret_cast<LPARAM>(record);
    const int inserted = ListView_InsertItem(g_app.packetList, &item);
    if (inserted < 0)
        return;
    ++g_app.visiblePackets;
    const wchar_t* values[] = {
        time.c_str(), source.c_str(), destination.c_str(),
        protocol.c_str(), sourcePort.c_str(), destinationPort.c_str(),
        length.c_str(), summary.c_str(),
    };
    for (int column = 1; column < 9; ++column) {
        ListView_SetItemText(
            g_app.packetList,
            inserted,
            column,
            const_cast<wchar_t*>(values[column - 1]));
    }
    if (index == 0) {
        ListView_SetItemState(
            g_app.packetList, 0,
            LVIS_SELECTED | LVIS_FOCUSED,
            LVIS_SELECTED | LVIS_FOCUSED);
    }
}

void updateSelection()
{
    const int selected =
        ListView_GetNextItem(g_app.packetList, -1, LVNI_SELECTED);
    if (selected < 0)
        return;
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = selected;
    if (!ListView_GetItem(g_app.packetList, &item))
        return;
    const auto* record = reinterpret_cast<const PacketRecord*>(item.lParam);
    if (!record)
        return;
    populateDetailsTree(*record);
    const std::wstring hex = packetHex(*record);
    SetWindowTextW(g_app.hexEdit, hex.c_str());
}

bool packetMatchesDisplayFilter(const PacketRecord& record)
{
    return g_app.displayFilter.matches(record.parsed);
}

void rebuildPacketList()
{
    ListView_DeleteAllItems(g_app.packetList);
    TreeView_DeleteAllItems(g_app.detailsTree);
    SetWindowTextW(g_app.hexEdit, L"");
    g_app.visiblePackets = 0;

    for (const auto& record : g_app.packets) {
        if (packetMatchesDisplayFilter(*record))
            addPacket(record.get());
    }
    refreshStatistics();
}

bool applyDisplayFilter()
{
    const std::string expression =
        windowTextUtf8(g_app.displayFilterEdit);
    netobserver::DisplayFilter nextFilter;
    std::string error;
    if (!nextFilter.compile(expression, error)) {
        setStatus(L"显示过滤错误: " + utf8ToWide(error));
        return false;
    }

    g_app.displayFilter = std::move(nextFilter);
    rebuildPacketList();
    setStatus(
        expression.empty()
            ? L"显示过滤已清空"
            : L"显示过滤已应用");
    return true;
}

void setActiveTab(int index)
{
    g_app.activeTab = index;
    ShowWindow(g_app.detailsTree, index == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.hexEdit, index == 1 ? SW_SHOW : SW_HIDE);
}

void postText(HWND window, UINT message, const std::wstring& text)
{
    auto* payload = new std::wstring(text);
    if (!PostMessageW(window, message, 0, reinterpret_cast<LPARAM>(payload)))
        delete payload;
}

void captureWorker(HWND window, netobserver::AdapterInfo adapter, std::string filter)
{
    netobserver::CaptureEngine engine;
    netobserver::CaptureStatistics statistics;
    std::string error;
    bool failed = false;
    std::wstring pcapDisplay;

    if (!engine.open(adapter, error)) {
        failed = true;
        postText(window, kMessageError, L"打开网卡失败: " + utf8ToWide(error));
    } else if (!engine.setFilter(filter, error)) {
        failed = true;
        postText(window, kMessageError, L"过滤器无效: " + utf8ToWide(error));
    } else {
        std::error_code directoryError;
        std::filesystem::create_directories("captures", directoryError);
        if (directoryError) {
            failed = true;
            postText(
                window, kMessageError,
                L"创建 captures 目录失败: " + utf8ToWide(directoryError.message()));
        } else {
            SYSTEMTIME now{};
            GetLocalTime(&now);
            wchar_t fileName[128]{};
            swprintf_s(
                fileName,
                L"captures\\netobserver_%04u%02u%02u_%02u%02u%02u.pcap",
                now.wYear, now.wMonth, now.wDay,
                now.wHour, now.wMinute, now.wSecond);
            const int pathSize = WideCharToMultiByte(
                CP_UTF8, 0, fileName, -1, nullptr, 0, nullptr, nullptr);
            std::string path(static_cast<std::size_t>(std::max(0, pathSize)), '\0');
            WideCharToMultiByte(
                CP_UTF8, 0, fileName, -1, path.data(), pathSize, nullptr, nullptr);
            path.resize(static_cast<std::size_t>(std::max(0, pathSize - 1)));
            if (!engine.startPcapDump(path, error)) {
                failed = true;
                postText(
                    window, kMessageError,
                    L"创建 pcap 文件失败: " + utf8ToWide(error));
            } else {
                pcapDisplay = fileName;
            }
        }

        if (!failed) {
            {
                std::lock_guard<std::mutex> lock(g_app.engineMutex);
                g_app.activeEngine = &engine;
            }
            if (g_app.running.load())
                postText(window, kMessageStarted, pcapDisplay);

            while (!failed && g_app.running.load()) {
                std::vector<std::uint8_t> bytes;
                netobserver::ParsedPacket metadata;
                error.clear();
                const auto result = engine.next(bytes, metadata, error);
                if (result == netobserver::CaptureResult::Timeout)
                    continue;
                if (result == netobserver::CaptureResult::End)
                    break;
                if (result == netobserver::CaptureResult::Error) {
                    failed = true;
                    postText(window, kMessageError, L"抓包失败: " + utf8ToWide(error));
                    break;
                }

                auto record = std::make_unique<PacketRecord>();
                record->bytes = std::move(bytes);
                record->parsed = netobserver::PacketParser::parsePacket(
                    record->bytes.data(),
                    record->bytes.size(),
                    metadata.originalLength,
                    engine.dataLinkType());
                record->parsed.number = metadata.number;
                record->parsed.timestampSeconds = metadata.timestampSeconds;
                record->parsed.timestampMicroseconds = metadata.timestampMicroseconds;
                auto* raw = record.release();
                if (!PostMessageW(window, kMessagePacket, 0, reinterpret_cast<LPARAM>(raw))) {
                    delete raw;
                    break;
                }
            }

            if (!engine.statistics(statistics, error)) {
                failed = true;
                postText(
                    window, kMessageError,
                    L"读取抓包统计失败: " + utf8ToWide(error));
            }
            {
                std::lock_guard<std::mutex> lock(g_app.engineMutex);
                g_app.activeEngine = nullptr;
            }
        }
    }

    g_app.running.store(false);
    engine.close();
    if (failed)
        return;

    auto* result = new netobserver::CaptureStatistics(statistics);
    if (!PostMessageW(window, kMessageStopped, 0, reinterpret_cast<LPARAM>(result)))
        delete result;
}

void loadWorker(HWND window, std::string filePath)
{
    netobserver::CaptureEngine engine;
    std::string error;
    bool failed = false;

    if (!engine.openOffline(filePath, error)) {
        failed = true;
        postText(window, kMessageError, L"打开抓包文件失败: " + utf8ToWide(error));
    } else {
        {
            std::lock_guard<std::mutex> lock(g_app.engineMutex);
            g_app.activeEngine = &engine;
        }

        while (g_app.running.load()) {
            std::vector<std::uint8_t> bytes;
            netobserver::ParsedPacket metadata;
            error.clear();
            const auto result = engine.next(bytes, metadata, error);
            if (result == netobserver::CaptureResult::Timeout)
                continue;
            if (result == netobserver::CaptureResult::End)
                break;
            if (result == netobserver::CaptureResult::Error) {
                failed = true;
                postText(window, kMessageError, L"读取抓包文件失败: " + utf8ToWide(error));
                break;
            }

            auto record = std::make_unique<PacketRecord>();
            record->bytes = std::move(bytes);
            record->parsed = netobserver::PacketParser::parsePacket(
                record->bytes.data(),
                record->bytes.size(),
                metadata.originalLength,
                engine.dataLinkType());
            record->parsed.number = metadata.number;
            record->parsed.timestampSeconds = metadata.timestampSeconds;
            record->parsed.timestampMicroseconds = metadata.timestampMicroseconds;
            auto* raw = record.release();
            if (!PostMessageW(window, kMessagePacket, 0, reinterpret_cast<LPARAM>(raw))) {
                delete raw;
                failed = true;
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_app.engineMutex);
            g_app.activeEngine = nullptr;
        }
    }

    g_app.running.store(false);
    engine.close();
    if (!failed)
        PostMessageW(window, kMessageOfflineLoaded, 0, 0);
}

std::wstring choosePcapFile(HWND owner)
{
    std::vector<wchar_t> fileName(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFilter =
        L"抓包文件 (*.pcap;*.pcapng)\0*.pcap;*.pcapng\0"
        L"所有文件 (*.*)\0*.*\0\0";
    dialog.lpstrFile = fileName.data();
    dialog.nMaxFile = static_cast<DWORD>(fileName.size());
    dialog.lpstrTitle = L"打开抓包文件";
    dialog.Flags =
        OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
        OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&dialog))
        return {};
    return fileName.data();
}

void beginLoadPcap(HWND window, const std::wstring& path)
{
    if (g_app.running.load())
        return;
    if (path.empty())
        return;
    if (g_app.worker.joinable())
        g_app.worker.join();

    resetPackets();
    const std::wstring fileName =
        std::filesystem::path(path).filename().wstring();
    SetWindowTextW(g_app.pcapPath, (L"文件: " + fileName).c_str());

    g_app.running.store(true);
    g_app.loadingOffline = true;
    setRunningUi(true);
    SetWindowTextW(g_app.state, L"● 读取文件");
    setStatus(L"正在读取抓包文件...");
    g_app.worker = std::thread(
        loadWorker,
        window,
        wideToUtf8(path));
}

void openPcapFile(HWND window)
{
    beginLoadPcap(window, choosePcapFile(window));
}

void stopCapture()
{
    g_app.running.store(false);
    {
        std::lock_guard<std::mutex> lock(g_app.engineMutex);
        if (g_app.activeEngine)
            g_app.activeEngine->breakLoop();
    }
    if (g_app.worker.joinable())
        g_app.worker.join();
    setRunningUi(false);
}

void startCapture(HWND window)
{
    if (g_app.running.load())
        return;
    const int selection = ComboBox_GetCurSel(g_app.adapterCombo);
    if (selection < 0 || selection >= static_cast<int>(g_app.adapters.size())) {
        setStatus(L"请先选择有效网卡");
        return;
    }
    if (g_app.worker.joinable())
        g_app.worker.join();

    resetPackets();
    const auto adapter = g_app.adapters[selection];
    const std::string filter = windowTextUtf8(g_app.filterEdit);
    g_app.running.store(true);
    g_app.loadingOffline = false;
    setRunningUi(true);
    setStatus(L"正在打开网卡并创建 pcap 文件...");
    g_app.worker = std::thread(captureWorker, window, adapter, filter);
}

void layoutControls(HWND window)
{
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right;
    const int height = client.bottom;
    const int margin = 8;
    const int headerHeight = 64;
    const int statusHeight = 26;
    const int leftWidth = 280;
    const int contentTop = headerHeight + 12;
    const int contentBottom = height - statusHeight - margin;
    const int setupHeight = 330;
    const int statsTop = contentTop + setupHeight + 10;
    const int statsHeight = std::max(110, contentBottom - statsTop);
    const int rightX = margin + leftWidth + 10;
    const int rightWidth = width - rightX - margin;

    SetWindowPos(g_app.title, nullptr, 20, 10, 260, 30, SWP_NOZORDER);
    SetWindowPos(g_app.subtitle, nullptr, 20, 39, 460, 18, SWP_NOZORDER);
    SetWindowPos(g_app.state, nullptr, width - 170, 20, 150, 24, SWP_NOZORDER);

    SetWindowPos(
        g_app.setupGroup, nullptr, margin, contentTop,
        leftWidth, setupHeight, SWP_NOZORDER);
    SetWindowPos(
        g_app.statsGroup, nullptr, margin, statsTop,
        leftWidth, statsHeight, SWP_NOZORDER);

    const int controlX = margin + 16;
    const int controlWidth = leftWidth - 32;
    SetWindowPos(
        g_app.adapterCombo, nullptr, controlX, contentTop + 54,
        controlWidth, 180, SWP_NOZORDER);
    SetWindowPos(
        g_app.refreshButton, nullptr, controlX, contentTop + 92,
        78, 28, SWP_NOZORDER);
    SetWindowPos(
        g_app.openButton, nullptr, controlX + 82, contentTop + 92,
        78, 28, SWP_NOZORDER);
    SetWindowPos(
        g_app.clearButton, nullptr,
        controlX + 164, contentTop + 92,
        84, 28, SWP_NOZORDER);
    SetWindowPos(
        g_app.filterEdit, nullptr, controlX, contentTop + 160,
        controlWidth, 28, SWP_NOZORDER);

    const int presetWidth = (controlWidth - 4 * 4) / 5;
    for (int index = 0; index < 5; ++index) {
        SetWindowPos(
            GetDlgItem(window, kIdPresetFirst + index), nullptr,
            controlX + index * (presetWidth + 4),
            contentTop + 198,
            presetWidth, 26, SWP_NOZORDER);
    }

    SetWindowPos(
        g_app.startButton, nullptr,
        controlX, contentTop + 252,
        125, 34, SWP_NOZORDER);
    SetWindowPos(
        g_app.stopButton, nullptr,
        controlX + controlWidth - 125, contentTop + 252,
        125, 34, SWP_NOZORDER);

    SetWindowPos(
        g_app.statsLabel, nullptr,
        controlX, statsTop + 32,
        controlWidth, std::max(100, statsHeight - 104),
        SWP_NOZORDER);
    SetWindowPos(
        g_app.pcapPath, nullptr,
        controlX, contentBottom - 54,
        controlWidth, 32, SWP_NOZORDER);

    const int displayFilterY = contentTop;
    const int filterButtonWidth = 82;
    SetWindowPos(
        g_app.displayFilterEdit, nullptr,
        rightX + 70, displayFilterY,
        std::max(140, rightWidth - 70 - filterButtonWidth - 6), 28,
        SWP_NOZORDER);
    SetWindowPos(
        g_app.applyFilterButton, nullptr,
        rightX + rightWidth - filterButtonWidth,
        displayFilterY, filterButtonWidth, 28, SWP_NOZORDER);

    const int listTop = contentTop + 36;
    const int remainingHeight = contentBottom - listTop;
    const int listHeight = std::max(
        160,
        static_cast<int>(remainingHeight * 0.56));
    SetWindowPos(
        g_app.packetList, nullptr,
        rightX, listTop, rightWidth, listHeight, SWP_NOZORDER);
    SetWindowPos(
        g_app.tabs, nullptr,
        rightX, listTop + listHeight + 8,
        rightWidth, std::max(130, contentBottom - listTop - listHeight - 8),
        SWP_NOZORDER);

    RECT page{};
    GetClientRect(g_app.tabs, &page);
    TabCtrl_AdjustRect(g_app.tabs, FALSE, &page);
    MapWindowPoints(g_app.tabs, window, reinterpret_cast<POINT*>(&page), 2);
    SetWindowPos(
        g_app.detailsTree, nullptr,
        page.left + 2, page.top + 2,
        page.right - page.left - 4, page.bottom - page.top - 4,
        SWP_NOZORDER);
    SetWindowPos(
        g_app.hexEdit, nullptr,
        page.left + 2, page.top + 2,
        page.right - page.left - 4, page.bottom - page.top - 4,
        SWP_NOZORDER);

    SetWindowPos(
        g_app.statusLabel, nullptr,
        margin, height - statusHeight,
        width - margin * 2, statusHeight - 2, SWP_NOZORDER);
}

void createHeader(HWND window, HINSTANCE instance)
{
    g_app.title = CreateWindowExW(
        0, L"STATIC", L"NetObserver",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 10, 260, 30, window, nullptr, instance, nullptr);
    g_app.subtitle = CreateWindowExW(
        0, L"STATIC", L"Windows Network Protocol Analyzer  ·  v0.1.0",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 39, 460, 18, window, nullptr, instance, nullptr);
    g_app.state = CreateWindowExW(
        0, L"STATIC", L"● 就绪",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        1080, 20, 150, 24, window, nullptr, instance, nullptr);
    SetWindowFont(g_app.title, g_app.titleFont, TRUE);
    SetWindowFont(g_app.subtitle, g_app.subtitleFont, TRUE);
    SetWindowFont(g_app.state, g_app.uiFont, TRUE);
}

void createControls(HWND window)
{
    const HINSTANCE instance =
        reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(window, GWLP_HINSTANCE));
    createHeader(window, instance);

    g_app.setupGroup = CreateWindowExW(
        0, L"BUTTON", L"抓包设置",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        8, 76, 280, 330, window, nullptr, instance, nullptr);
    g_app.statsGroup = CreateWindowExW(
        0, L"BUTTON", L"实时统计",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        8, 416, 280, 300, window, nullptr, instance, nullptr);
    SetWindowFont(g_app.setupGroup, g_app.uiFont, TRUE);
    SetWindowFont(g_app.statsGroup, g_app.uiFont, TRUE);

    CreateWindowExW(
        0, L"STATIC", L"网络适配器",
        WS_CHILD | WS_VISIBLE,
        24, 100, 200, 20, window, nullptr, instance, nullptr);
    CreateWindowExW(
        0, L"STATIC", L"BPF 捕获过滤（可留空）",
        WS_CHILD | WS_VISIBLE,
        24, 204, 248, 20, window, nullptr, instance, nullptr);

    g_app.adapterCombo = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"COMBOBOX", nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        24, 130, 248, 180, window, controlId(kIdAdapter), instance, nullptr);
    g_app.refreshButton = CreateWindowExW(
        0, L"BUTTON", L"刷新网卡",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        24, 168, 78, 28, window, controlId(kIdRefresh), instance, nullptr);
    g_app.openButton = CreateWindowExW(
        0, L"BUTTON", L"打开 pcap",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        106, 168, 78, 28, window, controlId(kIdOpenPcap), instance, nullptr);
    g_app.clearButton = CreateWindowExW(
        0, L"BUTTON", L"清空结果",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        188, 168, 84, 28, window, controlId(kIdClear), instance, nullptr);
    g_app.filterEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        24, 236, 248, 28, window, controlId(kIdFilter), instance, nullptr);

    for (int index = 0; index < 5; ++index) {
        CreateWindowExW(
            0, L"BUTTON", kPresets[index].label,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            24 + index * 50, 274, 46, 26, window,
            controlId(kIdPresetFirst + index), instance, nullptr);
    }

    g_app.startButton = CreateWindowExW(
        0, L"BUTTON", L"开始捕获",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        24, 328, 125, 34, window, controlId(kIdStart), instance, nullptr);
    g_app.stopButton = CreateWindowExW(
        0, L"BUTTON", L"停止",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        147, 328, 125, 34, window, controlId(kIdStop), instance, nullptr);
    EnableWindow(g_app.stopButton, FALSE);

    g_app.statsLabel = CreateWindowExW(
        0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        24, 448, 248, 160, window, controlId(kIdStatistics), instance, nullptr);
    g_app.pcapPath = CreateWindowExW(
        0, L"STATIC", L"pcap: 尚未开始",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
        24, 674, 248, 28, window, controlId(kIdPcapPath), instance, nullptr);

    CreateWindowExW(
        0, L"STATIC", L"显示过滤",
        WS_CHILD | WS_VISIBLE,
        300, 79, 66, 22, window, nullptr, instance, nullptr);
    g_app.displayFilterEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        370, 76, 800, 28, window, controlId(kIdDisplayFilter), instance, nullptr);
    g_app.applyFilterButton = CreateWindowExW(
        0, L"BUTTON", L"应用过滤",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        1175, 76, 82, 28, window, controlId(kIdApplyFilter), instance, nullptr);

    g_app.packetList = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
        300, 112, 960, 310, window, controlId(kIdPacketList), instance, nullptr);
    g_app.tabs = CreateWindowExW(
        0, WC_TABCONTROLW, nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        300, 414, 960, 300, window, controlId(kIdTabs), instance, nullptr);
    g_app.detailsTree = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_TREEVIEWW, nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASBUTTONS |
            TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        304, 446, 950, 250, window, controlId(kIdDetailsTree), instance, nullptr);
    g_app.hexEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", nullptr,
        WS_CHILD | WS_TABSTOP | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL,
        304, 446, 950, 250, window, controlId(kIdHex), instance, nullptr);
    g_app.statusLabel = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"STATIC", L"准备就绪",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        8, 700, 1250, 24, window, controlId(kIdStatus), instance, nullptr);

    TCITEMW tab{};
    tab.mask = TCIF_TEXT;
    tab.pszText = const_cast<wchar_t*>(L"协议详情");
    TabCtrl_InsertItem(g_app.tabs, 0, &tab);
    tab.pszText = const_cast<wchar_t*>(L"十六进制");
    TabCtrl_InsertItem(g_app.tabs, 1, &tab);

    SetWindowFont(g_app.adapterCombo, g_app.uiFont, TRUE);
    SetWindowFont(g_app.filterEdit, g_app.uiFont, TRUE);
    SetWindowFont(g_app.displayFilterEdit, g_app.uiFont, TRUE);
    SetWindowFont(g_app.applyFilterButton, g_app.uiFont, TRUE);
    SetWindowFont(g_app.refreshButton, g_app.uiFont, TRUE);
    SetWindowFont(g_app.openButton, g_app.uiFont, TRUE);
    SetWindowFont(g_app.clearButton, g_app.uiFont, TRUE);
    SetWindowFont(g_app.startButton, g_app.uiFont, TRUE);
    SetWindowFont(g_app.stopButton, g_app.uiFont, TRUE);
    for (int id = kIdPresetFirst; id <= kIdPresetLast; ++id)
        SetWindowFont(GetDlgItem(window, id), g_app.uiFont, TRUE);
    SetWindowFont(g_app.statsLabel, g_app.uiFont, TRUE);
    SetWindowFont(g_app.pcapPath, g_app.subtitleFont, TRUE);
    SetWindowFont(g_app.packetList, g_app.uiFont, TRUE);
    SetWindowFont(g_app.tabs, g_app.uiFont, TRUE);
    SetWindowFont(g_app.detailsTree, g_app.uiFont, TRUE);
    SetWindowFont(g_app.hexEdit, g_app.monoFont, TRUE);
    SetWindowFont(g_app.statusLabel, g_app.subtitleFont, TRUE);

    setupList();
    setActiveTab(0);
    populateAdapters();
    refreshStatistics();
}

COLORREF protocolColor(const std::string& protocol)
{
    if (protocol == "TCP")
        return RGB(23, 123, 91);
    if (protocol == "UDP")
        return RGB(126, 74, 176);
    if (protocol == "ARP")
        return RGB(180, 102, 25);
    if (protocol == "ICMP")
        return RGB(38, 102, 190);
    if (protocol == "IGMP")
        return RGB(163, 72, 128);
    return kTextColor;
}

LRESULT handleCustomDraw(LPARAM lParam)
{
    auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
    switch (draw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT: {
        LVITEMW item{};
        item.mask = LVIF_PARAM;
        item.iItem = static_cast<int>(draw->nmcd.dwItemSpec);
        ListView_GetItem(g_app.packetList, &item);
        const auto* record =
            reinterpret_cast<const PacketRecord*>(item.lParam);
        if (record)
            draw->clrText = protocolColor(record->parsed.protocol);
        if (draw->nmcd.uItemState & CDIS_SELECTED) {
            draw->clrTextBk = RGB(215, 229, 247);
            draw->clrText = RGB(20, 62, 112);
        } else {
            draw->clrTextBk =
                (draw->nmcd.dwItemSpec % 2 == 0)
                    ? RGB(255, 255, 255)
                    : RGB(248, 250, 253);
        }
        return CDRF_NEWFONT;
    }
    default:
        return CDRF_DODEFAULT;
    }
}

LRESULT CALLBACK windowProcedure(
    HWND window,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message) {
    case WM_CREATE:
        g_app.window = window;
        createControls(window);
        layoutControls(window);
        return 0;
    case WM_SIZE:
        layoutControls(window);
        return 0;
    case WM_ERASEBKGND: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        RECT client{};
        GetClientRect(window, &client);
        FillRect(dc, &client, g_app.backgroundBrush);
        RECT header{0, 0, client.right, 64};
        FillRect(dc, &header, g_app.headerBrush);
        return 1;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        HWND control = reinterpret_cast<HWND>(lParam);
        SetBkMode(dc, TRANSPARENT);
        if (control == g_app.title || control == g_app.subtitle) {
            SetTextColor(
                dc,
                control == g_app.title
                    ? RGB(255, 255, 255)
                    : RGB(173, 190, 215));
            return reinterpret_cast<LRESULT>(g_app.headerBrush);
        }
        if (control == g_app.state) {
            SetTextColor(
                dc,
                g_app.running.load()
                    ? RGB(83, 220, 151)
                    : RGB(164, 178, 198));
            return reinterpret_cast<LRESULT>(g_app.headerBrush);
        }
        SetTextColor(dc, kTextColor);
        return reinterpret_cast<LRESULT>(g_app.backgroundBrush);
    }
    case WM_CTLCOLORBTN:
        SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        SetTextColor(reinterpret_cast<HDC>(wParam), kTextColor);
        return reinterpret_cast<LRESULT>(g_app.backgroundBrush);
    case WM_GETMINMAXINFO:
        reinterpret_cast<MINMAXINFO*>(lParam)->ptMinTrackSize.x = 1080;
        reinterpret_cast<MINMAXINFO*>(lParam)->ptMinTrackSize.y = 680;
        return 0;
    case WM_COMMAND: {
        const int id = LOWORD(wParam);
        if (id == kIdRefresh && !g_app.running.load()) {
            populateAdapters();
            return 0;
        }
        if (id == kIdStart) {
            startCapture(window);
            return 0;
        }
        if (id == kIdStop) {
            stopCapture();
            setStatus(L"捕获已停止");
            return 0;
        }
        if (id == kIdClear) {
            resetPackets();
            setStatus(L"捕获结果已清空");
            return 0;
        }
        if (id == kIdOpenPcap) {
            openPcapFile(window);
            return 0;
        }
        if (id == kIdApplyFilter) {
            applyDisplayFilter();
            return 0;
        }
        if (id >= kIdPresetFirst && id <= kIdPresetLast) {
            const int index = id - kIdPresetFirst;
            SetWindowTextW(
                g_app.displayFilterEdit,
                kPresets[index].expression);
            applyDisplayFilter();
            SetFocus(g_app.displayFilterEdit);
            return 0;
        }
        break;
    }
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<NMHDR*>(lParam);
        if (header->idFrom == kIdPacketList) {
            if (header->code == LVN_ITEMCHANGED)
                updateSelection();
            else if (header->code == NM_CUSTOMDRAW)
                return handleCustomDraw(lParam);
        } else if (header->idFrom == kIdTabs &&
                   header->code == TCN_SELCHANGE) {
            setActiveTab(TabCtrl_GetCurSel(g_app.tabs));
            layoutControls(window);
        }
        break;
    }
    case kMessageStarted: {
        std::unique_ptr<std::wstring> path(
            reinterpret_cast<std::wstring*>(lParam));
        if (path)
            SetWindowTextW(
                g_app.pcapPath,
                (L"pcap: " + *path).c_str());
        setStatus(L"正在捕获数据包，点击“停止”结束");
        InvalidateRect(g_app.state, nullptr, TRUE);
        return 0;
    }
    case kMessageError: {
        std::unique_ptr<std::wstring> error(
            reinterpret_cast<std::wstring*>(lParam));
        g_app.running.store(false);
        setRunningUi(false);
        if (error)
            setStatus(*error);
        return 0;
    }
    case kMessagePacket: {
        std::unique_ptr<PacketRecord> record(
            reinterpret_cast<PacketRecord*>(lParam));
        if (!record)
            return 0;
        auto* raw = record.get();
        g_app.packets.push_back(std::move(record));
        countPacket(raw->parsed);
        if (packetMatchesDisplayFilter(*raw))
            addPacket(raw);
        refreshStatistics();
        setStatus(
            g_app.loadingOffline
                ? L"正在读取抓包文件"
                : L"正在捕获数据包");
        return 0;
    }
    case kMessageStopped: {
        std::unique_ptr<netobserver::CaptureStatistics> statistics(
            reinterpret_cast<netobserver::CaptureStatistics*>(lParam));
        g_app.running.store(false);
        setRunningUi(false);
        SetWindowTextW(
            g_app.statsLabel,
            statisticsText(
                true,
                statistics ? *statistics : netobserver::CaptureStatistics{}).c_str());
        setStatus(L"捕获已停止");
        return 0;
    }
    case kMessageOfflineLoaded:
        g_app.running.store(false);
        g_app.loadingOffline = false;
        setRunningUi(false);
        setStatus(
            L"抓包文件加载完成，共 " +
            std::to_wstring(g_app.totalPackets) +
            L" 个数据包");
        return 0;
    case WM_CLOSE:
        stopCapture();
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        if (g_app.titleFont)
            DeleteObject(g_app.titleFont);
        if (g_app.subtitleFont)
            DeleteObject(g_app.subtitleFont);
        if (g_app.uiFont)
            DeleteObject(g_app.uiFont);
        if (g_app.monoFont)
            DeleteObject(g_app.monoFont);
        if (g_app.backgroundBrush)
            DeleteObject(g_app.backgroundBrush);
        if (g_app.headerBrush)
            DeleteObject(g_app.headerBrush);
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand)
{
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    INITCOMMONCONTROLSEX commonControls{};
    commonControls.dwSize = sizeof(commonControls);
    commonControls.dwICC =
        ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES |
        ICC_TREEVIEW_CLASSES;
    InitCommonControlsEx(&commonControls);

    g_app.backgroundBrush = CreateSolidBrush(kBackgroundColor);
    g_app.headerBrush = CreateSolidBrush(kHeaderColor);
    g_app.titleFont = CreateFontW(
        -30, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_app.subtitleFont = CreateFontW(
        -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
    g_app.uiFont = CreateFontW(
        -15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
    g_app.monoFont = CreateFontW(
        -15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH | FF_MODERN, L"Consolas");

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = windowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(kAppIcon));
    windowClass.hIconSm = windowClass.hIcon;
    windowClass.hbrBackground = g_app.backgroundBrush;
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass))
        return 1;

    HWND window = CreateWindowExW(
        0, kWindowClass, kWindowTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1320, 820,
        nullptr, nullptr, instance, nullptr);
    if (!window)
        return 1;
    ShowWindow(window, showCommand);
    UpdateWindow(window);

    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (arguments) {
        if (argumentCount > 1)
            beginLoadPcap(window, arguments[1]);
        LocalFree(arguments);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
