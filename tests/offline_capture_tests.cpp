#ifndef WPCAP
#define WPCAP
#endif

#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif

#include "core/CaptureEngine.h"
#include "core/PacketParser.h"
#include "core/PcapNgWriter.h"

#include <pcap.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> makePacket()
{
    return {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x1C,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        192, 168, 1, 10, 192, 168, 1, 20,
        0xCF, 0x08, 0x00, 0x35,
        0x00, 0x08, 0x00, 0x00,
    };
}

} // namespace

int main()
{
    const std::string fileName =
        "netobserver_offline_test_" +
        std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) +
        ".pcap";
    const auto path = std::filesystem::current_path() / fileName;
    const auto packet = makePacket();

    pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead) {
        std::cerr << "pcap_open_dead failed\n";
        return 1;
    }

    pcap_dumper_t* dumper =
        pcap_dump_open(dead, path.string().c_str());
    if (!dumper) {
        std::cerr << "pcap_dump_open failed\n";
        pcap_close(dead);
        return 1;
    }

    pcap_pkthdr header{};
    header.ts.tv_sec = 1777777777;
    header.ts.tv_usec = 123456;
    header.caplen = static_cast<bpf_u_int32>(packet.size());
    header.len = static_cast<bpf_u_int32>(packet.size());
    pcap_dump(
        reinterpret_cast<u_char*>(dumper),
        &header,
        packet.data());
    pcap_dump_close(dumper);
    pcap_close(dead);

    netobserver::CaptureEngine engine;
    std::string error;
    if (!engine.openOffline(path.string(), error)) {
        std::cerr << "openOffline failed: " << error << "\n";
        std::filesystem::remove(path);
        return 1;
    }

    std::vector<std::uint8_t> bytes;
    netobserver::ParsedPacket metadata;
    const auto result = engine.next(bytes, metadata, error);
    if (result != netobserver::CaptureResult::Packet || !engine.isOffline()) {
        std::cerr << "offline packet read failed: " << error << "\n";
        engine.close();
        std::filesystem::remove(path);
        return 1;
    }

    const auto parsed = netobserver::PacketParser::parsePacket(
        bytes.data(),
        bytes.size(),
        metadata.originalLength,
        engine.dataLinkType());
    if (parsed.protocol != "UDP" ||
        parsed.destinationPort != 53 ||
        parsed.sourceIp != "192.168.1.10") {
        std::cerr << "offline packet parse mismatch\n";
        engine.close();
        std::filesystem::remove(path);
        return 1;
    }

    if (engine.next(bytes, metadata, error) !=
        netobserver::CaptureResult::End) {
        std::cerr << "offline end-of-file not detected\n";
        engine.close();
        std::filesystem::remove(path);
        return 1;
    }

    engine.close();
    std::filesystem::remove(path);

    const auto pcapngPath =
        std::filesystem::current_path() /
        ("netobserver_offline_test_" +
         std::to_string(
             std::chrono::steady_clock::now().time_since_epoch().count()) +
         ".pcapng");
    netobserver::PcapNgWriter writer;
    if (!writer.open(pcapngPath.string(), DLT_EN10MB, 65535, error)) {
        std::cerr << "pcapng open failed: " << error << "\n";
        return 1;
    }
    if (!writer.writePacket(
            header.ts.tv_sec,
            header.ts.tv_usec,
            packet.data(),
            header.caplen,
            header.len)) {
        std::cerr << "pcapng packet write failed\n";
        return 1;
    }
    writer.close();

    netobserver::CaptureEngine pcapngEngine;
    if (!pcapngEngine.openOffline(pcapngPath.string(), error)) {
        std::cerr << "pcapng openOffline failed: " << error << "\n";
        std::filesystem::remove(pcapngPath);
        return 1;
    }
    bytes.clear();
    const auto pcapngResult =
        pcapngEngine.next(bytes, metadata, error);
    const auto parsedPcapng = netobserver::PacketParser::parsePacket(
        bytes.data(),
        bytes.size(),
        metadata.originalLength,
        pcapngEngine.dataLinkType());
    pcapngEngine.close();
    std::filesystem::remove(pcapngPath);
    if (pcapngResult != netobserver::CaptureResult::Packet ||
        parsedPcapng.destinationPort != 53) {
        std::cerr << "pcapng round-trip failed\n";
        return 1;
    }

    std::cout << "Offline capture test passed\n";
    return 0;
}
