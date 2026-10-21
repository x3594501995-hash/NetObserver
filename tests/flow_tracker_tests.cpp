#include "core/FlowTracker.h"

#include <cstdint>
#include <iostream>
#include <string>

#include <windows.h>

namespace {

netobserver::ParsedPacket makeTcpPacket(
    const std::string& sourceIp,
    std::uint16_t sourcePort,
    const std::string& destinationIp,
    std::uint16_t destinationPort,
    std::uint32_t sequence)
{
    netobserver::ParsedPacket packet;
    packet.protocol = "TCP";
    packet.hasIpv4 = true;
    packet.ipVersion = 4;
    packet.sourceIp = sourceIp;
    packet.destinationIp = destinationIp;
    packet.hasPorts = true;
    packet.sourcePort = sourcePort;
    packet.destinationPort = destinationPort;
    packet.tcpSequence = sequence;
    packet.capturedLength = 60;
    packet.transportPayloadOffset = 0;
    return packet;
}

void add(
    netobserver::FlowTracker& tracker,
    netobserver::ParsedPacket packet,
    const std::string& payload)
{
    packet.transportPayloadLength = payload.size();
    tracker.addPacket(
        packet,
        reinterpret_cast<const std::uint8_t*>(payload.data()),
        payload.size());
}

} // namespace

int main()
{
    netobserver::FlowTracker tracker;
    const std::string clientIp = "192.168.1.10";
    const std::string serverIp = "192.168.1.20";

    add(tracker, makeTcpPacket(clientIp, 50000, serverIp, 80, 100), "Hello");
    add(tracker, makeTcpPacket(serverIp, 80, clientIp, 50000, 700), "ACK");
    add(tracker, makeTcpPacket(clientIp, 50000, serverIp, 80, 106), "World");
    add(tracker, makeTcpPacket(clientIp, 50000, serverIp, 80, 105), " ");
    add(tracker, makeTcpPacket(clientIp, 50000, serverIp, 80, 100), "Hello");

    const auto flows = tracker.statistics();
    if (flows.size() != 1) {
        std::cerr << "expected one flow\n";
        return 1;
    }
    if (flows[0].packetsAToB != 4 || flows[0].packetsBToA != 1) {
        std::cerr << "flow packet counts mismatch\n";
        return 1;
    }

    const std::string stream = tracker.followStream(flows[0].key);
    if (stream.find("Hello World") == std::string::npos ||
        stream.find("ACK") == std::string::npos) {
        std::cerr << "TCP reassembly mismatch:\n" << stream << "\n";
        return 1;
    }

    netobserver::FlowTracker overlapTracker;
    add(
        overlapTracker,
        makeTcpPacket(clientIp, 50002, serverIp, 80, 100),
        "Hello");
    add(
        overlapTracker,
        makeTcpPacket(clientIp, 50002, serverIp, 80, 110),
        "World");
    add(
        overlapTracker,
        makeTcpPacket(clientIp, 50002, serverIp, 80, 105),
        " fiveWor");
    const auto overlapFlows = overlapTracker.statistics();
    const std::string overlapStream =
        overlapTracker.followStream(overlapFlows[0].key);
    if (overlapStream.find("Hello fiveWorld") == std::string::npos) {
        std::cerr << "overlapping segment reassembly mismatch:\n"
                  << overlapStream << "\n";
        return 1;
    }

    netobserver::FlowTracker wrapTracker;
    add(
        wrapTracker,
        makeTcpPacket(clientIp, 50003, serverIp, 80, 0xFFFFFFFEU),
        "AB");
    add(
        wrapTracker,
        makeTcpPacket(clientIp, 50003, serverIp, 80, 0),
        "CD");
    const auto wrapFlows = wrapTracker.statistics();
    if (wrapTracker.followStream(wrapFlows[0].key).find("ABCD") ==
        std::string::npos) {
        std::cerr << "sequence wrap reassembly mismatch\n";
        return 1;
    }

    netobserver::FlowTracker utf8Tracker;
    add(
        utf8Tracker,
        makeTcpPacket(clientIp, 50004, serverIp, 80, 1),
        "\xE4\xBD\xA0\xE5\xA5\xBD");
    const auto utf8Flows = utf8Tracker.statistics();
    if (utf8Tracker.followStream(utf8Flows[0].key).find("你好") ==
        std::string::npos) {
        std::cerr << "UTF-8 stream rendering mismatch\n";
        return 1;
    }

    if (GetACP() == 936) {
        netobserver::FlowTracker gbkTracker;
        add(
            gbkTracker,
            makeTcpPacket(clientIp, 50005, serverIp, 80, 1),
            "\xC4\xE3\xBA\xC3");
        const auto gbkFlows = gbkTracker.statistics();
        if (gbkTracker.followStream(gbkFlows[0].key).find("你好") ==
            std::string::npos) {
            std::cerr << "GBK stream rendering mismatch\n";
            return 1;
        }
    }

    netobserver::FlowTracker encodedTracker;
    add(
        encodedTracker,
        makeTcpPacket(clientIp, 50001, serverIp, 80, 1000),
        "GET /compressed HTTP/1.1\r\nHost: lab.local\r\n\r\n");
    std::string compressed =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Encoding: gzip\r\n\r\n";
    compressed.append("\x1F\x8B\x08\x00\x01\x02\x03\x04", 8);
    add(
        encodedTracker,
        makeTcpPacket(serverIp, 80, clientIp, 50001, 3000),
        compressed);
    const auto encodedFlows = encodedTracker.statistics();
    const std::string encodedStream =
        encodedTracker.followStream(encodedFlows[0].key);
    const std::string fullEncodedStream =
        encodedTracker.followStream(encodedFlows[0].key, true);
    if (encodedStream.find("压缩或二进制内容") == std::string::npos ||
        encodedStream.find("1F 8B") == std::string::npos ||
        fullEncodedStream.size() <= encodedStream.size()) {
        std::cerr << "compressed stream rendering mismatch:\n"
                  << encodedStream << "\n";
        return 1;
    }

    std::cout << "Flow tracker tests passed\n";
    return 0;
}
