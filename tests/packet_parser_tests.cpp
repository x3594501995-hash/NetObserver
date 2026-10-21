#include "core/PacketParser.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const std::string& message)
{
    if (condition)
        return;
    ++failures;
    std::cerr << "FAIL: " << message << "\n";
}

void append16(std::vector<std::uint8_t>& output, std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append32(std::vector<std::uint8_t>& output, std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void appendEthernetHeader(
    std::vector<std::uint8_t>& packet,
    std::uint16_t etherType)
{
    const std::uint8_t destination[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const std::uint8_t source[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    packet.insert(packet.end(), destination, destination + 6);
    packet.insert(packet.end(), source, source + 6);
    append16(packet, etherType);
}

void appendIpv4Header(
    std::vector<std::uint8_t>& packet,
    std::uint8_t protocol,
    std::size_t payloadLength)
{
    const std::uint16_t totalLength =
        static_cast<std::uint16_t>(20 + payloadLength);
    packet.push_back(0x45);
    packet.push_back(0x00);
    append16(packet, totalLength);
    append16(packet, 0x1234);
    append16(packet, 0x4000);
    packet.push_back(64);
    packet.push_back(protocol);
    append16(packet, 0);
    packet.insert(packet.end(), {192, 168, 1, 10});
    packet.insert(packet.end(), {192, 168, 1, 20});
}

std::vector<std::uint8_t> makeHttpTcpPacket()
{
    const std::string http =
        "GET /index.html HTTP/1.1\r\nHost: lab.local\r\n\r\n";
    std::vector<std::uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIpv4Header(packet, 6, 20 + http.size());
    append16(packet, 49152);
    append16(packet, 80);
    append32(packet, 1000);
    append32(packet, 2000);
    packet.push_back(0x50);
    packet.push_back(0x18);
    append16(packet, 8192);
    append16(packet, 0);
    append16(packet, 0);
    packet.insert(packet.end(), http.begin(), http.end());
    return packet;
}

std::vector<std::uint8_t> makeUdpPacket()
{
    std::vector<std::uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIpv4Header(packet, 17, 8 + 4);
    append16(packet, 53000);
    append16(packet, 53);
    append16(packet, 12);
    append16(packet, 0);
    packet.insert(packet.end(), {'D', 'N', 'S', '?'});
    return packet;
}

std::vector<std::uint8_t> makeArpPacket()
{
    std::vector<std::uint8_t> packet;
    appendEthernetHeader(packet, 0x0806);
    append16(packet, 1);
    append16(packet, 0x0800);
    packet.push_back(6);
    packet.push_back(4);
    append16(packet, 1);
    packet.insert(packet.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB});
    packet.insert(packet.end(), {192, 168, 1, 10});
    packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    packet.insert(packet.end(), {192, 168, 1, 20});
    return packet;
}

std::vector<std::uint8_t> makeIpProtocolPacket(std::uint8_t protocol)
{
    std::vector<std::uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIpv4Header(packet, protocol, 8);
    if (protocol == 1)
        packet.insert(packet.end(), {8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01});
    else
        packet.insert(packet.end(), {0x16, 0, 0, 0, 224, 0, 0, 1});
    return packet;
}

} // namespace

int main()
{
    const auto http = makeHttpTcpPacket();
    const auto parsedHttp = netobserver::PacketParser::parseEthernet(
        http.data(), http.size(), static_cast<std::uint32_t>(http.size()));
    check(parsedHttp.parseError.empty(), "HTTP packet should parse");
    check(parsedHttp.protocol == "TCP", "HTTP protocol mismatch");
    check(parsedHttp.sourceIp == "192.168.1.10", "HTTP source IP mismatch");
    check(parsedHttp.destinationIp == "192.168.1.20", "HTTP destination IP mismatch");
    check(parsedHttp.sourcePort == 49152, "HTTP source port mismatch");
    check(parsedHttp.destinationPort == 80, "HTTP destination port mismatch");
    check(parsedHttp.applicationProtocol == "HTTP", "HTTP app protocol mismatch");
    check(
        parsedHttp.applicationSummary == "GET /index.html HTTP/1.1",
        "HTTP request line mismatch");

    std::vector<std::uint8_t> loopbackHttp = {2, 0, 0, 0};
    loopbackHttp.insert(loopbackHttp.end(), http.begin() + 14, http.end());
    const auto parsedLoopback = netobserver::PacketParser::parsePacket(
        loopbackHttp.data(),
        loopbackHttp.size(),
        static_cast<std::uint32_t>(loopbackHttp.size()),
        0);
    check(parsedLoopback.protocol == "TCP", "Loopback HTTP should be TCP");
    check(parsedLoopback.applicationProtocol == "HTTP", "Loopback HTTP mismatch");

    const auto udp = makeUdpPacket();
    const auto parsedUdp = netobserver::PacketParser::parseEthernet(
        udp.data(), udp.size());
    check(parsedUdp.protocol == "UDP", "UDP protocol mismatch");
    check(parsedUdp.sourcePort == 53000, "UDP source port mismatch");
    check(parsedUdp.destinationPort == 53, "UDP destination port mismatch");

    const auto arp = makeArpPacket();
    const auto parsedArp = netobserver::PacketParser::parseEthernet(
        arp.data(), arp.size());
    check(parsedArp.protocol == "ARP", "ARP protocol mismatch");
    check(
        parsedArp.summary == "Who has 192.168.1.20? Tell 192.168.1.10",
        "ARP request summary mismatch");

    const auto icmp = makeIpProtocolPacket(1);
    check(
        netobserver::PacketParser::parseEthernet(
            icmp.data(), icmp.size()).protocol == "ICMP",
        "ICMP protocol mismatch");

    const auto igmp = makeIpProtocolPacket(2);
    check(
        netobserver::PacketParser::parseEthernet(
            igmp.data(), igmp.size()).protocol == "IGMP",
        "IGMP protocol mismatch");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All packet parser tests passed\n";
    return 0;
}
