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

std::vector<std::uint8_t> makeDnsQueryPayload()
{
    std::vector<std::uint8_t> dns;
    append16(dns, 0x1234);
    append16(dns, 0x0100);
    append16(dns, 1);
    append16(dns, 0);
    append16(dns, 0);
    append16(dns, 0);
    dns.insert(dns.end(), {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm',
                           'p', 'l', 'e', 3, 'c', 'o', 'm', 0});
    append16(dns, 1);
    append16(dns, 1);
    return dns;
}

std::vector<std::uint8_t> makeIpv6DnsPacket()
{
    const auto dns = makeDnsQueryPayload();
    std::vector<std::uint8_t> packet;
    appendEthernetHeader(packet, 0x86DD);
    packet.push_back(0x60);
    packet.push_back(0);
    packet.push_back(0);
    packet.push_back(0);
    append16(packet, static_cast<std::uint16_t>(8 + dns.size()));
    packet.push_back(17);
    packet.push_back(64);
    packet.insert(packet.end(), {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 1});
    packet.insert(packet.end(), {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 2});
    append16(packet, 53000);
    append16(packet, 53);
    append16(packet, static_cast<std::uint16_t>(8 + dns.size()));
    append16(packet, 0);
    packet.insert(packet.end(), dns.begin(), dns.end());
    return packet;
}

std::vector<std::uint8_t> makeHttpResponsePacket()
{
    const std::string http =
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n";
    std::vector<std::uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIpv4Header(packet, 6, 20 + http.size());
    append16(packet, 80);
    append16(packet, 50000);
    append32(packet, 2000);
    append32(packet, 1001);
    packet.push_back(0x50);
    packet.push_back(0x18);
    append16(packet, 8192);
    append16(packet, 0);
    append16(packet, 0);
    packet.insert(packet.end(), http.begin(), http.end());
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
    check(parsedHttp.httpMethod == "GET", "HTTP method mismatch");
    check(parsedHttp.httpUri == "/index.html", "HTTP URI mismatch");
    check(parsedHttp.httpHost == "lab.local", "HTTP host mismatch");

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

    const auto ipv6Dns = makeIpv6DnsPacket();
    const auto parsedIpv6Dns = netobserver::PacketParser::parseEthernet(
        ipv6Dns.data(), ipv6Dns.size());
    check(parsedIpv6Dns.hasIpv6, "IPv6 flag mismatch");
    check(parsedIpv6Dns.sourceIp == "2001:db8::1", "IPv6 source mismatch");
    check(parsedIpv6Dns.destinationIp == "2001:db8::2", "IPv6 destination mismatch");
    check(parsedIpv6Dns.applicationProtocol == "DNS", "IPv6 DNS protocol mismatch");
    check(parsedIpv6Dns.dnsTransactionId == 0x1234, "DNS transaction ID mismatch");
    check(parsedIpv6Dns.dnsQueryName == "www.example.com", "DNS query mismatch");

    const auto httpResponse = makeHttpResponsePacket();
    const auto parsedResponse = netobserver::PacketParser::parseEthernet(
        httpResponse.data(), httpResponse.size());
    check(parsedResponse.httpStatusCode == 404, "HTTP response code mismatch");
    check(parsedResponse.httpContentType == "text/plain", "HTTP content type mismatch");

    const auto empty = netobserver::PacketParser::parseEthernet(nullptr, 0);
    check(!empty.parseError.empty(), "empty packet should return an error");

    const std::vector<std::uint8_t> truncatedEthernet = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00,
    };
    const auto truncated = netobserver::PacketParser::parseEthernet(
        truncatedEthernet.data(), truncatedEthernet.size());
    check(!truncated.parseError.empty(), "truncated IPv4 should return an error");

    std::vector<std::uint8_t> unknownEtherType;
    appendEthernetHeader(unknownEtherType, 0x88B5);
    unknownEtherType.insert(unknownEtherType.end(), 8, 0);
    const auto unknown = netobserver::PacketParser::parseEthernet(
        unknownEtherType.data(), unknownEtherType.size());
    check(
        unknown.protocol.find("88B5") != std::string::npos,
        "unknown EtherType should be preserved");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All packet parser tests passed\n";
    return 0;
}
