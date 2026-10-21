#include "core/DisplayFilter.h"

#include <iostream>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& message)
{
    if (condition)
        return;
    ++failures;
    std::cerr << "FAIL: " << message << "\n";
}

bool matches(
    const std::string& expression,
    const netobserver::ParsedPacket& packet)
{
    netobserver::DisplayFilter filter;
    std::string error;
    if (!filter.compile(expression, error)) {
        std::cerr << "Filter compile failed for '" << expression
                  << "': " << error << "\n";
        ++failures;
        return false;
    }
    return filter.matches(packet);
}

} // namespace

int main()
{
    netobserver::ParsedPacket http;
    http.protocol = "TCP";
    http.hasIpv4 = true;
    http.sourceIp = "192.168.1.10";
    http.destinationIp = "192.168.1.20";
    http.hasPorts = true;
    http.sourcePort = 50000;
    http.destinationPort = 8080;
    http.applicationProtocol = "HTTP";
    http.capturedLength = 180;

    netobserver::ParsedPacket dns;
    dns.protocol = "UDP";
    dns.hasIpv4 = true;
    dns.sourceIp = "192.168.1.10";
    dns.destinationIp = "8.8.8.8";
    dns.hasPorts = true;
    dns.sourcePort = 53000;
    dns.destinationPort = 53;
    dns.capturedLength = 92;

    netobserver::ParsedPacket arp;
    arp.protocol = "ARP";
    arp.sourceIp = "192.168.1.10";
    arp.destinationIp = "192.168.1.1";
    arp.capturedLength = 42;

    check(matches("http", http), "http protocol filter");
    check(!matches("http", dns), "http should reject DNS");
    check(matches("dns", dns), "dns protocol filter");
    check(
        matches(
            "tcp and ip.src == 192.168.1.10 and tcp.port == 8080",
            http),
        "combined field filter");
    check(
        matches("udp.port == 53 or icmp", dns),
        "logical OR filter");
    check(matches("not arp", http), "NOT filter");
    check(matches("frame.len > 100", http), "frame length filter");
    check(!matches("frame.len <= 100", http), "frame length rejection");
    check(
        matches("ip.addr == 8.8.8.8", dns),
        "source or destination address filter");
    check(
        matches("protocol == tcp", http),
        "protocol equality filter");

    netobserver::DisplayFilter invalid;
    std::string error;
    check(
        !invalid.compile("tcp and (udp or", error),
        "invalid expression should fail");
    check(!error.empty(), "invalid expression should return an error");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All display filter tests passed\n";
    return 0;
}
