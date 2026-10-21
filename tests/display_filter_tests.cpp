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
    http.httpMethod = "GET";
    http.httpUri = "/index.html";
    http.httpHost = "lab.local";
    http.capturedLength = 180;

    netobserver::ParsedPacket dns;
    dns.protocol = "UDP";
    dns.hasIpv4 = true;
    dns.sourceIp = "192.168.1.10";
    dns.destinationIp = "8.8.8.8";
    dns.hasPorts = true;
    dns.sourcePort = 53000;
    dns.destinationPort = 53;
    dns.applicationProtocol = "DNS";
    dns.dnsTransactionId = 0x1234;
    dns.dnsQueryName = "www.example.com";
    dns.capturedLength = 92;

    netobserver::ParsedPacket arp;
    arp.protocol = "ARP";
    arp.sourceIp = "192.168.1.10";
    arp.destinationIp = "192.168.1.1";
    arp.capturedLength = 42;

    netobserver::ParsedPacket ipv6 = dns;
    ipv6.hasIpv4 = false;
    ipv6.hasIpv6 = true;
    ipv6.ipVersion = 6;
    ipv6.sourceIp = "2001:db8::1";
    ipv6.destinationIp = "2001:db8::2";

    netobserver::ParsedPacket response = http;
    response.httpMethod.clear();
    response.httpUri.clear();
    response.httpStatusCode = 404;
    response.httpContentType = "text/plain";

    netobserver::ParsedPacket tcpPort80 = http;
    tcpPort80.sourcePort = 50000;
    tcpPort80.destinationPort = 80;
    tcpPort80.applicationProtocol.clear();

    check(matches("http", http), "http protocol filter");
    check(!matches("http", dns), "http should reject DNS");
    check(
        !matches("http", tcpPort80),
        "http should reject an unidentified TCP packet on port 80");
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
    check(
        matches(
            "ipv6 and dns.qry.name == www.example.com and dns.id == 4660",
            ipv6),
        "IPv6 and DNS field filter");
    check(
        matches(
            "http.request.method == GET and http.host == lab.local",
            http),
        "HTTP request field filter");
    check(
        matches("http.response.code == 404", response),
        "HTTP response code filter");

    netobserver::DisplayFilter invalid;
    std::string error;
    for (const std::string& expression : {
             "icmp",
             "arp",
             "dns or udp.port == 53 or tcp.port == 53",
             "tcp",
             "http"}) {
        netobserver::DisplayFilter preset;
        check(
            preset.compile(expression, error),
            "preset expression should compile: " + expression + " / " + error);
    }
    check(
        !invalid.compile("tcp and (udp or", error),
        "invalid expression should fail");
    check(!error.empty(), "invalid expression should return an error");
    check(
        !invalid.compile("tcp.port == 65536", error),
        "out-of-range TCP port should fail");
    check(
        !invalid.compile("dns.id == -1", error),
        "negative DNS ID should fail");
    check(
        !invalid.compile("ip.src > 1", error),
        "ordering comparison on a text field should fail");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All display filter tests passed\n";
    return 0;
}
