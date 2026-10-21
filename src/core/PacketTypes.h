#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace netobserver {

struct ProtocolField {
    std::string name;
    std::string value;
};

struct ProtocolLayer {
    std::string name;
    std::vector<ProtocolField> fields;
};

struct ParsedPacket {
    std::uint64_t number = 0;
    std::int64_t timestampSeconds = 0;
    std::int64_t timestampMicroseconds = 0;
    std::uint32_t capturedLength = 0;
    std::uint32_t originalLength = 0;

    std::array<std::uint8_t, 6> destinationMac{};
    std::array<std::uint8_t, 6> sourceMac{};
    std::string destinationMacText;
    std::string sourceMacText;
    std::uint16_t etherType = 0;

    bool hasIpv4 = false;
    bool hasIpv6 = false;
    int ipVersion = 0;
    std::string sourceIp;
    std::string destinationIp;
    std::uint8_t ipProtocol = 0;
    std::uint8_t ttl = 0;
    std::string protocol;

    bool hasPorts = false;
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    std::uint32_t tcpSequence = 0;
    std::uint32_t tcpAcknowledgment = 0;
    std::uint8_t tcpFlags = 0;
    std::size_t transportPayloadOffset = 0;
    std::size_t transportPayloadLength = 0;

    std::uint16_t dnsTransactionId = 0;
    bool dnsResponse = false;
    std::uint8_t dnsResponseCode = 0;
    std::string dnsQueryName;
    std::string dnsAnswers;

    std::string httpMethod;
    std::string httpUri;
    std::string httpHost;
    int httpStatusCode = 0;
    std::string httpStatusText;
    std::string httpContentType;

    std::string applicationProtocol;
    std::string applicationSummary;
    std::string summary;
    std::string parseError;
    std::vector<ProtocolLayer> layers;
};

struct CaptureStatistics {
    std::uint32_t received = 0;
    std::uint32_t dropped = 0;
    std::uint32_t interfaceDropped = 0;
};

} // namespace netobserver

