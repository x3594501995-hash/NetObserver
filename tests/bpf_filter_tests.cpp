#ifndef WPCAP
#define WPCAP
#endif

#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif

#include <pcap.h>

#include <windows.h>

#include <iostream>
#include <string>

namespace {

bool compiles(pcap_t* handle, const std::string& expression)
{
    bpf_program program{};
    const int result = pcap_compile(
        handle,
        &program,
        expression.c_str(),
        1,
        0);
    if (result == 0)
        pcap_freecode(&program);
    return result == 0;
}

} // namespace

int main()
{
    HMODULE runtime = LoadLibraryW(L"wpcap.dll");
    if (!runtime) {
        std::cout << "SKIP: wpcap.dll is not available\n";
        return 77;
    }

    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) {
        std::cerr << "pcap_open_dead failed\n";
        return 1;
    }

    const std::string valid[] = {
        "icmp",
        "arp",
        "tcp",
        "udp",
        "udp port 53 or tcp port 53",
        "tcp port 8080",
        "host 10.122.60.186",
        "src host 10.122.60.186 and tcp",
        "ip proto 2",
    };
    for (const auto& expression : valid) {
        if (!compiles(handle, expression)) {
            std::cerr << "valid BPF expression failed: " << expression << "\n";
            pcap_close(handle);
            return 1;
        }
    }

    const std::string invalid[] = {
        "tcp port",
        "not_a_protocol",
        "tcp and (",
    };
    for (const auto& expression : invalid) {
        if (compiles(handle, expression)) {
            std::cerr << "invalid BPF expression compiled: " << expression << "\n";
            pcap_close(handle);
            return 1;
        }
    }

    pcap_close(handle);
    std::cout << "BPF filter tests passed\n";
    FreeLibrary(runtime);
    return 0;
}
