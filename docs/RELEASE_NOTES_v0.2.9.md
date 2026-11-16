# NetObserver v0.2.9

NetObserver is a lightweight Windows network protocol analyzer built with
C++17, Win32, and the Npcap WinPcap-compatible API.

## Highlights

- Live adapter enumeration, promiscuous capture, and BPF capture filters
- Post-capture display filters for protocols, addresses, ports, DNS, and HTTP
- Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ARP, ICMP, IGMP, and DNS parsing
- HTTP request/response metadata
- pcap and pcapng reading, pcapng export
- TCP conversation tracking, out-of-order reassembly, and Follow Stream
- Bounded packet and stream memory usage
- Responsive stop handling with non-blocking Npcap reads

## Installation

1. Install Npcap with WinPcap API compatibility.
2. Download and extract `NetObserver-v0.2.9-win64.zip`.
3. Run `NetObserver.exe`.

The portable package statically links the Microsoft C++ runtime. Npcap is a
separate dependency and is not bundled.

## Known limitations

- IPv4 and IPv6 fragmentation are not fully reassembled.
- TLS and encrypted application protocols remain encrypted.
- TCP Follow Stream retains at most 1 MB per direction.
- Protocol coverage is intentionally smaller than Wireshark.

## License

MIT License. See `LICENSE`.
