# Changelog

## [0.2.8] - 2026-10-21

### Fixed

- Flush the final short packet batch when capture stops, preventing empty or
  incomplete packet lists after brief captures.
- Corrected DNS and HTTP display-filter presets to use display-filter syntax.
- Changed the HTTP display filter to match only packets successfully identified
  as HTTP application traffic.
- Added automated BPF syntax and preset-expression tests.

## [0.2.7] - 2026-10-21

### Fixed

- Correctly trims and consumes overlapped out-of-order TCP segments.
- Added global limits for retained stream and pending-segment memory.
- Added UTF-8 and system-ANSI text handling for Follow Stream.
- Propagate pcapng write and flush failures to the capture UI.
- Validate port, DNS ID, HTTP status and numeric filter ranges.
- Link the MSVC runtime statically for portable releases.
- Corrected outdated IPv6, reassembly and pcapng documentation.

## [0.2.6] - 2026-10-21

### Fixed

- Replaced the packet hexadecimal editor with Rich Edit.
- Eliminated long-text scroll repaint artifacts that required double-click or
  Select All to restore readable content.
- Raised the text limit for hex and stream views to 16 million characters.

## [0.2.5] - 2026-10-21

### Added

- Added a Full Stream action that renders all retained TCP payload bytes.
- Added an explicit distinction between compact binary preview and full content.

## [0.2.4] - 2026-10-21

### Fixed

- Follow Stream no longer dumps long encrypted or compressed data as character
  noise.
- Binary TCP payloads show a clear explanation and a fixed 32-byte hex preview.
- Follow Stream uses Rich Edit for stable long-text scrolling.

## [0.2.3] - 2026-10-21

### Fixed

- Switched live capture to non-blocking Npcap reads with a 5 ms stop poll.
- Reduced redundant UI statistics updates during packet batches.
- Improved Stop responsiveness when the selected interface is idle or busy.

## [0.2.2] - 2026-10-21

### Fixed

- Display filter presets now remain usable while capture is running.
- “Only this conversation” now works for ICMP, ICMPv6, ARP, and IGMP.
- Follow Stream renders compressed, encrypted, and binary payloads as a
  bounded hexadecimal preview instead of producing character noise.

## [0.2.1] - 2026-10-21

### Fixed

- Prevented high-rate packet batches from delaying the Stop button.
- Limited outstanding UI batches so capture cancellation remains responsive.

## [0.2.0] - 2026-10-21

### Added

- pcapng export with interface metadata and microsecond timestamps
- IPv6 base and extension-header parsing
- DNS question and answer extraction
- HTTP method, URI, Host, response code and content type fields
- TCP reassembly with out-of-order segment handling
- Conversation summaries and Follow Stream
- Live packet and throughput rates
- Batched UI packet delivery
- Bounded packet and memory storage
- Expanded display filter fields for IPv6, DNS and HTTP

## [0.1.0] - 2026-10-21

### Added

- Windows network adapter enumeration and selection
- Npcap capture with BPF filtering
- Ethernet, VLAN, IPv4, TCP, UDP, ARP, ICMP, and IGMP parsing
- Basic HTTP and FTP payload inspection
- Multithreaded GUI with packet list, protocol tree, hex view, and statistics
- Capture-time BPF filtering separated from post-capture display filtering
- Display filter expressions with logical operators and common protocol fields
- Open existing pcap and pcapng capture files
- Apply display filters to offline captures and startup file arguments
- Automatic pcap export
- DLT_NULL and DLT_LOOP support
- Protocol parser tests
- Windows CI workflow
