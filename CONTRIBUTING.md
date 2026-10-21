# Contributing

## Development setup

1. Install Visual Studio 2022 Build Tools with the C++ workload.
2. Install Npcap.
3. Download the Npcap SDK and extract it to `third_party/npcap-sdk`.
4. Build and run tests:

```powershell
.\scripts\build-vs-cmake.cmd
```

## Pull requests

- Keep capture and parsing logic independent from Win32 UI code.
- Add parser tests for new protocols or malformed input.
- Avoid committing generated `build` files, Npcap SDK binaries, or pcap captures.
- Describe behavior changes and test results in the pull request.
- Use only traffic you are authorized to capture when testing.

