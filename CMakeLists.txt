cmake_minimum_required(VERSION 3.20)

project(NetObserver VERSION 0.2.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(NPCAP_ROOT "" CACHE PATH "Path to the Npcap SDK or WinPcap Developer's Pack")

if(NOT NPCAP_ROOT AND DEFINED ENV{NPCAP_SDK_DIR})
    set(NPCAP_ROOT "$ENV{NPCAP_SDK_DIR}")
endif()

set(_pcap_hints
    "${NPCAP_ROOT}"
    "${CMAKE_SOURCE_DIR}/third_party/npcap-sdk"
    "C:/Program Files/Npcap"
)

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS ${_pcap_hints}
    PATH_SUFFIXES Include include
)

find_library(WPCAP_LIBRARY
    NAMES wpcap
    HINTS ${_pcap_hints}
    PATH_SUFFIXES Lib/x64 Lib lib
)

find_library(PACKET_LIBRARY
    NAMES Packet packet
    HINTS ${_pcap_hints}
    PATH_SUFFIXES Lib/x64 Lib lib
)

if(NOT PCAP_INCLUDE_DIR OR NOT WPCAP_LIBRARY)
    message(FATAL_ERROR
        "Npcap SDK was not found. Install the Npcap SDK and configure "
        "-DNPCAP_ROOT=<sdk-root>, or place it in third_party/npcap-sdk."
    )
endif()

add_library(netobserver_core STATIC
    src/core/CaptureEngine.cpp
    src/core/DisplayFilter.cpp
    src/core/FlowTracker.cpp
    src/core/PacketParser.cpp
    src/core/PcapNgWriter.cpp
)

target_include_directories(netobserver_core
    PUBLIC
        "${CMAKE_SOURCE_DIR}/src"
        "${PCAP_INCLUDE_DIR}"
)

target_compile_definitions(netobserver_core
    PUBLIC
        NETOBSERVER_VERSION="${PROJECT_VERSION}"
        WPCAP
        HAVE_REMOTE
        _WINSOCK_DEPRECATED_NO_WARNINGS
        NOMINMAX
)

target_link_libraries(netobserver_core
    PUBLIC
        "${WPCAP_LIBRARY}"
        ws2_32
)

if(PACKET_LIBRARY)
    target_link_libraries(netobserver_core PUBLIC "${PACKET_LIBRARY}")
endif()

if(MSVC)
    target_compile_options(netobserver_core PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(netobserver_core PUBLIC /EHsc)
endif()

add_executable(netobserver-cli
    src/console_main.cpp
    resources/version.rc
)
target_link_libraries(netobserver-cli PRIVATE netobserver_core)

add_executable(NetObserver WIN32
    src/gui_main.cpp
    resources/version.rc
)
target_link_libraries(NetObserver PRIVATE netobserver_core comctl32 comdlg32 shell32)
target_compile_definitions(NetObserver PRIVATE UNICODE _UNICODE)

if(MSVC)
    target_compile_options(netobserver-cli PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(NetObserver PRIVATE /W4 /permissive- /utf-8)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(netobserver-tests
        tests/packet_parser_tests.cpp
    )
    target_link_libraries(netobserver-tests PRIVATE netobserver_core)
    add_test(NAME netobserver_parser_tests COMMAND netobserver-tests)

    add_executable(netobserver-filter-tests
        tests/display_filter_tests.cpp
    )
    target_link_libraries(netobserver-filter-tests PRIVATE netobserver_core)
    add_test(NAME netobserver_filter_tests COMMAND netobserver-filter-tests)

    add_executable(netobserver-offline-tests
        tests/offline_capture_tests.cpp
    )
    target_link_libraries(netobserver-offline-tests PRIVATE netobserver_core)
    add_test(NAME netobserver_offline_tests COMMAND netobserver-offline-tests)

    add_executable(netobserver-flow-tests
        tests/flow_tracker_tests.cpp
    )
    target_link_libraries(netobserver-flow-tests PRIVATE netobserver_core)
    add_test(NAME netobserver_flow_tests COMMAND netobserver-flow-tests)
endif()

