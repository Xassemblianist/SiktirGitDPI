cmake_minimum_required(VERSION 3.20)
project(sgdpi
    VERSION     0.2.0
    LANGUAGES   CXX
    DESCRIPTION "SiktirGitDPI - DPI bypass tool for Turkish ISPs"
)

# ---------------------------------------------------------------------------
# Build configuration
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

if(NOT WIN32)
    message(FATAL_ERROR "SiktirGitDPI is Windows-only (uses WinDivert kernel driver).")
endif()

# Force Unicode + recent Windows targeting (Win10+).
add_compile_definitions(
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00   # Windows 10
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8 /MP)
    add_compile_options($<$<CONFIG:Release>:/O2>)
    add_compile_options($<$<CONFIG:Release>:/GL>)
    add_link_options($<$<CONFIG:Release>:/LTCG>)
    # Static MSVC runtime so the binary runs without VC redist.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_options($<$<CONFIG:Release>:-O2>)
endif()

# ---------------------------------------------------------------------------
# WinDivert SDK
# ---------------------------------------------------------------------------
set(WINDIVERT_DIR "${CMAKE_SOURCE_DIR}/third_party/windivert"
    CACHE PATH "Path to WinDivert SDK directory")

if(NOT EXISTS "${WINDIVERT_DIR}/include/windivert.h")
    message(FATAL_ERROR
        "WinDivert SDK not found at ${WINDIVERT_DIR}.\n"
        "Run: powershell -ExecutionPolicy Bypass -File scripts/get-windivert.ps1")
endif()

# Architecture-specific lib + dll + sys.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WINDIVERT_LIB_DIR "${WINDIVERT_DIR}/x64")
    set(WINDIVERT_SYS     "${WINDIVERT_DIR}/x64/WinDivert64.sys")
else()
    set(WINDIVERT_LIB_DIR "${WINDIVERT_DIR}/x86")
    set(WINDIVERT_SYS     "${WINDIVERT_DIR}/x86/WinDivert32.sys")
endif()

add_library(windivert SHARED IMPORTED)
set_target_properties(windivert PROPERTIES
    IMPORTED_LOCATION             "${WINDIVERT_LIB_DIR}/WinDivert.dll"
    IMPORTED_IMPLIB               "${WINDIVERT_LIB_DIR}/WinDivert.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${WINDIVERT_DIR}/include"
)

# ---------------------------------------------------------------------------
# Source layout
# ---------------------------------------------------------------------------
set(SGDPI_SOURCES
    src/main.cpp
    src/log.cpp
    src/config.cpp
    src/divert.cpp
    src/packet.cpp
    src/checksum.cpp
    src/tls.cpp
    src/http.cpp
    src/strategy.cpp
    src/ttl_probe.cpp
    src/auto_tune.cpp
    src/stats.cpp
    src/engine.cpp
    src/domain_filter.cpp
    src/flow_table.cpp
    src/dns_redirect.cpp
)

set(SGDPI_HEADERS
    include/sgdpi/common.hpp
    include/sgdpi/log.hpp
    include/sgdpi/config.hpp
    include/sgdpi/divert.hpp
    include/sgdpi/packet.hpp
    include/sgdpi/checksum.hpp
    include/sgdpi/tls.hpp
    include/sgdpi/http.hpp
    include/sgdpi/strategy.hpp
    include/sgdpi/ttl_probe.hpp
    include/sgdpi/auto_tune.hpp
    include/sgdpi/stats.hpp
    include/sgdpi/engine.hpp
    include/sgdpi/domain_filter.hpp
    include/sgdpi/flow_table.hpp
    include/sgdpi/dns_redirect.hpp
)

add_executable(sgdpi ${SGDPI_SOURCES} ${SGDPI_HEADERS})
target_include_directories(sgdpi PRIVATE include)
target_link_libraries(sgdpi PRIVATE windivert ws2_32 iphlpapi)

# Embed app manifest requesting administrator privileges (required to load
# WinDivert kernel driver). MSVC's linker generates the UAC manifest from the
# /MANIFESTUAC flag and merges resources/sgdpi.manifest (which carries the
# Windows 10/11 supportedOS GUID) via /MANIFESTINPUT.
if(MSVC)
    set(_uac "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
    set(_min "/MANIFESTINPUT:\"${CMAKE_SOURCE_DIR}/resources/sgdpi.manifest\"")
    set_target_properties(sgdpi PROPERTIES
        LINK_FLAGS "${_uac} ${_min} /MANIFEST:EMBED")
endif()

# Copy WinDivert.dll and the .sys driver next to the .exe so it can be run
# straight from the build dir.
add_custom_command(TARGET sgdpi POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_LIB_DIR}/WinDivert.dll" $<TARGET_FILE_DIR:sgdpi>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_SYS}"                   $<TARGET_FILE_DIR:sgdpi>
    COMMENT "Copying WinDivert runtime"
)

# Optionally copy presets next to the binary.
add_custom_command(TARGET sgdpi POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/presets"
            "$<TARGET_FILE_DIR:sgdpi>/presets"
    COMMENT "Copying presets"
)

install(TARGETS sgdpi RUNTIME DESTINATION bin)
install(DIRECTORY presets/ DESTINATION bin/presets)
install(FILES "${WINDIVERT_LIB_DIR}/WinDivert.dll" "${WINDIVERT_SYS}"
        DESTINATION bin)

# ---------------------------------------------------------------------------
# Tests (no WinDivert dependency - exercises only the parsers + filters).
# ---------------------------------------------------------------------------
option(SGDPI_BUILD_TESTS "Build unit tests" ON)
if(SGDPI_BUILD_TESTS)
    enable_testing()
    add_executable(sgdpi_tests
        tests/runner.cpp
        tests/test_checksum.cpp
        tests/test_packet.cpp
        tests/test_tls.cpp
        tests/test_http.cpp
        tests/test_domain_filter.cpp
        tests/test_flow_table.cpp
        src/checksum.cpp
        src/packet.cpp
        src/tls.cpp
        src/http.cpp
        src/domain_filter.cpp
        src/flow_table.cpp
        src/log.cpp
    )
    target_include_directories(sgdpi_tests PRIVATE include tests)
    add_test(NAME unit COMMAND sgdpi_tests)
endif()
