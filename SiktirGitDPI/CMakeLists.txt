cmake_minimum_required(VERSION 3.20)
project(SGDPI_Enterprise VERSION 2.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
link_directories(lib)

add_executable(sgdpi
    src/main.cpp
    src/engine.cpp
    src/dns_handler.cpp
    src/tls_parser.cpp
    src/http_parser.cpp
    src/utils.cpp
)

target_link_libraries(sgdpi PRIVATE WinDivert)