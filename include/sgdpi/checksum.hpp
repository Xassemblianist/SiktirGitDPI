// IP/TCP/UDP one's-complement checksum.
//
// We rely on WinDivertHelperCalcChecksums for the hot path, but having a
// portable implementation is useful for unit tests and for synthesizing
// packets that bypass the helper (e.g. fake checksums on decoy packets).

#pragma once

#include "sgdpi/common.hpp"

namespace sgdpi::checksum {

// Generic 16-bit one's complement sum. Returns the *complement*, ready to
// drop into a checksum field.
[[nodiscard]] uint16_t internet_checksum(const uint8_t* data, size_t len) noexcept;

// IPv4 header checksum (IHL bytes long).
[[nodiscard]] uint16_t ipv4_header(const uint8_t* iphdr, size_t iphdr_len) noexcept;

// TCP checksum over IPv4 + TCP segment.
//   ip_src/ip_dst: 4 bytes each, network order.
//   tcp_segment:   TCP header + payload, with the checksum field zeroed.
[[nodiscard]] uint16_t tcp_v4(const uint8_t* ip_src, const uint8_t* ip_dst,
                              const uint8_t* tcp_segment, size_t segment_len) noexcept;

// UDP checksum over IPv4 + UDP datagram.
[[nodiscard]] uint16_t udp_v4(const uint8_t* ip_src, const uint8_t* ip_dst,
                              const uint8_t* udp_datagram, size_t datagram_len) noexcept;

} // namespace sgdpi::checksum
