#include "sgdpi/checksum.hpp"

namespace sgdpi::checksum {

namespace {

// Fold a 32-bit accumulator down to 16 bits with carry-around.
inline uint16_t fold(uint32_t sum) noexcept {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(sum);
}

inline uint32_t sum_words(const uint8_t* data, size_t len, uint32_t acc = 0) noexcept {
    while (len >= 2) {
        acc += (static_cast<uint32_t>(data[0]) << 8) | static_cast<uint32_t>(data[1]);
        data += 2;
        len  -= 2;
    }
    if (len) acc += static_cast<uint32_t>(data[0]) << 8;
    return acc;
}

} // namespace

uint16_t internet_checksum(const uint8_t* data, size_t len) noexcept {
    return static_cast<uint16_t>(~fold(sum_words(data, len)));
}

uint16_t ipv4_header(const uint8_t* iphdr, size_t iphdr_len) noexcept {
    // Caller is expected to have zeroed iphdr[10..11] (the checksum field)
    // before calling. We re-zero just to be safe and recompute.
    uint32_t acc = 0;
    for (size_t i = 0; i < iphdr_len; i += 2) {
        if (i == 10) continue;  // skip checksum field
        const uint16_t w = (static_cast<uint16_t>(iphdr[i]) << 8) |
                            static_cast<uint16_t>(iphdr[i + 1]);
        acc += w;
    }
    return static_cast<uint16_t>(~fold(acc));
}

uint16_t tcp_v4(const uint8_t* ip_src, const uint8_t* ip_dst,
                const uint8_t* tcp_segment, size_t segment_len) noexcept {
    // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcp_len(2)
    uint32_t acc = 0;
    acc = sum_words(ip_src, 4, acc);
    acc = sum_words(ip_dst, 4, acc);
    acc += 0x0006;                                          // proto = TCP
    acc += static_cast<uint16_t>(segment_len);              // length
    acc = sum_words(tcp_segment, segment_len, acc);
    return static_cast<uint16_t>(~fold(acc));
}

uint16_t udp_v4(const uint8_t* ip_src, const uint8_t* ip_dst,
                const uint8_t* udp_datagram, size_t datagram_len) noexcept {
    uint32_t acc = 0;
    acc = sum_words(ip_src, 4, acc);
    acc = sum_words(ip_dst, 4, acc);
    acc += 0x0011;                                          // proto = UDP
    acc += static_cast<uint16_t>(datagram_len);
    acc = sum_words(udp_datagram, datagram_len, acc);
    const uint16_t cksum = static_cast<uint16_t>(~fold(acc));
    // RFC 768: zero result is sent as 0xFFFF to differentiate from "no checksum".
    return cksum == 0 ? 0xFFFF : cksum;
}

} // namespace sgdpi::checksum
