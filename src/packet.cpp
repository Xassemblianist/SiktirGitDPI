#include "sgdpi/packet.hpp"
#include "sgdpi/checksum.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace sgdpi {

namespace {

constexpr uint8_t  kIpProtoTcp     = 6;
constexpr size_t   kIpv4MinHdr     = 20;
constexpr size_t   kIpv6FixedHdr   = 40;
constexpr size_t   kTcpMinHdr      = 20;

// Walk past IPv6 extension headers until we find the upper-layer protocol or
// run out of room. Returns the total header length (incl. 40-byte fixed
// header + extensions) and writes the upper-layer protocol number to *proto.
size_t parse_ipv6_chain(const uint8_t* p, size_t n, uint8_t* proto) noexcept {
    if (n < kIpv6FixedHdr) return 0;
    uint8_t  next = p[6];           // Next Header in fixed v6 header
    size_t   off  = kIpv6FixedHdr;
    for (int i = 0; i < 8; ++i) {   // bound the chain to avoid pathological loops
        switch (next) {
            case 0:    // Hop-by-hop
            case 43:   // Routing
            case 60:   // Destination options
            case 51: { // AH
                if (off + 8 > n) return 0;
                const size_t hlen = (next == 51)
                    ? (static_cast<size_t>(p[off + 1]) + 2) * 4
                    :  static_cast<size_t>(p[off + 1] + 1) * 8;
                if (off + hlen > n) return 0;
                next = p[off];
                off += hlen;
                continue;
            }
            case 44:   // Fragment - we don't try to bypass on fragmented v6
                return 0;
            default:
                *proto = next;
                return off;
        }
    }
    return 0;
}

} // namespace

// ---------------------------------------------------------------------------
// PacketView
// ---------------------------------------------------------------------------
void PacketView::reset(uint8_t* data, size_t len) noexcept {
    data_ = data;
    len_  = len;
    valid_ = false;
    ipver_ = detect_ip_version(data, len);

    if (ipver_ == IpVersion::V4) {
        if (len < kIpv4MinHdr) return;
        const uint8_t ihl = (data[0] & 0x0F) * 4;
        if (ihl < kIpv4MinHdr || ihl > len) return;
        ip_hdr_len_ = ihl;
        ip_proto_   = data[9];
    } else if (ipver_ == IpVersion::V6) {
        uint8_t      proto = 0;
        const size_t hl    = parse_ipv6_chain(data, len, &proto);
        if (hl == 0) return;
        ip_hdr_len_ = static_cast<uint16_t>(hl);
        ip_proto_   = proto;
    } else {
        return;
    }

    if (ip_proto_ != kIpProtoTcp) {
        // We still mark valid so callers can inspect e.g. ICMP TTL probes,
        // but tcp_* accessors will return zero / harmless values.
        valid_ = true;
        tcp_hdr_len_ = 0;
        return;
    }

    if (len < ip_hdr_len_ + kTcpMinHdr) return;
    const uint8_t  data_off = (data[ip_hdr_len_ + 12] >> 4) & 0x0F;
    const uint16_t thl      = data_off * 4;
    if (thl < kTcpMinHdr || ip_hdr_len_ + thl > len) return;
    tcp_hdr_len_ = thl;
    valid_       = true;
}

uint8_t PacketView::ttl() const noexcept {
    if (!valid_) return 0;
    return ipver_ == IpVersion::V4 ? data_[8] : data_[7];
}
void PacketView::set_ttl(uint8_t t) noexcept {
    if (!valid_) return;
    if (ipver_ == IpVersion::V4) data_[8] = t;
    else                          data_[7] = t;
}

uint16_t PacketView::ip_total_length() const noexcept {
    if (!valid_) return 0;
    if (ipver_ == IpVersion::V4) return rd_be16(data_ + 2);
    return static_cast<uint16_t>(rd_be16(data_ + 4) + kIpv6FixedHdr);
}
void PacketView::set_ip_total_length(uint16_t n) noexcept {
    if (!valid_) return;
    if (ipver_ == IpVersion::V4) {
        wr_be16(data_ + 2, n);
    } else {
        wr_be16(data_ + 4, static_cast<uint16_t>(n - kIpv6FixedHdr));
    }
}

uint16_t PacketView::ip_identification() const noexcept {
    if (!valid_ || ipver_ != IpVersion::V4) return 0;
    return rd_be16(data_ + 4);
}
void PacketView::set_ip_identification(uint16_t id) noexcept {
    if (!valid_ || ipver_ != IpVersion::V4) return;
    wr_be16(data_ + 4, id);
}

void PacketView::copy_src_addr(uint8_t* out) const noexcept {
    if (!valid_) return;
    if (ipver_ == IpVersion::V4) std::memcpy(out, data_ + 12, 4);
    else                          std::memcpy(out, data_ + 8,  16);
}
void PacketView::copy_dst_addr(uint8_t* out) const noexcept {
    if (!valid_) return;
    if (ipver_ == IpVersion::V4) std::memcpy(out, data_ + 16, 4);
    else                          std::memcpy(out, data_ + 24, 16);
}

uint16_t PacketView::src_port() const noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return 0;
    return rd_be16(tcp_header());
}
uint16_t PacketView::dst_port() const noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return 0;
    return rd_be16(tcp_header() + 2);
}
uint32_t PacketView::seq() const noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return 0;
    return rd_be32(tcp_header() + 4);
}
uint32_t PacketView::ack() const noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return 0;
    return rd_be32(tcp_header() + 8);
}
uint8_t PacketView::tcp_flags() const noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return 0;
    return tcp_header()[13];
}
uint16_t PacketView::tcp_window() const noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return 0;
    return rd_be16(tcp_header() + 14);
}
void PacketView::set_tcp_window(uint16_t w) noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return;
    wr_be16(tcp_header() + 14, w);
}
void PacketView::set_seq(uint32_t s) noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return;
    wr_be32(tcp_header() + 4, s);
}

size_t PacketView::payload_size() const noexcept {
    if (!is_tcp() || tcp_hdr_len_ == 0) return 0;
    const size_t total = ip_total_length();
    if (total < ip_hdr_len_ + tcp_hdr_len_) return 0;
    return total - ip_hdr_len_ - tcp_hdr_len_;
}

uint16_t PacketView::udp_src_port() const noexcept {
    if (!is_udp() || size_t{ip_hdr_len_} + 8u > len_) return 0;
    return rd_be16(data_ + ip_hdr_len_);
}
uint16_t PacketView::udp_dst_port() const noexcept {
    if (!is_udp() || size_t{ip_hdr_len_} + 8u > len_) return 0;
    return rd_be16(data_ + ip_hdr_len_ + 2);
}
size_t PacketView::udp_payload_size() const noexcept {
    if (!is_udp() || size_t{ip_hdr_len_} + 8u > len_) return 0;
    const uint16_t udp_len = rd_be16(data_ + ip_hdr_len_ + 4);
    if (udp_len < 8) return 0;
    const size_t total = ip_total_length();
    if (total < size_t{ip_hdr_len_} + udp_len) return 0;
    return udp_len - 8u;
}
void PacketView::set_dst_addr_v4(const uint8_t bytes[4]) noexcept {
    if (!valid_ || ipver_ != IpVersion::V4) return;
    std::memcpy(data_ + 16, bytes, 4);
}
void PacketView::set_src_addr_v4(const uint8_t bytes[4]) noexcept {
    if (!valid_ || ipver_ != IpVersion::V4) return;
    std::memcpy(data_ + 12, bytes, 4);
}

// ---------------------------------------------------------------------------
// PacketBuilder
// ---------------------------------------------------------------------------
void PacketBuilder::from_view(const PacketView& src) {
    assert(src.valid());
    len_         = std::min<size_t>(src.size(), buf_.size());
    std::memcpy(buf_.data(), src.data(), len_);
    ip_hdr_len_  = static_cast<uint16_t>(src.ip_header_len());
    tcp_hdr_len_ = static_cast<uint16_t>(src.tcp_header_len());
    ipver_       = src.ip_version();
}

void PacketBuilder::replace_payload(const uint8_t* src, size_t n) {
    const size_t total = ip_hdr_len_ + tcp_hdr_len_ + n;
    if (total > buf_.size()) return;
    std::memcpy(payload(), src, n);
    len_ = total;
    // Caller must call recompute() before send.
}

void PacketBuilder::resize_payload(size_t n) {
    const size_t total = ip_hdr_len_ + tcp_hdr_len_ + n;
    if (total > buf_.size()) return;
    if (n > payload_size()) {
        std::memset(payload() + payload_size(), 0, n - payload_size());
    }
    len_ = total;
}

void PacketBuilder::set_ttl(uint8_t t) {
    if (ipver_ == IpVersion::V4) ip_hdr()[8] = t;
    else                          ip_hdr()[7] = t;
}
void PacketBuilder::set_seq(uint32_t s) {
    wr_be32(tcp_hdr() + 4, s);
}
void PacketBuilder::set_ack(uint32_t a) {
    wr_be32(tcp_hdr() + 8, a);
}
void PacketBuilder::set_tcp_flags(uint8_t f) {
    tcp_hdr()[13] = f;
}
void PacketBuilder::set_tcp_window(uint16_t w) {
    wr_be16(tcp_hdr() + 14, w);
}
void PacketBuilder::set_ip_identification(uint16_t id) {
    if (ipver_ == IpVersion::V4) wr_be16(ip_hdr() + 4, id);
}

void PacketBuilder::append_tcp_option(uint8_t kind, ByteView data) {
    const size_t opt_len_raw = 2 + data.size();
    // The TCP data offset field is in 32-bit words, so the option region
    // must be a multiple of 4 bytes long. Pad with NOP options (kind=1).
    const size_t pad     = (4 - ((tcp_hdr_len_ + opt_len_raw) & 3u)) & 3u;
    const size_t opt_len = opt_len_raw + pad;
    if (tcp_hdr_len_ + opt_len > 60) return;            // 4-bit data offset limit
    if (len_ + opt_len > buf_.size()) return;

    // Make room: shift payload right by opt_len bytes.
    const size_t pl = payload_size();
    if (pl) {
        std::memmove(payload() + opt_len, payload(), pl);
    }
    uint8_t* opt = tcp_hdr() + tcp_hdr_len_;
    opt[0] = kind;
    opt[1] = static_cast<uint8_t>(opt_len_raw);
    if (!data.empty()) std::memcpy(opt + 2, data.data(), data.size());
    // NOP padding tail.
    for (size_t i = 0; i < pad; ++i) opt[opt_len_raw + i] = 0x01;

    tcp_hdr_len_ = static_cast<uint16_t>(tcp_hdr_len_ + opt_len);
    len_        += opt_len;

    // Update TCP data offset (top 4 bits of byte 12).
    const uint8_t doff = static_cast<uint8_t>(tcp_hdr_len_ / 4);
    tcp_hdr()[12] = static_cast<uint8_t>((doff << 4) | (tcp_hdr()[12] & 0x0F));
}

bool PacketBuilder::recompute() {
    if (ipver_ == IpVersion::Unknown) return false;

    // 1) Fix up IP total-length.
    if (ipver_ == IpVersion::V4) {
        wr_be16(ip_hdr() + 2, static_cast<uint16_t>(len_));
    } else {
        wr_be16(ip_hdr() + 4, static_cast<uint16_t>(len_ - kIpv6FixedHdr));
    }

    // 2) IPv4 header checksum (zero then compute).
    if (ipver_ == IpVersion::V4) {
        wr_be16(ip_hdr() + 10, 0);
        wr_be16(ip_hdr() + 10, checksum::ipv4_header(ip_hdr(), ip_hdr_len_));
    }

    // 3) Detect upper-layer protocol.
    const uint8_t proto =
        (ipver_ == IpVersion::V4) ? ip_hdr()[9]
                                  : ip_hdr()[6]; // simplification: first nxt-hdr only

    // 4) Transport checksum.
    if (proto == kIpProtoTcp && tcp_hdr_len_ > 0) {
        wr_be16(tcp_hdr() + 16, 0);
        if (ipver_ == IpVersion::V4) {
            const size_t   seg_len = len_ - ip_hdr_len_;
            const uint16_t cs      = checksum::tcp_v4(ip_hdr() + 12, ip_hdr() + 16,
                                                      tcp_hdr(), seg_len);
            wr_be16(tcp_hdr() + 16, cs);
        } else {
            // IPv6 TCP checksum: pseudo-header (src 16 + dst 16 + length 4 + zero 3 + nxt 1).
            uint32_t acc = 0;
            for (int i = 0; i < 16; i += 2) {
                acc += rd_be16(ip_hdr() + 8  + i);
                acc += rd_be16(ip_hdr() + 24 + i);
            }
            const uint32_t seg_len = static_cast<uint32_t>(len_ - ip_hdr_len_);
            acc += (seg_len >> 16) & 0xFFFF;
            acc += seg_len & 0xFFFF;
            acc += 0x0006;
            size_t i = 0;
            while (i + 1 < seg_len) {
                acc += rd_be16(tcp_hdr() + i);
                i += 2;
            }
            if (i < seg_len) acc += static_cast<uint32_t>(tcp_hdr()[i]) << 8;
            while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
            wr_be16(tcp_hdr() + 16, static_cast<uint16_t>(~acc));
        }
    } else if (proto == 17) {
        // UDP. Header is at ip_hdr_len_, length 8 + payload.
        uint8_t* udp = buf_.data() + ip_hdr_len_;
        const size_t udp_total = len_ - ip_hdr_len_;
        if (udp_total < 8) return false;
        wr_be16(udp + 4, static_cast<uint16_t>(udp_total));   // length field
        wr_be16(udp + 6, 0);                                  // zero checksum
        if (ipver_ == IpVersion::V4) {
            wr_be16(udp + 6, checksum::udp_v4(ip_hdr() + 12, ip_hdr() + 16,
                                              udp, udp_total));
        }
        // IPv6 UDP checksum is mandatory but we don't currently emit IPv6
        // synthetic packets. If needed, add the analog of the TCP IPv6 path.
    }
    return true;
}

} // namespace sgdpi
