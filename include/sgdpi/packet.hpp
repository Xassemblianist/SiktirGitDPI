// Zero-copy view + mutable builder over an IPv4/IPv6 + TCP packet that
// WinDivert hands us.
//
// We intentionally do not pull in <winsock2.h> from this header to keep
// compile times sane and to make the parser unit-testable on non-Windows
// builds (the parser itself doesn't touch any Win32 API).

#pragma once

#include "sgdpi/common.hpp"

#include <array>
#include <optional>

namespace sgdpi {

// ---------------------------------------------------------------------------
// IP version detection
// ---------------------------------------------------------------------------
enum class IpVersion : uint8_t { Unknown = 0, V4 = 4, V6 = 6 };

[[nodiscard]] inline IpVersion detect_ip_version(const uint8_t* p, size_t n) noexcept {
    if (n < 1) return IpVersion::Unknown;
    const uint8_t v = p[0] >> 4;
    if (v == 4) return IpVersion::V4;
    if (v == 6) return IpVersion::V6;
    return IpVersion::Unknown;
}

// ---------------------------------------------------------------------------
// Mutable packet view. Holds a pointer + length into a buffer that someone
// else owns (almost always the WinDivert recv buffer).
//
// All lookups are bounds-checked; if a header is malformed valid() returns
// false and you must not touch the typed accessors.
// ---------------------------------------------------------------------------
class PacketView {
public:
    PacketView() noexcept = default;
    PacketView(uint8_t* data, size_t len) noexcept { reset(data, len); }

    void reset(uint8_t* data, size_t len) noexcept;

    [[nodiscard]] bool valid() const noexcept { return valid_; }
    [[nodiscard]] IpVersion ip_version() const noexcept { return ipver_; }

    [[nodiscard]] uint8_t*  data()  const noexcept { return data_; }
    [[nodiscard]] size_t    size()  const noexcept { return len_;  }

    // ---- IP layer --------------------------------------------------------
    [[nodiscard]] uint8_t* ip_header()      const noexcept { return data_; }
    [[nodiscard]] size_t   ip_header_len()  const noexcept { return ip_hdr_len_; }
    [[nodiscard]] uint8_t  ip_protocol()    const noexcept { return ip_proto_; }
    [[nodiscard]] uint8_t  ttl()            const noexcept;
    void                   set_ttl(uint8_t t) noexcept;

    [[nodiscard]] uint16_t ip_total_length() const noexcept;
    void                   set_ip_total_length(uint16_t n) noexcept;

    [[nodiscard]] uint16_t ip_identification() const noexcept;
    void                   set_ip_identification(uint16_t id) noexcept;

    // src/dst address copied out as 4 (v4) or 16 (v6) bytes in network order.
    void copy_src_addr(uint8_t* out) const noexcept;
    void copy_dst_addr(uint8_t* out) const noexcept;

    // ---- TCP / UDP layer -------------------------------------------------
    [[nodiscard]] bool      is_tcp()         const noexcept { return ip_proto_ == 6;  }
    [[nodiscard]] bool      is_udp()         const noexcept { return ip_proto_ == 17; }
    [[nodiscard]] uint8_t*  udp_header()     const noexcept { return is_udp() ? data_ + ip_hdr_len_ : nullptr; }
    [[nodiscard]] uint16_t  udp_src_port()   const noexcept;
    [[nodiscard]] uint16_t  udp_dst_port()   const noexcept;
    [[nodiscard]] uint8_t*  udp_payload()    const noexcept { return is_udp() ? data_ + ip_hdr_len_ + 8 : nullptr; }
    [[nodiscard]] size_t    udp_payload_size() const noexcept;
    void                    set_dst_addr_v4(const uint8_t bytes[4]) noexcept;
    void                    set_src_addr_v4(const uint8_t bytes[4]) noexcept;

    [[nodiscard]] uint8_t*  tcp_header()     const noexcept { return data_ + ip_hdr_len_; }
    [[nodiscard]] size_t    tcp_header_len() const noexcept { return tcp_hdr_len_; }
    [[nodiscard]] uint16_t  src_port()       const noexcept;
    [[nodiscard]] uint16_t  dst_port()       const noexcept;
    [[nodiscard]] uint32_t  seq()            const noexcept;
    [[nodiscard]] uint32_t  ack()            const noexcept;
    [[nodiscard]] uint8_t   tcp_flags()      const noexcept;
    [[nodiscard]] uint16_t  tcp_window()     const noexcept;
    void                    set_tcp_window(uint16_t w) noexcept;
    void                    set_seq(uint32_t s) noexcept;

    [[nodiscard]] uint8_t*  payload()        const noexcept { return data_ + ip_hdr_len_ + tcp_hdr_len_; }
    [[nodiscard]] size_t    payload_size()   const noexcept;
    [[nodiscard]] ByteView  payload_view()   const noexcept { return {payload(), payload_size()}; }

    // Convenience flag tests.
    [[nodiscard]] bool tcp_syn()  const noexcept { return tcp_flags() & 0x02; }
    [[nodiscard]] bool tcp_ack()  const noexcept { return tcp_flags() & 0x10; }
    [[nodiscard]] bool tcp_psh()  const noexcept { return tcp_flags() & 0x08; }
    [[nodiscard]] bool tcp_fin()  const noexcept { return tcp_flags() & 0x01; }
    [[nodiscard]] bool tcp_rst()  const noexcept { return tcp_flags() & 0x04; }
    [[nodiscard]] bool tcp_urg()  const noexcept { return tcp_flags() & 0x20; }

private:
    uint8_t*  data_ = nullptr;
    size_t    len_  = 0;
    IpVersion ipver_ = IpVersion::Unknown;
    uint8_t   ip_proto_ = 0;
    uint16_t  ip_hdr_len_ = 0;
    uint16_t  tcp_hdr_len_ = 0;
    bool      valid_ = false;
};

// ---------------------------------------------------------------------------
// PacketBuilder - owned buffer with helpers to splice payloads, append TCP
// options, and recompute checksums via the windivert helper at finalization
// time. We keep the build flow explicit so each strategy can do exactly what
// it needs without a sea of optional flags.
// ---------------------------------------------------------------------------
class PacketBuilder {
public:
    static constexpr size_t kMaxMtu = 1600; // larger than any reasonable Ethernet frame

    PacketBuilder() = default;

    // Initialize builder by *copying* an existing packet view. Subsequent
    // mutators operate on the owned copy.
    void from_view(const PacketView& src);

    [[nodiscard]] uint8_t*       data()       noexcept { return buf_.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return buf_.data(); }
    [[nodiscard]] size_t         size() const noexcept { return len_; }

    // Replace the TCP payload with [src, src+n). Buffer is resized as needed
    // and IP total-length is updated, but checksums are NOT recomputed - call
    // recompute_checksums() before sending.
    void replace_payload(const uint8_t* src, size_t n);

    // Truncate or extend the payload to exactly n bytes. New bytes are
    // zeroed.
    void resize_payload(size_t n);

    // Direct field accessors that mirror PacketView; mutators here update
    // the owned buffer.
    void set_ttl(uint8_t t);
    void set_seq(uint32_t s);
    void set_ack(uint32_t a);
    void set_tcp_flags(uint8_t f);
    void set_tcp_window(uint16_t w);
    void set_ip_identification(uint16_t id);

    // Append a TCP option (kind, len, data...) by growing the TCP header.
    // Useful for the MD5-fake-option strategy. NB: total TCP header length
    // must remain <= 60 bytes (data offset is 4 bits).
    void append_tcp_option(uint8_t kind, ByteView data);

    // Recompute IP and TCP checksums in place, plus the IP total length.
    // Returns false on malformed packet.
    bool recompute();

    // Re-parse the current contents into a PacketView (non-owning).
    [[nodiscard]] PacketView view() noexcept { return PacketView{buf_.data(), len_}; }

private:
    std::array<uint8_t, kMaxMtu> buf_{};
    size_t                       len_ = 0;
    uint16_t                     ip_hdr_len_  = 0;
    uint16_t                     tcp_hdr_len_ = 0;
    IpVersion                    ipver_       = IpVersion::Unknown;

    [[nodiscard]] uint8_t* ip_hdr()  noexcept { return buf_.data(); }
    [[nodiscard]] uint8_t* tcp_hdr() noexcept { return buf_.data() + ip_hdr_len_; }
    [[nodiscard]] uint8_t* payload() noexcept { return buf_.data() + ip_hdr_len_ + tcp_hdr_len_; }
    [[nodiscard]] size_t   payload_size() const noexcept { return len_ - ip_hdr_len_ - tcp_hdr_len_; }
};

} // namespace sgdpi
