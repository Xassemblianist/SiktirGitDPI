// TLS ClientHello / SNI parser.
//
// We only need enough of the TLS spec to *find* the SNI hostname (and decide
// where to split the TCP segment). We don't validate the rest.
//
// References:
//   RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), RFC 6066 (SNI extension)

#pragma once

#include "sgdpi/common.hpp"

#include <optional>
#include <string_view>

namespace sgdpi::tls {

struct ClientHelloInfo {
    bool             present       = false;   // looks like a TLS ClientHello
    uint16_t         record_version = 0;       // TLS record version (0x0301-0x0304)
    uint16_t         client_version = 0;       // version inside the ClientHello body

    // Offsets into the *TCP payload* of interesting fields. 0 means "unset".
    size_t           record_start  = 0;       // start of TLSPlaintext (== 0 in normal case)
    size_t           record_end    = 0;       // one past last byte of this TLS record
    size_t           sni_extension_off = 0;   // start of SNI extension header (type byte)
    size_t           sni_hostname_off  = 0;   // start of the hostname bytes
    size_t           sni_hostname_len  = 0;   // hostname length (excluding the length field itself)

    std::string_view hostname;                 // pointer into the original buffer; not owned
};

// Parse a TCP payload that *might* be a TLS ClientHello. Returns a structure
// where present=false if not a ClientHello. Safe to call on garbage.
[[nodiscard]] ClientHelloInfo parse_client_hello(ByteView tcp_payload) noexcept;

// Returns true if this looks like the start of a TLS handshake (record type
// 0x16) - cheap check used to short-circuit before full parse.
[[nodiscard]] inline bool looks_like_tls_handshake(ByteView v) noexcept {
    return v.size() >= 6 && v[0] == 0x16
        && v[1] == 0x03                       // major version always 3
        && v[5] == 0x01;                      // ClientHello handshake type
}

// Picks a "good" split offset (within the TCP payload) so that the TLS record
// is broken across two TCP segments such that the SNI hostname spans the
// boundary.  Returns 0 if no split should be applied.
//
// Strategy:
//   - If position == "midsni": split at hostname_off + hostname_len/2
//   - If position == "presni": split right before hostname_off
//   - If position == "first":  split after the first byte of payload
//   - If a fixed numeric offset is given, use that.
[[nodiscard]] size_t choose_split_offset(const ClientHelloInfo& info,
                                         std::string_view       mode,
                                         size_t                 fixed) noexcept;

} // namespace sgdpi::tls
