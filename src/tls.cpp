#include "sgdpi/tls.hpp"

namespace sgdpi::tls {

namespace {

constexpr uint8_t  kRecordHandshake     = 0x16;
constexpr uint8_t  kHandshakeClientHello = 0x01;
constexpr uint16_t kExtServerName       = 0x0000;
constexpr uint8_t  kHostNameType        = 0x00;

} // namespace

ClientHelloInfo parse_client_hello(ByteView v) noexcept {
    ClientHelloInfo out;
    if (v.size() < 5) return out;

    // ---- TLS record header --------------------------------------------------
    if (v[0] != kRecordHandshake) return out;
    out.record_version = rd_be16(v.data() + 1);
    if ((out.record_version >> 8) != 0x03) return out;
    const uint16_t rec_len = rd_be16(v.data() + 3);
    if (5u + rec_len > v.size()) return out;
    out.record_start = 0;
    out.record_end   = 5u + rec_len;

    // ---- Handshake header --------------------------------------------------
    size_t off = 5;
    if (off + 4 > v.size()) return out;
    if (v[off] != kHandshakeClientHello) return out;
    const uint32_t hs_len = rd_be24(v.data() + off + 1);
    off += 4;
    if (off + hs_len > v.size()) return out;
    const size_t hs_end = off + hs_len;

    // ---- ClientHello body --------------------------------------------------
    if (off + 2 + 32 > hs_end) return out;
    out.client_version = rd_be16(v.data() + off);
    off += 2 + 32;     // version + random

    // session_id<0..32>
    if (off + 1 > hs_end) return out;
    const uint8_t sid_len = v[off++];
    if (off + sid_len > hs_end) return out;
    off += sid_len;

    // cipher_suites<2..2^16-2>
    if (off + 2 > hs_end) return out;
    const uint16_t cs_len = rd_be16(v.data() + off); off += 2;
    if (off + cs_len > hs_end) return out;
    off += cs_len;

    // compression_methods<1..2^8-1>
    if (off + 1 > hs_end) return out;
    const uint8_t cm_len = v[off++];
    if (off + cm_len > hs_end) return out;
    off += cm_len;

    // extensions<0..2^16-1>
    if (off + 2 > hs_end) {
        // No extensions - not a ClientHello with SNI but still a valid hello.
        out.present = true;
        return out;
    }
    const uint16_t ext_total = rd_be16(v.data() + off); off += 2;
    if (off + ext_total > hs_end) return out;
    const size_t ext_end = off + ext_total;

    // Walk extensions, find SNI.
    while (off + 4 <= ext_end) {
        const uint16_t etype = rd_be16(v.data() + off);
        const uint16_t elen  = rd_be16(v.data() + off + 2);
        const size_t   ebody = off + 4;
        if (ebody + elen > ext_end) return out;

        if (etype == kExtServerName) {
            out.sni_extension_off = off;
            // server_name_list_length: 2 bytes
            if (elen < 2) return out;
            const uint16_t list_len = rd_be16(v.data() + ebody);
            if (list_len + 2u > elen) return out;
            // First entry: name_type(1) + host_name<2..>
            size_t p = ebody + 2;
            const size_t list_end = ebody + 2 + list_len;
            if (p + 3 > list_end) return out;
            const uint8_t name_type = v[p++];
            const uint16_t host_len  = rd_be16(v.data() + p); p += 2;
            if (name_type != kHostNameType) {
                // Skip and continue (multiple entries allowed though rare).
                out.present = true;
                break;
            }
            if (p + host_len > list_end) return out;
            out.sni_hostname_off = p;
            out.sni_hostname_len = host_len;
            out.hostname = std::string_view(
                reinterpret_cast<const char*>(v.data() + p), host_len);
            out.present = true;
            return out;
        }
        off = ebody + elen;
    }

    out.present = true;
    return out;
}

size_t choose_split_offset(const ClientHelloInfo& info,
                           std::string_view       mode,
                           size_t                 fixed) noexcept {
    if (!info.present) return 0;
    if (mode == "fixed") {
        return fixed;
    }
    if (mode == "first") {
        return 1;
    }
    if (info.sni_hostname_len == 0) {
        // No SNI - fall back to splitting at half the record.
        if (info.record_end > 8) return info.record_end / 2;
        return 0;
    }
    if (mode == "presni") {
        return info.sni_hostname_off;
    }
    // default: midsni
    return info.sni_hostname_off + info.sni_hostname_len / 2;
}

} // namespace sgdpi::tls
