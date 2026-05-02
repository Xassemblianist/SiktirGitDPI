#include "test_main.hpp"
#include "sgdpi/tls.hpp"

#include <string>
#include <vector>

using namespace sgdpi;

namespace {

// Build a synthetic TLS 1.2 ClientHello with a single SNI extension.
std::vector<uint8_t> build_hello(const std::string& hostname) {
    std::vector<uint8_t> body;

    // legacy_version + random
    body.insert(body.end(), {0x03, 0x03});
    for (int i = 0; i < 32; ++i) body.push_back(0x42);
    // session_id (empty)
    body.push_back(0x00);
    // cipher_suites: 1 suite
    body.insert(body.end(), {0x00, 0x02, 0x00, 0x9C});
    // compression_methods: null
    body.insert(body.end(), {0x01, 0x00});

    // extensions
    std::vector<uint8_t> exts;
    // SNI: type=0x0000
    {
        std::vector<uint8_t> ext;
        const uint16_t hl = static_cast<uint16_t>(hostname.size());
        ext.insert(ext.end(), {0x00, 0x00, 0x00, 0x00}); // type + len placeholder
        // server_name_list:
        ext.insert(ext.end(), {0x00, 0x00});             // list len placeholder
        ext.push_back(0x00);                              // host_name
        ext.push_back(static_cast<uint8_t>(hl >> 8));
        ext.push_back(static_cast<uint8_t>(hl));
        ext.insert(ext.end(), hostname.begin(), hostname.end());
        const uint16_t list_len = static_cast<uint16_t>(ext.size() - 6);
        ext[4] = static_cast<uint8_t>(list_len >> 8);
        ext[5] = static_cast<uint8_t>(list_len);
        const uint16_t ext_len = static_cast<uint16_t>(list_len + 2);
        ext[2] = static_cast<uint8_t>(ext_len >> 8);
        ext[3] = static_cast<uint8_t>(ext_len);
        exts.insert(exts.end(), ext.begin(), ext.end());
    }
    body.push_back(static_cast<uint8_t>(exts.size() >> 8));
    body.push_back(static_cast<uint8_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    // Wrap in handshake header
    std::vector<uint8_t> hs;
    hs.push_back(0x01);
    hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    hs.push_back(static_cast<uint8_t>((body.size() >>  8) & 0xFF));
    hs.push_back(static_cast<uint8_t>( body.size()        & 0xFF));
    hs.insert(hs.end(), body.begin(), body.end());

    // Wrap in TLS record
    std::vector<uint8_t> rec;
    rec.insert(rec.end(), {0x16, 0x03, 0x01});
    rec.push_back(static_cast<uint8_t>((hs.size() >> 8) & 0xFF));
    rec.push_back(static_cast<uint8_t>( hs.size()       & 0xFF));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

} // namespace

TEST(tls, sniffs_handshake) {
    auto h = build_hello("example.com");
    EXPECT_TRUE(tls::looks_like_tls_handshake(ByteView{h.data(), h.size()}));

    uint8_t junk[] = {0x17, 0x03, 0x03, 0x00, 0x10};
    EXPECT_FALSE(tls::looks_like_tls_handshake(ByteView{junk, sizeof(junk)}));
}

TEST(tls, parses_simple_clienthello) {
    auto h = build_hello("youtube.com");
    auto info = tls::parse_client_hello(ByteView{h.data(), h.size()});
    EXPECT_TRUE(info.present);
    EXPECT_EQ(info.sni_hostname_len, size_t{11});
    EXPECT_EQ(std::string(info.hostname), std::string("youtube.com"));
    // hostname bytes must really be at the reported offset.
    for (size_t i = 0; i < info.sni_hostname_len; ++i) {
        EXPECT_EQ(h[info.sni_hostname_off + i],
                  static_cast<uint8_t>("youtube.com"[i]));
    }
}

TEST(tls, parses_unicode_punycode_host) {
    auto h = build_hello("xn--fiqs8s.example");  // punycode for chinese
    auto info = tls::parse_client_hello(ByteView{h.data(), h.size()});
    EXPECT_TRUE(info.present);
    EXPECT_EQ(std::string(info.hostname), std::string("xn--fiqs8s.example"));
}

TEST(tls, rejects_truncated_record) {
    auto h = build_hello("foo.bar");
    h.resize(10); // chop record body
    auto info = tls::parse_client_hello(ByteView{h.data(), h.size()});
    EXPECT_FALSE(info.present);
}

TEST(tls, rejects_non_handshake_content) {
    // ApplicationData record (type 0x17), not handshake.
    uint8_t app[] = {0x17, 0x03, 0x03, 0x00, 0x05, 1,2,3,4,5};
    auto info = tls::parse_client_hello(ByteView{app, sizeof(app)});
    EXPECT_FALSE(info.present);
}

TEST(tls, choose_split_offset_midsni) {
    auto h = build_hello("example.com");
    auto info = tls::parse_client_hello(ByteView{h.data(), h.size()});
    const size_t off = tls::choose_split_offset(info, "midsni", 0);
    EXPECT_EQ(off, info.sni_hostname_off + info.sni_hostname_len / 2);
}

TEST(tls, choose_split_offset_presni) {
    auto h = build_hello("example.com");
    auto info = tls::parse_client_hello(ByteView{h.data(), h.size()});
    const size_t off = tls::choose_split_offset(info, "presni", 0);
    EXPECT_EQ(off, info.sni_hostname_off);
}

TEST(tls, choose_split_offset_first) {
    auto h = build_hello("example.com");
    auto info = tls::parse_client_hello(ByteView{h.data(), h.size()});
    const size_t off = tls::choose_split_offset(info, "first", 0);
    EXPECT_EQ(off, size_t{1});
}

TEST(tls, choose_split_offset_fixed) {
    auto h = build_hello("example.com");
    auto info = tls::parse_client_hello(ByteView{h.data(), h.size()});
    const size_t off = tls::choose_split_offset(info, "fixed", 42);
    EXPECT_EQ(off, size_t{42});
}
