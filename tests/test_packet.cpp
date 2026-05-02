#include "test_main.hpp"
#include "sgdpi/packet.hpp"

#include <cstring>
#include <vector>

using namespace sgdpi;

namespace {

// Build a synthetic IPv4+TCP packet with the given payload. Returns the
// fully-formed packet bytes (no checksums initially - caller may compute).
std::vector<uint8_t> make_ipv4_tcp(const std::vector<uint8_t>& payload,
                                   uint32_t seq = 0x12345678,
                                   uint16_t src_port = 12345,
                                   uint16_t dst_port = 443) {
    std::vector<uint8_t> p(20 + 20 + payload.size(), 0);

    // IPv4 header
    p[0]  = 0x45;                                  // version=4, ihl=5
    p[1]  = 0x00;                                  // dscp/ecn
    const uint16_t total = static_cast<uint16_t>(p.size());
    p[2]  = static_cast<uint8_t>(total >> 8);
    p[3]  = static_cast<uint8_t>(total);
    p[4]  = 0xAB; p[5] = 0xCD;                    // ID
    p[6]  = 0x40;                                  // DF
    p[7]  = 0x00;
    p[8]  = 64;                                    // TTL
    p[9]  = 6;                                     // proto = TCP
    // checksum left zero
    p[12] = 192; p[13] = 168; p[14] = 1; p[15] = 100;   // src
    p[16] =   1; p[17] =   1; p[18] = 1; p[19] =   1;   // dst

    // TCP header
    uint8_t* t = p.data() + 20;
    t[0] = static_cast<uint8_t>(src_port >> 8);
    t[1] = static_cast<uint8_t>(src_port);
    t[2] = static_cast<uint8_t>(dst_port >> 8);
    t[3] = static_cast<uint8_t>(dst_port);
    t[4] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    t[5] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    t[6] = static_cast<uint8_t>((seq >>  8) & 0xFF);
    t[7] = static_cast<uint8_t>( seq        & 0xFF);
    // ack=0
    t[12] = 0x50;                                  // doff=5
    t[13] = 0x18;                                  // PSH|ACK
    t[14] = 0xFF; t[15] = 0xFF;                    // window
    // checksum, urg = 0

    if (!payload.empty())
        std::memcpy(p.data() + 40, payload.data(), payload.size());
    return p;
}

} // namespace

TEST(packet, parses_ipv4_tcp) {
    auto p = make_ipv4_tcp({'h','e','l','l','o'});
    PacketView v(p.data(), p.size());
    EXPECT_TRUE(v.valid());
    EXPECT_EQ(static_cast<int>(v.ip_version()), 4);
    EXPECT_TRUE(v.is_tcp());
    EXPECT_EQ(v.ip_header_len(),  size_t{20});
    EXPECT_EQ(v.tcp_header_len(), size_t{20});
    EXPECT_EQ(v.payload_size(),   size_t{5});
    EXPECT_EQ(v.src_port(), uint16_t{12345});
    EXPECT_EQ(v.dst_port(), uint16_t{443});
    EXPECT_EQ(v.seq(),      uint32_t{0x12345678});
    EXPECT_EQ(v.ttl(),      uint8_t{64});
    EXPECT_TRUE(v.tcp_psh());
    EXPECT_TRUE(v.tcp_ack());
}

TEST(packet, rejects_bogus) {
    uint8_t junk[10] = {};
    PacketView v(junk, sizeof(junk));
    EXPECT_FALSE(v.valid());
}

TEST(packet, builder_roundtrip_recomputes_checksums) {
    auto p = make_ipv4_tcp({'A','B','C','D','E','F'});
    PacketView v(p.data(), p.size());

    PacketBuilder b;
    b.from_view(v);
    b.set_ttl(48);
    EXPECT_TRUE(b.recompute());

    PacketView v2 = b.view();
    EXPECT_TRUE(v2.valid());
    EXPECT_EQ(v2.ttl(),          uint8_t{48});
    EXPECT_EQ(v2.payload_size(), size_t{6});
    EXPECT_EQ(v2.seq(),          uint32_t{0x12345678});
}

TEST(packet, builder_replace_payload_resizes) {
    auto p = make_ipv4_tcp({'a','b','c'});
    PacketView v(p.data(), p.size());

    PacketBuilder b;
    b.from_view(v);

    const uint8_t fresh[10] = {1,2,3,4,5,6,7,8,9,10};
    b.replace_payload(fresh, sizeof(fresh));
    EXPECT_TRUE(b.recompute());

    PacketView v2 = b.view();
    EXPECT_EQ(v2.payload_size(), size_t{10});
    for (int i = 0; i < 10; ++i) EXPECT_EQ(v2.payload()[i], uint8_t(i + 1));

    // IP total length must reflect new size.
    EXPECT_EQ(v2.ip_total_length(), uint16_t{20 + 20 + 10});
}

TEST(packet, builder_split_payload_preserves_seq) {
    // Simulate how strategies do TCP splits: one "first half" with original
    // seq, one "second half" with seq advanced by the offset.
    auto p = make_ipv4_tcp({'1','2','3','4','5','6','7','8'});
    PacketView v(p.data(), p.size());

    PacketBuilder a, b2;
    a.from_view(v);
    a.replace_payload(v.payload(), 3);
    EXPECT_TRUE(a.recompute());

    b2.from_view(v);
    b2.set_seq(v.seq() + 3);
    b2.replace_payload(v.payload() + 3, v.payload_size() - 3);
    EXPECT_TRUE(b2.recompute());

    PacketView va = a.view();
    PacketView vb = b2.view();
    EXPECT_EQ(va.payload_size(), size_t{3});
    EXPECT_EQ(vb.payload_size(), size_t{5});
    EXPECT_EQ(va.seq(),          v.seq());
    EXPECT_EQ(vb.seq(),          v.seq() + 3);
}

TEST(packet, parses_ipv4_udp_dns_query) {
    // Synthetic IPv4 + UDP + 12-byte DNS header.
    std::vector<uint8_t> p(20 + 8 + 12, 0);
    p[0] = 0x45; const uint16_t total = static_cast<uint16_t>(p.size());
    p[2] = static_cast<uint8_t>(total >> 8); p[3] = static_cast<uint8_t>(total);
    p[8] = 64; p[9] = 17;                    // ttl, proto = UDP
    p[12]=192; p[13]=168; p[14]=1; p[15]=100;
    p[16]=  1; p[17]=  1; p[18]=1; p[19]=  1;
    // UDP header: src=12345, dst=53, len=20, checksum=0
    p[20]=0x30; p[21]=0x39; p[22]=0; p[23]=53; p[24]=0; p[25]=20;
    // DNS payload: id=0xABCD, rest zero
    p[28]=0xAB; p[29]=0xCD;

    PacketView v(p.data(), p.size());
    EXPECT_TRUE(v.valid());
    EXPECT_TRUE(v.is_udp());
    EXPECT_FALSE(v.is_tcp());
    EXPECT_EQ(v.udp_src_port(), uint16_t{12345});
    EXPECT_EQ(v.udp_dst_port(), uint16_t{53});
    EXPECT_EQ(v.udp_payload_size(), size_t{12});
    EXPECT_EQ(v.udp_payload()[0], uint8_t{0xAB});

    // Builder should recompute UDP checksum without crashing.
    PacketBuilder b;
    b.from_view(v);
    EXPECT_TRUE(b.recompute());

    PacketView v2 = b.view();
    // Dst-IP rewrite + checksum recompute.
    const uint8_t new_dst[4] = {1, 1, 1, 1};
    v2.set_dst_addr_v4(new_dst);
    b.recompute();
    EXPECT_TRUE(b.recompute());
}

TEST(packet, builder_appends_tcp_option) {
    auto p = make_ipv4_tcp({'x','y'});
    PacketView v(p.data(), p.size());

    PacketBuilder b;
    b.from_view(v);

    const uint8_t md5[16] = {};
    b.append_tcp_option(19, ByteView{md5, sizeof(md5)});
    EXPECT_TRUE(b.recompute());

    PacketView v2 = b.view();
    // 20 base + (2+16) option + 2 NOP padding = 40 bytes total. The data
    // offset field is in 32-bit words and must round up.
    EXPECT_EQ(v2.tcp_header_len(), size_t{40});
    EXPECT_EQ(v2.payload_size(),   size_t{2});
    EXPECT_EQ(v2.payload()[0], 'x');
    EXPECT_EQ(v2.payload()[1], 'y');
    // First option byte should be MD5 kind (19); last two bytes NOP (0x01).
    const uint8_t* opts = v2.tcp_header() + 20;
    EXPECT_EQ(opts[0],  uint8_t{19});
    EXPECT_EQ(opts[1],  uint8_t{18});      // option length stays the real length
    EXPECT_EQ(opts[18], uint8_t{0x01});
    EXPECT_EQ(opts[19], uint8_t{0x01});
}
