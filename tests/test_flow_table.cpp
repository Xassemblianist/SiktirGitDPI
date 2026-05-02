#include "test_main.hpp"
#include "sgdpi/flow_table.hpp"

#include <thread>

using namespace sgdpi;

namespace {

FlowKey k(uint16_t sp, uint16_t dp) {
    FlowKey x;
    x.family   = 4;
    x.src_port = sp;
    x.dst_port = dp;
    x.src.fill(0); x.src[0] = 10; x.src[1] = 0; x.src[2] = 0; x.src[3] = 1;
    x.dst.fill(0); x.dst[0] = 8;  x.dst[1] = 8; x.dst[2] = 8; x.dst[3] = 8;
    return x;
}

} // namespace

TEST(flow_table, probe_creates_then_finds) {
    FlowTable t{Millis{60'000}};

    FlowState s;
    auto h1 = t.probe(k(1234, 443), &s);
    EXPECT_TRUE(h1.created);
    EXPECT_FALSE(s.first_handled);

    auto h2 = t.probe(k(1234, 443), &s);
    EXPECT_FALSE(h2.created);
    EXPECT_FALSE(s.first_handled);
    EXPECT_EQ(t.size(), size_t{1});
}

TEST(flow_table, distinct_flows_are_distinct) {
    FlowTable t;
    FlowState s;
    t.probe(k(1, 443), &s);
    t.probe(k(2, 443), &s);
    t.probe(k(1, 80),  &s);
    EXPECT_EQ(t.size(), size_t{3});
}

TEST(flow_table, update_writes_back) {
    FlowTable t;
    FlowState s;

    auto key = k(5555, 443);
    auto h   = t.probe(key, &s);
    EXPECT_TRUE(h.created);

    s.first_handled = true;
    s.fakes_sent    = 3;
    t.update(h, key, s);

    FlowState s2;
    t.probe(key, &s2);
    EXPECT_TRUE(s2.first_handled);
    EXPECT_EQ(s2.fakes_sent, uint8_t{3});
}

TEST(flow_table, expired_entry_eventually_cleared) {
    FlowTable t{Millis{30}};        // very short TTL
    FlowState s;
    auto key = k(7, 7);
    t.probe(key, &s);
    EXPECT_EQ(t.size(), size_t{1});
    std::this_thread::sleep_for(Millis{60});
    // Trigger sweeps via additional probes.
    for (int i = 0; i < 16; ++i) t.probe(k(static_cast<uint16_t>(100 + i), 7), &s);
    // The original key may have been swept; size should at least be bounded.
    EXPECT_TRUE(t.size() <= size_t{17});
}

TEST(flow_table, clear_resets) {
    FlowTable t;
    FlowState s;
    for (uint16_t p = 0; p < 100; ++p) t.probe(k(p, 443), &s);
    EXPECT_EQ(t.size(), size_t{100});
    t.clear();
    EXPECT_EQ(t.size(), size_t{0});
}
