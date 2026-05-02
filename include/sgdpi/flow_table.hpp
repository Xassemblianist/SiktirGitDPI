// Per-flow state with TTL-based expiry.
//
// Used by the engine to remember which flows have already had their first
// "interesting" packet handled, so we don't re-apply expensive strategies
// (or re-issue fake decoys) on every subsequent segment of the same TCP
// connection.
//
// Implementation: striped lock + unordered_map. Expiry is lazy - on every
// lookup we sweep at most a handful of buckets for old entries. This keeps
// the data structure bounded even under churn without a dedicated cleanup
// thread.

#pragma once

#include "sgdpi/common.hpp"

#include <array>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace sgdpi {

// 5-tuple-ish flow key. Protocol is implicit (only used for TCP today).
struct FlowKey {
    std::array<uint8_t, 16> src{};   // big enough for IPv6
    std::array<uint8_t, 16> dst{};
    uint16_t                src_port = 0;
    uint16_t                dst_port = 0;
    uint8_t                 family   = 0;   // 4 = IPv4, 6 = IPv6

    bool operator==(const FlowKey& o) const noexcept {
        return src_port == o.src_port && dst_port == o.dst_port &&
               family   == o.family   &&
               std::memcmp(src.data(), o.src.data(), 16) == 0 &&
               std::memcmp(dst.data(), o.dst.data(), 16) == 0;
    }
};

struct FlowKeyHash {
    [[nodiscard]] size_t operator()(const FlowKey& k) const noexcept {
        // Reasonable mix - we don't need cryptographic strength.
        const uint64_t s0 = *reinterpret_cast<const uint64_t*>(k.src.data());
        const uint64_t s1 = *reinterpret_cast<const uint64_t*>(k.src.data() + 8);
        const uint64_t d0 = *reinterpret_cast<const uint64_t*>(k.dst.data());
        const uint64_t d1 = *reinterpret_cast<const uint64_t*>(k.dst.data() + 8);
        uint64_t h = 0xCBF29CE484222325ull;
        for (uint64_t v : { s0, s1, d0, d1,
                            (uint64_t(k.src_port) << 16) | uint64_t(k.dst_port) }) {
            h ^= v;
            h *= 0x100000001B3ull;
        }
        return static_cast<size_t>(h);
    }
};

struct FlowState {
    bool        first_handled  = false;     // first interesting packet seen and acted upon
    uint8_t     fakes_sent     = 0;         // how many fake decoys we've sent
    TimePoint   last_seen{};
};

class FlowTable {
public:
    explicit FlowTable(Millis ttl = Millis{30'000}) : ttl_(ttl) {}

    // Reassign TTL without destroying the table. (FlowTable is non-movable
    // because each stripe owns its own mutex.)
    void set_ttl(Millis ttl) noexcept { ttl_ = ttl; }
    [[nodiscard]] Millis ttl() const noexcept { return ttl_; }

    // Look up a flow, creating it if absent. Returns a copy of the state plus
    // a *handle* token (the bucket index) the caller can use to commit
    // updates back via update().
    struct Handle {
        size_t bucket = ~size_t{0};
        bool   created = false;
    };

    Handle probe(const FlowKey& key, FlowState* out_state);
    void   update(const Handle& h, const FlowKey& key, const FlowState& s);

    // For tests / observability.
    [[nodiscard]] size_t size() const noexcept;
    void   clear() noexcept;

private:
    static constexpr size_t kStripes = 32;
    struct Stripe {
        std::mutex                                                      mu;
        std::unordered_map<FlowKey, FlowState, FlowKeyHash>             map;
    };

    [[nodiscard]] size_t bucket_for(const FlowKey& k) const noexcept {
        return FlowKeyHash{}(k) % kStripes;
    }
    void sweep(Stripe& s, TimePoint now);

    mutable std::array<Stripe, kStripes> stripes_;
    Millis                                ttl_;
};

// Build a FlowKey from a parsed PacketView.
class PacketView;
[[nodiscard]] FlowKey flow_key_from(const PacketView& v) noexcept;

} // namespace sgdpi
