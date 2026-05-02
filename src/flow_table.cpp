#include "sgdpi/flow_table.hpp"
#include "sgdpi/packet.hpp"

#include <algorithm>

namespace sgdpi {

FlowKey flow_key_from(const PacketView& v) noexcept {
    FlowKey k;
    if (!v.valid()) return k;
    k.family = (v.ip_version() == IpVersion::V6) ? 6 : 4;
    v.copy_src_addr(k.src.data());
    v.copy_dst_addr(k.dst.data());
    k.src_port = v.src_port();
    k.dst_port = v.dst_port();
    return k;
}

void FlowTable::sweep(Stripe& s, TimePoint now) {
    // Walk-and-prune. Bounded effort - we look at a few entries per call so
    // the cost is amortized constant across many probe()s.
    int budget = 8;
    for (auto it = s.map.begin(); it != s.map.end() && budget > 0; --budget) {
        if (now - it->second.last_seen > ttl_) {
            it = s.map.erase(it);
        } else {
            ++it;
        }
    }
}

FlowTable::Handle FlowTable::probe(const FlowKey& key, FlowState* out_state) {
    Handle h;
    h.bucket = bucket_for(key);
    Stripe& s = stripes_[h.bucket];
    const auto now = Clock::now();

    std::lock_guard<std::mutex> lk(s.mu);
    sweep(s, now);

    auto [it, inserted] = s.map.try_emplace(key, FlowState{});
    h.created = inserted;
    it->second.last_seen = now;
    if (out_state) *out_state = it->second;
    return h;
}

void FlowTable::update(const Handle& h, const FlowKey& key, const FlowState& s) {
    if (h.bucket >= kStripes) return;
    Stripe& st = stripes_[h.bucket];
    std::lock_guard<std::mutex> lk(st.mu);
    auto it = st.map.find(key);
    if (it == st.map.end()) {
        st.map.emplace(key, s);
    } else {
        it->second = s;
        it->second.last_seen = Clock::now();
    }
}

size_t FlowTable::size() const noexcept {
    size_t n = 0;
    for (auto& s : stripes_) {
        std::lock_guard<std::mutex> lk(s.mu);
        n += s.map.size();
    }
    return n;
}

void FlowTable::clear() noexcept {
    for (auto& s : stripes_) {
        std::lock_guard<std::mutex> lk(s.mu);
        s.map.clear();
    }
}

} // namespace sgdpi
