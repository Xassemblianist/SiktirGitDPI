#include "sgdpi/dns_redirect.hpp"
#include "sgdpi/log.hpp"
#include "sgdpi/packet.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <vector>

namespace sgdpi {

namespace {

// Lazy NAT eviction: stale entries get removed during occasional sweeps.
constexpr Millis kNatTtl{10'000};

bool parse_ipv4(const std::string& s, uint8_t out[4]) noexcept {
    IN_ADDR a{};
    if (::inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
    std::memcpy(out, &a.s_addr, 4);
    return true;
}

} // namespace

void DnsRedirect::start(const std::string& upstream_ipv4) {
    if (running_.exchange(true)) return;
    if (!parse_ipv4(upstream_ipv4, upstream_.data())) {
        running_ = false;
        throw Error("dns-redirect: invalid upstream IPv4 '" + upstream_ipv4 + "'");
    }

    // Capture both directions of UDP port 53 traffic. The "ip" clause keeps
    // us on IPv4 - we don't currently translate IPv6 DNS.
    const std::string filter =
        "ip and udp and ((outbound and udp.DstPort == 53) or "
        "                (inbound  and udp.SrcPort == 53))";
    divert_.open(filter, DivertLayer::Network, /*priority=*/1);
    divert_.set_queue_length(1024);
    divert_.set_queue_size  (4 * 1024 * 1024);
    divert_.set_queue_time_ms(1000);

    SGDPI_LOG_INFO("dns-redirect: upstream=", upstream_ipv4, " filter active");

    th_ = std::thread([this] { worker(); });
}

void DnsRedirect::stop() noexcept {
    if (!running_.exchange(false)) return;
    divert_.shutdown_recv();
    if (th_.joinable()) th_.join();
    divert_.close();
    std::lock_guard<std::mutex> lk(nat_mu_);
    nat_.clear();
}

size_t DnsRedirect::nat_size() const noexcept {
    std::lock_guard<std::mutex> lk(nat_mu_);
    return nat_.size();
}

void DnsRedirect::worker() {
    std::vector<uint8_t> buf(0x4000);
    while (running_.load()) {
        DivertAddr addr;
        uint32_t   rlen = 0, err = 0;
        if (!divert_.recv(buf.data(), static_cast<uint32_t>(buf.size()),
                          &rlen, &addr, &err)) {
            if (!running_.load()) return;
            continue;
        }
        bool ok = false;
        if (addr.is_outbound()) ok = handle_outbound(buf.data(), rlen, addr);
        else                    ok = handle_inbound (buf.data(), rlen, addr);
        if (!ok) {
            // Pass through unchanged on parse / classify failure.
            divert_.send(buf.data(), rlen, addr);
        }
    }
}

bool DnsRedirect::handle_outbound(uint8_t* pkt, uint32_t len, DivertAddr& addr) {
    PacketView v(pkt, len);
    if (!v.valid() || !v.is_udp() || v.ip_version() != IpVersion::V4) return false;
    if (v.udp_payload_size() < 12) return false;        // need DNS header
    const uint16_t qid = rd_be16(v.udp_payload());
    const uint16_t cport = v.udp_src_port();

    // Save mapping client_port + qid -> original dst.
    std::array<uint8_t, 4> orig_dst{};
    v.copy_dst_addr(orig_dst.data());
    const auto now = Clock::now();
    {
        std::lock_guard<std::mutex> lk(nat_mu_);
        // Lazy sweep: evict expired entries. Walk a small budget.
        int budget = 8;
        for (auto it = nat_.begin(); it != nat_.end() && budget > 0; --budget) {
            if (now - it->second.created > kNatTtl) it = nat_.erase(it);
            else                                     ++it;
        }
        nat_[NatKey{cport, qid}] = NatEntry{orig_dst, now};
    }

    // Rewrite destination IP and recompute checksums.
    PacketBuilder b;
    b.from_view(v);
    b.view().set_dst_addr_v4(upstream_.data());
    if (!b.recompute()) return false;

    addr.clear_checksums();
    divert_.send(b.data(), static_cast<uint32_t>(b.size()), addr);
    queries_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool DnsRedirect::handle_inbound(uint8_t* pkt, uint32_t len, DivertAddr& addr) {
    PacketView v(pkt, len);
    if (!v.valid() || !v.is_udp() || v.ip_version() != IpVersion::V4) return false;
    if (v.udp_payload_size() < 12) return false;
    const uint16_t qid   = rd_be16(v.udp_payload());
    const uint16_t cport = v.udp_dst_port();   // client is now the destination

    // Confirm this came from our upstream; if not, leave alone.
    std::array<uint8_t, 4> src{};
    v.copy_src_addr(src.data());
    if (src != upstream_) return false;

    std::array<uint8_t, 4> original_dst{};
    {
        std::lock_guard<std::mutex> lk(nat_mu_);
        auto it = nat_.find(NatKey{cport, qid});
        if (it == nat_.end()) return false;
        original_dst = it->second.original_dst;
        nat_.erase(it);
    }

    // Rewrite the source IP back to whatever the client originally targeted.
    PacketBuilder b;
    b.from_view(v);
    b.view().set_src_addr_v4(original_dst.data());
    if (!b.recompute()) return false;

    addr.clear_checksums();
    divert_.send(b.data(), static_cast<uint32_t>(b.size()), addr);
    responses_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

} // namespace sgdpi
