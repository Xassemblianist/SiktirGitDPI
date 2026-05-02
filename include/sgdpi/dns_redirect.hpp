// DNS redirect / NAT.
//
// Some Turkish ISPs (notably TT) hijack outbound port-53 traffic to inject
// "blocked site" responses. The simplest mitigation that doesn't require an
// embedded DoH client is to transparently route every DNS query to a
// trusted upstream resolver (default 1.1.1.1) and reverse the rewrite on
// the way back.
//
// Lifecycle:
//   DnsRedirect dnr;
//   dnr.start("1.1.1.1");      // takes its own divert handle
//   ...                          // runs in background
//   dnr.stop();                  // joins worker, closes handle
//
// The redirect module owns a single divert handle scoped to UDP/53 (both
// directions). It does NOT interfere with the main TCP engine.

#pragma once

#include "sgdpi/common.hpp"
#include "sgdpi/divert.hpp"

#include <array>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace sgdpi {

class DnsRedirect {
public:
    DnsRedirect() = default;
    ~DnsRedirect() { stop(); }

    DnsRedirect(const DnsRedirect&)            = delete;
    DnsRedirect& operator=(const DnsRedirect&) = delete;

    // Start with the chosen upstream resolver. Throws on divert open failure.
    void start(const std::string& upstream_ipv4 = "1.1.1.1");
    void stop() noexcept;

    // Read-only stats.
    [[nodiscard]] uint64_t queries_redirected() const noexcept { return queries_.load(); }
    [[nodiscard]] uint64_t responses_translated() const noexcept { return responses_.load(); }
    [[nodiscard]] size_t   nat_size() const noexcept;

private:
    void worker();
    bool handle_outbound(uint8_t* pkt, uint32_t len, DivertAddr& addr);
    bool handle_inbound (uint8_t* pkt, uint32_t len, DivertAddr& addr);

    struct NatKey {
        uint16_t client_port = 0;
        uint16_t query_id    = 0;
        bool operator==(const NatKey& o) const noexcept {
            return client_port == o.client_port && query_id == o.query_id;
        }
    };
    struct NatHash {
        size_t operator()(const NatKey& k) const noexcept {
            return (uint32_t(k.client_port) << 16) | k.query_id;
        }
    };
    struct NatEntry {
        std::array<uint8_t, 4> original_dst{};
        TimePoint              created{};
    };

    Divert                                                divert_;
    std::thread                                           th_;
    std::atomic<bool>                                     running_{false};
    std::array<uint8_t, 4>                                upstream_{};
    mutable std::mutex                                    nat_mu_;
    std::unordered_map<NatKey, NatEntry, NatHash>         nat_;
    std::atomic<uint64_t>                                 queries_{0};
    std::atomic<uint64_t>                                 responses_{0};
};

} // namespace sgdpi
