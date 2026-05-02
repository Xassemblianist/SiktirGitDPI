// ICMP-based hop discovery used by auto-TTL.
//
// We send ICMP echo requests with increasing TTL until we either get a real
// echo reply (we reached the host) or run out of hops. Implemented via
// IcmpSendEcho2 from iphlpapi (so we don't have to fight with raw sockets +
// admin-only privileges - although we *are* admin, this is just simpler).

#pragma once

#include "sgdpi/common.hpp"

#include <optional>
#include <string>

namespace sgdpi::ttl {

struct ProbeResult {
    bool     ok            = false;
    int      hops_to_target = 0;     // 0 if never reached
    int      suggested_fake_ttl = 4; // computed as max(hops/2, 1)
    std::string target_ipv4;          // resolved address used for the probe
};

// Resolve `host` to its first IPv4 address and probe TTLs from 1..max_hops.
// Returns the result. Never throws - on failure, ok=false and the suggested
// fake TTL falls back to 4.
[[nodiscard]] ProbeResult discover(const std::string& host,
                                   int max_hops      = 30,
                                   int per_hop_timeout_ms = 1000) noexcept;

} // namespace sgdpi::ttl
