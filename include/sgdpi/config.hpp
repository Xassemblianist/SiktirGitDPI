// Runtime configuration: assembled from CLI args, optional preset file, and
// defaults. Engine reads from a single Config struct; nothing else inside
// the codebase needs to know about CLI parsing.

#pragma once

#include "sgdpi/common.hpp"
#include "sgdpi/domain_filter.hpp"
#include "sgdpi/log.hpp"
#include "sgdpi/strategy.hpp"

#include <string>
#include <vector>

namespace sgdpi {

struct Config {
    // Logging
    log::Level   log_level = log::Level::Info;
    std::string  log_file;                       // empty = stdout/stderr only

    // Engine
    int          worker_threads = 0;             // 0 = HW concurrency
    uint64_t     queue_length   = 4096;
    uint64_t     queue_size_mb  = 32;
    uint64_t     queue_time_ms  = 2000;
    int16_t      divert_priority = 0;
    bool         show_stats     = false;
    Millis       stats_interval{1000};

    // Filter / scope
    std::string  custom_filter;                  // overrides built-in if set
    std::vector<uint16_t> tcp_ports = {80, 443}; // built-in filter targets these
    bool         capture_ipv6 = false;           // adds an IPv6 filter clause

    // Strategy chain (order matters - first match wins)
    std::vector<std::string> strategies;

    // Strategy parameters
    StrategyParams  params;

    // Auto features
    bool         auto_tune = false;
    std::string  auto_tune_target;               // domain to test against
    bool         auto_ttl  = false;              // discover real fake-TTL
    std::string  auto_ttl_target;

    // Domain filter (allow/blocklist for which hosts get strategies applied)
    FilterMode   domain_mode = FilterMode::Off;
    std::string  domain_file;                    // path to a domain list

    // Per-flow state tracking (suppress redundant strategy work on long flows)
    bool         flow_tracking = true;
    Millis       flow_ttl{30'000};

    // DNS redirect (anti-hijack)
    bool         dns_redirect = false;
    std::string  dns_upstream = "1.1.1.1";

    // Inbound RST drop: silently drop ISP-injected TCP RST packets.
    // Turkish ISPs send fake RST/FIN after detecting a blocked SNI.
    bool         inbound_rst_drop = false;

    // ISP preset (loaded into the above before CLI overrides)
    std::string  preset;
};

// Load a key=value preset file from disk into `cfg`. Recognised keys:
//   strategies     - comma-separated list (overwrites)
//   tls_split_mode - midsni|presni|first|fixed
//   tls_split_fixed
//   fake_ttl       - integer or "auto"
//   fake_repeat
//   http_mangle_case, http_extra_space, http_split_url - true|false
//   ports          - comma-separated list
[[nodiscard]] bool load_preset_file(const std::string& path, Config& cfg);

// Parse argv into a Config. Throws Error on bad usage.
[[nodiscard]] Config parse_args(int argc, char** argv);

void print_usage(std::ostream& os);

// Build the WinDivert filter expression from cfg.
[[nodiscard]] std::string build_divert_filter(const Config& cfg);

} // namespace sgdpi
