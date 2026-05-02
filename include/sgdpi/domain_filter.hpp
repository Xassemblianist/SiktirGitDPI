// Domain filter: decides whether a flow's hostname (TLS SNI / HTTP Host)
// should be subject to bypass strategies.
//
// Rule sources:
//   - exact match:   "youtube.com"
//   - suffix match:  "*.googlevideo.com"  (matches a.b.googlevideo.com but
//                                          not googlevideo.com itself, RFC-style)
//   - root suffix:   ".example.com"       (matches example.com AND any subdomain)
//   - blank lines and lines starting with '#' are ignored
//
// Modes:
//   - Off:        match everything (default - same as no filter)
//   - Allowlist:  match ONLY when hostname is in the list
//   - Blocklist:  match everything EXCEPT when hostname is in the list
//
// The data structure is read-mostly: it's built once at startup (or rebuilt
// on SIGHUP if we ever wire that up) and then queried from N worker threads.
// A vector of patterns plus an unordered_set for exact matches gives us
// good worst-case behavior without needing fancy data structures.

#pragma once

#include "sgdpi/common.hpp"

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace sgdpi {

enum class FilterMode : uint8_t {
    Off       = 0,
    Allowlist = 1,
    Blocklist = 2,
};

[[nodiscard]] FilterMode filter_mode_from_string(std::string_view s) noexcept;
[[nodiscard]] const char* filter_mode_name(FilterMode m) noexcept;

class DomainFilter {
public:
    DomainFilter() = default;

    // Replace the rule set. mode controls allowlist vs blocklist semantics.
    void set_mode(FilterMode m) noexcept { mode_ = m; }
    [[nodiscard]] FilterMode mode() const noexcept { return mode_; }

    // Add a pattern. Lower-cased internally. Wildcard rules:
    //   "host"          -> exact only
    //   "*.host"        -> any single-or-multi-label subdomain (NOT host itself)
    //   ".host"         -> "host" plus any subdomain
    void add_pattern(std::string_view pat);

    // Bulk load from a file (one pattern per line, '#' comments).
    bool load_file(const std::string& path);

    // Empty means no rules; query() will only respect the mode setting.
    [[nodiscard]] bool empty() const noexcept {
        return exact_.empty() && suffix_.empty() && root_suffix_.empty();
    }

    [[nodiscard]] size_t pattern_count() const noexcept {
        return exact_.size() + suffix_.size() + root_suffix_.size();
    }

    // Returns true iff a flow with this hostname should be subject to
    // bypass strategies.
    [[nodiscard]] bool should_apply(std::string_view hostname) const noexcept;

private:
    FilterMode                       mode_ = FilterMode::Off;
    std::unordered_set<std::string>  exact_;          // "youtube.com"
    std::vector<std::string>         suffix_;         // ".googlevideo.com" - matches subdomains only
    std::vector<std::string>         root_suffix_;    // ".example.com" - matches "example.com" AND subdomains
};

} // namespace sgdpi
