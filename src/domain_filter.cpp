#include "sgdpi/domain_filter.hpp"
#include "sgdpi/log.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

namespace sgdpi {

FilterMode filter_mode_from_string(std::string_view s) noexcept {
    if (iequals(s, "off"))       return FilterMode::Off;
    if (iequals(s, "allowlist") || iequals(s, "allow") ||
        iequals(s, "whitelist"))  return FilterMode::Allowlist;
    if (iequals(s, "blocklist") || iequals(s, "block") ||
        iequals(s, "blacklist"))  return FilterMode::Blocklist;
    return FilterMode::Off;
}

const char* filter_mode_name(FilterMode m) noexcept {
    switch (m) {
        case FilterMode::Off:       return "off";
        case FilterMode::Allowlist: return "allowlist";
        case FilterMode::Blocklist: return "blocklist";
    }
    return "?";
}

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Strip an optional ":port" trailer from the hostname (HTTP Host header
// values often carry one).
std::string_view strip_port(std::string_view s) noexcept {
    auto colon = s.rfind(':');
    if (colon == std::string_view::npos) return s;
    // IPv6 literals are bracketed; bare colon means port.
    return s.substr(0, colon);
}

// Returns true iff `host` ends with `.suffix`. `suffix` should NOT itself
// start with a dot - we add it implicitly to make the boundary explicit so
// "evil-google.com" doesn't match a suffix of "google.com".
bool dot_suffix_match(std::string_view host, std::string_view suffix) noexcept {
    if (host.size() <= suffix.size()) return false;
    if (host[host.size() - suffix.size() - 1] != '.') return false;
    return host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
}

} // namespace

void DomainFilter::add_pattern(std::string_view pat) {
    pat = trim(pat);
    if (pat.empty()) return;

    if (pat.size() >= 2 && pat[0] == '*' && pat[1] == '.') {
        // "*.host" - subdomains only
        suffix_.emplace_back(lower(pat.substr(2)));
    } else if (pat[0] == '.') {
        // ".host" - host + subdomains
        root_suffix_.emplace_back(lower(pat.substr(1)));
    } else {
        exact_.emplace(lower(pat));
    }
}

bool DomainFilter::load_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        SGDPI_LOG_WARN("domain-filter: cannot open ", path);
        return false;
    }
    int n = 0;
    std::string line;
    while (std::getline(f, line)) {
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        const auto t = trim(line);
        if (t.empty()) continue;
        add_pattern(t);
        ++n;
    }
    SGDPI_LOG_INFO("domain-filter: loaded ", n, " pattern(s) from ", path);
    return true;
}

bool DomainFilter::should_apply(std::string_view hostname) const noexcept {
    if (mode_ == FilterMode::Off) return true;

    const auto stripped = strip_port(hostname);
    const auto host     = lower(stripped);

    bool matched = false;
    if (exact_.find(host) != exact_.end()) {
        matched = true;
    } else {
        for (const auto& s : suffix_) {
            if (dot_suffix_match(host, s)) { matched = true; break; }
        }
        if (!matched) {
            for (const auto& s : root_suffix_) {
                if (host == s) { matched = true; break; }
                if (dot_suffix_match(host, s)) { matched = true; break; }
            }
        }
    }

    return mode_ == FilterMode::Allowlist ? matched : !matched;
}

} // namespace sgdpi
