#include "sgdpi/config.hpp"
#include "sgdpi/log.hpp"
#include "sgdpi/strategy.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace sgdpi {

namespace {

std::vector<std::string> split_csv(std::string_view s) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == ',') {
            std::string tok = trim(s.substr(start, i - start));
            if (!tok.empty()) out.push_back(std::move(tok));
            start = i + 1;
        }
    }
    return out;
}

bool parse_bool(std::string_view s) noexcept {
    return iequals(s, "true") || iequals(s, "yes") || s == "1" || iequals(s, "on");
}

void apply_kv(const std::string& key, const std::string& val, Config& cfg) {
    if (key == "strategies") {
        cfg.strategies = split_csv(val);
    } else if (key == "tls_split_mode") {
        cfg.params.tls_split_mode = val;
    } else if (key == "tls_split_fixed") {
        cfg.params.tls_split_fixed = std::stoul(val);
    } else if (key == "fake_ttl") {
        if (iequals(val, "auto")) cfg.params.fake_ttl = -1;
        else                       cfg.params.fake_ttl = std::stoi(val);
    } else if (key == "fake_repeat") {
        cfg.params.fake_repeat = std::stoi(val);
    } else if (key == "http_mangle_case") {
        cfg.params.http_mangle_case = parse_bool(val);
    } else if (key == "http_extra_space") {
        cfg.params.http_extra_space = parse_bool(val);
    } else if (key == "http_split_url") {
        cfg.params.http_split_url = parse_bool(val);
    } else if (key == "zero_window") {
        cfg.params.zero_window = parse_bool(val);
    } else if (key == "ports") {
        cfg.tcp_ports.clear();
        for (auto& p : split_csv(val))
            cfg.tcp_ports.push_back(static_cast<uint16_t>(std::stoul(p)));
    } else if (key == "capture_ipv6") {
        cfg.capture_ipv6 = parse_bool(val);
    } else if (key == "log_level") {
        cfg.log_level = log::level_from_string(val);
    } else if (key == "domain_mode") {
        cfg.domain_mode = filter_mode_from_string(val);
    } else if (key == "domain_file") {
        cfg.domain_file = val;
    } else if (key == "flow_tracking") {
        cfg.flow_tracking = parse_bool(val);
    } else if (key == "dns_redirect") {
        cfg.dns_redirect = parse_bool(val);
    } else if (key == "dns_upstream") {
        cfg.dns_upstream = val;
    } else if (key == "inbound_rst_drop") {
        cfg.inbound_rst_drop = parse_bool(val);
    } else {
        SGDPI_LOG_WARN("preset: ignoring unknown key '", key, "'");
    }
}

} // namespace

bool load_preset_file(const std::string& path, Config& cfg) {
    std::ifstream f(path);
    if (!f) {
        SGDPI_LOG_WARN("preset: cannot open ", path);
        return false;
    }
    std::string line;
    int lineno = 0;
    while (std::getline(f, line)) {
        ++lineno;
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        const auto trimmed = trim(line);
        if (trimmed.empty()) continue;
        const auto eq = trimmed.find('=');
        if (eq == std::string::npos) {
            SGDPI_LOG_WARN("preset: ", path, ":", lineno, ": expected key=value");
            continue;
        }
        const std::string key = trim(trimmed.substr(0, eq));
        const std::string val = trim(trimmed.substr(eq + 1));
        try {
            apply_kv(key, val, cfg);
        } catch (const std::exception& e) {
            SGDPI_LOG_WARN("preset: ", path, ":", lineno, ": ", e.what());
        }
    }
    SGDPI_LOG_INFO("Loaded preset: ", path);
    return true;
}

void print_usage(std::ostream& os) {
    os <<
"SiktirGitDPI - DPI bypass tool (Windows / WinDivert)\n"
"Usage: sgdpi.exe [options]\n"
"\n"
"Strategy selection:\n"
"  --strategies LIST       Comma-separated chain (first match wins).\n"
"                          Default: tls-split,http-mangle\n"
"  --preset NAME           Load preset (presets/NAME.conf).\n"
"  --auto HOST             Probe HOST and pick the best strategy automatically.\n"
"\n"
"TLS split:\n"
"  --tls-split-mode MODE   midsni | presni | first | fixed (default: midsni)\n"
"  --tls-split-fixed N     Used when mode=fixed.\n"
"\n"
"Fake-TTL desync:\n"
"  --fake-ttl N            TTL of decoy packets. 'auto' to discover via ICMP.\n"
"  --fake-repeat N         Number of decoys per real packet (default: 1).\n"
"  --auto-ttl HOST         Probe HOST to discover a sensible fake TTL.\n"
"\n"
"HTTP host mangle:\n"
"  --http-mangle           Enable Host header mangling (alternates case).\n"
"  --http-extra-space      Add extra whitespace after 'Host:'.\n"
"  --http-split-url        Also TCP-split before the Host value.\n"
"\n"
"Misc strategies (toggle on by adding to --strategies):\n"
"  disorder, oob, md5-opt, zero-window, tls-frag, wrong-chksum\n"
"\n"
"Domain filter:\n"
"  --domain-mode MODE      off | allowlist | blocklist (default: off)\n"
"  --domain-file PATH      File with one pattern per line.\n"
"                          Patterns: 'host', '*.host', '.host'.\n"
"\n"
"DNS protection:\n"
"  --dns-redirect          Transparently route UDP/53 to a trusted upstream.\n"
"  --dns-upstream IP       Upstream DNS resolver (default: 1.1.1.1).\n"
"\n"
"Anti-DPI countermeasures:\n"
"  --inbound-rst-drop      Drop ISP-injected TCP RST packets (recommended).\n"
"\n"
"Engine:\n"
"  --threads N             Worker threads (default: HW concurrency).\n"
"  --priority N            WinDivert priority (default: 0).\n"
"  --ports LIST            Comma-separated TCP ports (default: 80,443).\n"
"  --ipv6                  Also capture IPv6 traffic.\n"
"  --filter EXPR           Use EXPR as the entire WinDivert filter.\n"
"\n"
"Observability:\n"
"  --stats [INTERVAL_MS]   Print per-second counters (default: 1000ms).\n"
"  --log-level LEVEL       trace|debug|info|warn|error|off (default: info).\n"
"  --log-file PATH         Also write logs to file.\n"
"\n"
"  -v, --version           Print version and exit.\n"
"  --list-strategies       List all available strategies and exit.\n"
"  -h, --help              This help.\n"
"\n"
"Examples:\n"
"  sgdpi.exe                                 # default profile\n"
"  sgdpi.exe --preset tt --stats             # TT preset with live stats\n"
"  sgdpi.exe --auto youtube.com              # auto-tune against youtube\n"
"  sgdpi.exe --strategies tls-split,fake-ttl,wrong-chksum --fake-ttl auto\n"
"  sgdpi.exe --preset safe --inbound-rst-drop  # safe mode + RST protection\n"
"\n"
"WinDivert error hints:\n"
"  error=2    - WinDivert.dll not found. Place next to sgdpi.exe.\n"
"  error=5    - Access denied. Run as Administrator.\n"
"  error=577  - Driver not signed. Disable driver signature enforcement\n"
"               or use a signed WinDivert build.\n"
"  error=1753 - WinDivert64.sys not found. Place next to sgdpi.exe.\n";
}

namespace {

bool eq(const char* a, const char* b) { return std::strcmp(a, b) == 0; }
bool eq2(const char* a, const char* x, const char* y) { return eq(a, x) || eq(a, y); }

const char* require_val(int& i, int argc, char** argv) {
    if (i + 1 >= argc) throw Error(std::string("missing value for ") + argv[i]);
    return argv[++i];
}

} // namespace

std::string build_divert_filter(const Config& cfg) {
    if (!cfg.custom_filter.empty()) return cfg.custom_filter;

    std::ostringstream os;

    // Outbound: TCP segments with payload on the target ports.
    os << "(outbound and tcp and tcp.PayloadLength > 0 and (";
    for (size_t i = 0; i < cfg.tcp_ports.size(); ++i) {
        if (i) os << " or ";
        os << "tcp.DstPort == " << cfg.tcp_ports[i];
    }
    os << ")";
    if (!cfg.capture_ipv6) os << " and ip";
    os << ")";

    // Inbound RST drop: also capture inbound RST packets on our ports.
    if (cfg.inbound_rst_drop) {
        os << " or (inbound and tcp and tcp.Rst and (";
        for (size_t i = 0; i < cfg.tcp_ports.size(); ++i) {
            if (i) os << " or ";
            os << "tcp.SrcPort == " << cfg.tcp_ports[i];
        }
        os << ")";
        if (!cfg.capture_ipv6) os << " and ip";
        os << ")";
    }

    return os.str();
}

namespace {
void resolve_preset_path(Config& cfg) {
    if (cfg.preset.empty()) return;
    namespace fs = std::filesystem;

    // Search: cwd, cwd/presets, and executable directory + presets.
    std::vector<fs::path> roots = {
        fs::current_path(),
        fs::current_path() / "presets",
    };

    // Try to find the executable's own directory.
    wchar_t exe_buf[MAX_PATH] = {};
    if (::GetModuleFileNameW(nullptr, exe_buf, MAX_PATH) > 0) {
        fs::path exe_dir = fs::path(exe_buf).parent_path();
        roots.push_back(exe_dir);
        roots.push_back(exe_dir / "presets");
    }

    const std::string filename = cfg.preset + ".conf";
    for (const auto& r : roots) {
        const fs::path candidate = r / filename;
        if (fs::exists(candidate)) {
            (void)load_preset_file(candidate.string(), cfg);
            return;
        }
    }
    SGDPI_LOG_WARN("preset '", cfg.preset, "' not found in ./, ./presets/, or exe directory");
}
} // namespace

Config parse_args(int argc, char** argv) {
    Config cfg;
    cfg.strategies = {"tls-split", "http-mangle"};

    // First pass: pull out --preset / --log-level so they take effect early.
    for (int i = 1; i < argc; ++i) {
        if (eq(argv[i], "--preset"))    cfg.preset    = require_val(i, argc, argv);
        else if (eq(argv[i], "--log-level"))
            cfg.log_level = log::level_from_string(require_val(i, argc, argv));
    }
    log::set_level(cfg.log_level);
    resolve_preset_path(cfg);

    // Second pass: real CLI options override preset values.
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if      (eq2(a, "-h", "--help"))     { print_usage(std::cout); std::exit(0); }
        else if (eq2(a, "-v", "--version"))  { std::cout << "sgdpi v0.2.0\n"; std::exit(0); }
        else if (eq(a, "--list-strategies")) {
            std::cout << "Available strategies:\n";
            for (const auto& n : all_strategy_names())
                std::cout << "  " << n << "\n";
            std::exit(0);
        }
        else if (eq(a, "--preset") || eq(a, "--log-level")) { ++i; continue; }
        else if (eq(a, "--strategies"))      cfg.strategies = split_csv(require_val(i, argc, argv));
        else if (eq(a, "--tls-split-mode"))  cfg.params.tls_split_mode = require_val(i, argc, argv);
        else if (eq(a, "--tls-split-fixed")) cfg.params.tls_split_fixed = std::stoul(require_val(i, argc, argv));
        else if (eq(a, "--fake-ttl")) {
            const char* v = require_val(i, argc, argv);
            cfg.params.fake_ttl = iequals(v, "auto") ? -1 : std::stoi(v);
        }
        else if (eq(a, "--fake-repeat"))     cfg.params.fake_repeat = std::stoi(require_val(i, argc, argv));
        else if (eq(a, "--auto-ttl"))      { cfg.auto_ttl = true; cfg.auto_ttl_target = require_val(i, argc, argv); }
        else if (eq(a, "--auto"))          { cfg.auto_tune = true; cfg.auto_tune_target = require_val(i, argc, argv); }
        else if (eq(a, "--http-mangle"))     cfg.params.http_mangle_case = true;
        else if (eq(a, "--http-extra-space"))cfg.params.http_extra_space = true;
        else if (eq(a, "--http-split-url"))  cfg.params.http_split_url   = true;
        else if (eq(a, "--threads"))         cfg.worker_threads = std::stoi(require_val(i, argc, argv));
        else if (eq(a, "--priority"))        cfg.divert_priority = static_cast<int16_t>(std::stoi(require_val(i, argc, argv)));
        else if (eq(a, "--ports")) {
            cfg.tcp_ports.clear();
            for (auto& p : split_csv(require_val(i, argc, argv)))
                cfg.tcp_ports.push_back(static_cast<uint16_t>(std::stoul(p)));
        }
        else if (eq(a, "--ipv6"))            cfg.capture_ipv6 = true;
        else if (eq(a, "--filter"))          cfg.custom_filter = require_val(i, argc, argv);
        else if (eq(a, "--stats")) {
            cfg.show_stats = true;
            // Optional integer immediately after.
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                try { cfg.stats_interval = Millis{std::stoi(argv[i + 1])}; ++i; }
                catch (...) {}
            }
        }
        else if (eq(a, "--log-file"))        cfg.log_file = require_val(i, argc, argv);
        else if (eq(a, "--domain-mode"))     cfg.domain_mode = filter_mode_from_string(require_val(i, argc, argv));
        else if (eq(a, "--domain-file"))     cfg.domain_file = require_val(i, argc, argv);
        else if (eq(a, "--dns-redirect"))    cfg.dns_redirect = true;
        else if (eq(a, "--dns-upstream"))    cfg.dns_upstream = require_val(i, argc, argv);
        else if (eq(a, "--no-flow-tracking")) cfg.flow_tracking = false;
        else if (eq(a, "--inbound-rst-drop")) cfg.inbound_rst_drop = true;
        else throw Error(std::string("unknown option: ") + a);
    }
    return cfg;
}

} // namespace sgdpi
