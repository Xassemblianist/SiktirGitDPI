// SiktirGitDPI entry point.

#include "sgdpi/auto_tune.hpp"
#include "sgdpi/config.hpp"
#include "sgdpi/dns_redirect.hpp"
#include "sgdpi/engine.hpp"
#include "sgdpi/log.hpp"
#include "sgdpi/stats.hpp"
#include "sgdpi/strategy.hpp"
#include "sgdpi/ttl_probe.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <iostream>

namespace {

std::atomic<bool>    g_should_stop{false};
sgdpi::Engine*       g_engine = nullptr;
sgdpi::DnsRedirect*  g_dnr    = nullptr;

BOOL WINAPI console_handler(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            g_should_stop.store(true);
            if (g_engine) g_engine->stop();
            if (g_dnr)    g_dnr->stop();
            return TRUE;
        default:
            return FALSE;
    }
}

void enable_vt_colors() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    if (!GetConsoleMode(h, &mode)) return;
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

void print_banner() {
    SGDPI_LOG_INFO("");
    SGDPI_LOG_INFO("  ____  _ _    _   _      ____ _ _   ____  ____ ___ ");
    SGDPI_LOG_INFO(" / ___|(_) | _| |_(_)_ __/ ___(_) |_|  _ \\|  _ \\_ _|");
    SGDPI_LOG_INFO(" \\___ \\| | |/ / __| | '__| |  _| | __| | | | |_) | | ");
    SGDPI_LOG_INFO("  ___) | |   <| |_| | |  | |_| | | |_| |_| |  __/| | ");
    SGDPI_LOG_INFO(" |____/|_|_|\\_\\\\__|_|_|   \\____|_|\\__|____/|_|  |___|");
    SGDPI_LOG_INFO("    DPI bypass for Turkish ISPs   v0.2.0");
    SGDPI_LOG_INFO("");
}

} // namespace

int main(int argc, char** argv) {
    using namespace sgdpi;

    enable_vt_colors();
    SetConsoleCtrlHandler(console_handler, TRUE);

    // Initialize Winsock once for the lifetime of the process. ttl_probe and
    // auto_tune both need it; doing it here is cheap and guarantees ordering.
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
    struct WsaCleanupGuard { ~WsaCleanupGuard() { ::WSACleanup(); } } wsa_guard;

    Config cfg;
    try {
        cfg = parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n\n";
        print_usage(std::cerr);
        return 2;
    }

    log::set_level(cfg.log_level);
    if (!cfg.log_file.empty()) log::set_file(cfg.log_file);

    print_banner();

    // ---- Auto-TTL ---------------------------------------------------------
    if (cfg.auto_ttl && !cfg.auto_ttl_target.empty()) {
        SGDPI_LOG_INFO("Discovering hop count to ", cfg.auto_ttl_target, "...");
        const auto pr = ttl::discover(cfg.auto_ttl_target);
        if (pr.ok) {
            cfg.params.fake_ttl = pr.suggested_fake_ttl;
        } else if (cfg.params.fake_ttl < 0) {
            cfg.params.fake_ttl = 4;
            SGDPI_LOG_WARN("auto-TTL failed, falling back to fake_ttl=4");
        }
    } else if (cfg.params.fake_ttl < 0) {
        // User asked for "auto" without an explicit probe target. Try a
        // sensible default destination.
        const auto pr = ttl::discover("1.1.1.1");
        cfg.params.fake_ttl = pr.ok ? pr.suggested_fake_ttl : 4;
    }

    // ---- Auto-tune -------------------------------------------------------
    if (cfg.auto_tune && !cfg.auto_tune_target.empty()) {
        SGDPI_LOG_INFO("Auto-tuning against ", cfg.auto_tune_target, "...");
        tune::TuneOptions opts;
        opts.target_host = cfg.auto_tune_target;
        opts.fake_ttl    = cfg.params.fake_ttl > 0 ? cfg.params.fake_ttl : 4;
        const auto r = tune::run(opts);
        if (!r.ok) {
            SGDPI_LOG_ERROR("Auto-tune found no working strategy. Falling back to defaults.");
        } else {
            SGDPI_LOG_INFO("Auto-tune chose: ", r.best_strategy);
            cfg.strategies = {r.best_strategy};
        }
    }

    // ---- Build pipeline --------------------------------------------------
    if (cfg.strategies.empty()) {
        SGDPI_LOG_ERROR("No strategies enabled. Use --strategies or --preset.");
        return 1;
    }
    SGDPI_LOG_INFO("Strategies: ", [&] {
        std::string s;
        for (size_t i = 0; i < cfg.strategies.size(); ++i) {
            if (i) s += ",";
            s += cfg.strategies[i];
        }
        return s;
    }());
    SGDPI_LOG_INFO("Fake TTL: ", cfg.params.fake_ttl, " (repeat=",
                   cfg.params.fake_repeat, ")");
    SGDPI_LOG_INFO("TLS split mode: ", cfg.params.tls_split_mode);

    auto pipeline = build_pipeline(cfg.strategies);
    if (pipeline.size() == 0) {
        SGDPI_LOG_ERROR("Pipeline is empty - all strategy names invalid?");
        return 1;
    }

    // ---- Run engine ------------------------------------------------------
    // Save values we need after std::move(cfg).
    const bool   want_stats    = cfg.show_stats;
    const Millis stats_ival    = cfg.stats_interval;
    const bool   want_dns      = cfg.dns_redirect;
    const auto   dns_upstream  = cfg.dns_upstream;

    Engine engine;
    g_engine = &engine;
    StatsPrinter printer{engine.stats()};

    DnsRedirect  dnr;
    g_dnr = &dnr;

    try {
        if (want_dns) dnr.start(dns_upstream);
        engine.start(std::move(cfg), std::move(pipeline));
    } catch (const std::exception& e) {
        SGDPI_LOG_ERROR("Engine start failed: ", e.what());
        SGDPI_LOG_ERROR("Are you running as Administrator? Is WinDivert.dll next to sgdpi.exe?");
        return 1;
    }

    if (want_stats) printer.start(stats_ival);

    SGDPI_LOG_INFO("Engine running. Press Ctrl+C to stop.");
    engine.wait();

    printer.stop();
    SGDPI_LOG_INFO("Bye.");
    return 0;
}
