#include "sgdpi/stats.hpp"
#include "sgdpi/log.hpp"

#include <cstdio>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace sgdpi {

void Stats::bump_strategy(const std::string& name) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    ++per_strategy_[name];
}

std::map<std::string, uint64_t> Stats::strategy_snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    return per_strategy_;
}

void Stats::reset() noexcept {
    pkts_recv.store(0);
    pkts_passthrough.store(0);
    pkts_modified.store(0);
    pkts_emitted.store(0);
    pkts_dropped.store(0);
    errors_recv.store(0);
    errors_send.store(0);
    tls_seen.store(0);
    http_seen.store(0);
    std::lock_guard<std::mutex> lk(mu_);
    per_strategy_.clear();
}

// ---------------------------------------------------------------------------
// StatsPrinter
// ---------------------------------------------------------------------------
void StatsPrinter::start(Millis interval) {
    if (running_.exchange(true)) return;
    th_ = std::thread([this, interval] { run(interval); });
}

void StatsPrinter::stop() noexcept {
    running_.store(false);
    if (th_.joinable()) th_.join();
}

void StatsPrinter::run(Millis interval) noexcept {
    uint64_t last_recv      = 0;
    uint64_t last_modified  = 0;
    uint64_t last_emitted   = 0;
    uint64_t last_dropped   = 0;
    auto     last_t         = Clock::now();

    while (running_.load()) {
        std::this_thread::sleep_for(interval);
        if (!running_.load()) break;

        const auto now = Clock::now();
        const auto dt  = std::chrono::duration_cast<std::chrono::duration<double>>(now - last_t).count();
        last_t = now;
        if (dt <= 0) continue;

        const uint64_t cur_recv     = s_.pkts_recv.load();
        const uint64_t cur_modified = s_.pkts_modified.load();
        const uint64_t cur_emitted  = s_.pkts_emitted.load();
        const uint64_t cur_dropped  = s_.pkts_dropped.load();

        const double rps = (cur_recv     - last_recv)     / dt;
        const double mps = (cur_modified - last_modified) / dt;
        const double eps = (cur_emitted  - last_emitted)  / dt;
        const double dps = (cur_dropped  - last_dropped)  / dt;

        last_recv     = cur_recv;
        last_modified = cur_modified;
        last_emitted  = cur_emitted;
        last_dropped  = cur_dropped;

        std::ostringstream line;
        line << "\x1b[36m\xe2\x94\x82\x1b[0m "  // │ cyan
             << "in=" << std::fixed << std::setprecision(0) << rps << "/s "
             << "\x1b[32m" << "mod=" << mps << "/s" << "\x1b[0m "
             << "out=" << eps << "/s";

        if (cur_dropped > 0) {
            line << " \x1b[33m" << "drop=" << dps << "/s"
                 << " (" << cur_dropped << " total)" << "\x1b[0m";
        }

        line << " \x1b[36m\xe2\x94\x82\x1b[0m "
             << "tls=" << s_.tls_seen.load()
             << " http=" << s_.http_seen.load();

        if (s_.errors_recv.load() > 0 || s_.errors_send.load() > 0) {
            line << " \x1b[31m"
                 << "err_recv=" << s_.errors_recv.load()
                 << " err_send=" << s_.errors_send.load()
                 << "\x1b[0m";
        }

        const auto strats = s_.strategy_snapshot();
        if (!strats.empty()) {
            line << " \x1b[36m\xe2\x94\x82\x1b[0m ";
            bool first = true;
            for (const auto& [name, n] : strats) {
                if (!first) line << " ";
                line << "\x1b[35m" << name << "\x1b[0m=" << n;
                first = false;
            }
        }
        SGDPI_LOG_INFO(line.str());
    }
}

} // namespace sgdpi
