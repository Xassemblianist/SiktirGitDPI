// Atomic counters + an optional live console panel.
//
// Counters are split into a small set of named fields. Strategies and the
// engine bump them; a printer thread periodically computes deltas and renders
// a one-line dashboard.

#pragma once

#include "sgdpi/common.hpp"

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>

namespace sgdpi {

class Stats {
public:
    // Global counters.
    std::atomic<uint64_t> pkts_recv          {0};
    std::atomic<uint64_t> pkts_passthrough   {0};
    std::atomic<uint64_t> pkts_modified      {0};
    std::atomic<uint64_t> pkts_emitted       {0};
    std::atomic<uint64_t> pkts_dropped       {0};
    std::atomic<uint64_t> errors_recv        {0};
    std::atomic<uint64_t> errors_send        {0};
    std::atomic<uint64_t> tls_seen           {0};
    std::atomic<uint64_t> http_seen          {0};

    // Per-strategy hit counter. Keyed by strategy name.
    void bump_strategy(const std::string& name) noexcept;

    // Snapshot the per-strategy map (cheap copy). Returned values are
    // cumulative since startup.
    [[nodiscard]] std::map<std::string, uint64_t> strategy_snapshot() const;

    // Reset all counters to zero.
    void reset() noexcept;

private:
    mutable std::mutex                     mu_;
    std::map<std::string, uint64_t>        per_strategy_;
};

// Optional live console renderer. start() spawns a thread that prints to
// stdout every `interval`. stop() joins it.
class StatsPrinter {
public:
    explicit StatsPrinter(Stats& s) noexcept : s_(s) {}
    ~StatsPrinter() { stop(); }

    void start(Millis interval = Millis{1000});
    void stop() noexcept;

private:
    void run(Millis interval) noexcept;

    Stats&            s_;
    std::thread       th_;
    std::atomic<bool> running_{false};
};

} // namespace sgdpi
