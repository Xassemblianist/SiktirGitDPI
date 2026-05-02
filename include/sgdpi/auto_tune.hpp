// Auto-tune: probe each strategy against a target and pick the best one.
//
// We approach this by *not* coupling auto_tune with the engine. Instead it:
//   1. Runs its own short-lived divert handle scoped to the target address.
//   2. Spawns a tester thread that performs a TLS ClientHello against the
//      target and waits for the ServerHello.
//   3. For each candidate strategy, it applies that strategy to the test
//      flow and measures success.
//
// The function blocks until tuning is done.

#pragma once

#include "sgdpi/common.hpp"
#include "sgdpi/strategy.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace sgdpi::tune {

struct StrategyScore {
    std::string name;
    int         attempts   = 0;
    int         successes  = 0;
    double      avg_first_byte_ms = 0.0;

    [[nodiscard]] double success_rate() const noexcept {
        return attempts ? (double)successes / attempts : 0.0;
    }
};

struct TuneOptions {
    std::string             target_host;       // e.g. "youtube.com"
    uint16_t                target_port = 443;
    int                     attempts_per_strategy = 3;
    std::chrono::milliseconds timeout{5000};
    int                     fake_ttl    = 4;   // applied where strategies use it
    std::vector<std::string> candidates;        // empty = all
};

struct TuneResult {
    bool                          ok = false;
    std::string                   best_strategy;     // "" if nothing worked
    std::vector<StrategyScore>    scores;
};

// Run the tuner. Requires admin (it opens a divert handle scoped to the
// target). The engine should NOT be running concurrently for this target -
// the caller is responsible for stopping the main engine first.
[[nodiscard]] TuneResult run(const TuneOptions& opts);

} // namespace sgdpi::tune
