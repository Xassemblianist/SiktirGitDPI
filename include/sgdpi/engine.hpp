// Multi-threaded packet processing engine.
//
// One Divert handle is shared by N worker threads. Each worker:
//   1. Recv()s a packet into a thread-local buffer.
//   2. Parses IP/TCP and (cheaply) sniffs whether it's TLS / HTTP.
//   3. Runs the strategy pipeline.
//   4. Sends the resulting packets via the same handle.
//
// Recv() is thread-safe in WinDivert and the kernel does the work of
// distributing packets across waiting receivers, so this scales linearly
// with worker count up to about the number of physical CPU cores.

#pragma once

#include "sgdpi/common.hpp"
#include "sgdpi/config.hpp"
#include "sgdpi/divert.hpp"
#include "sgdpi/domain_filter.hpp"
#include "sgdpi/flow_table.hpp"
#include "sgdpi/stats.hpp"
#include "sgdpi/strategy.hpp"

#include <atomic>
#include <thread>
#include <vector>

namespace sgdpi {

class Engine {
public:
    Engine() = default;
    ~Engine() { stop(); wait(); }

    Engine(const Engine&)            = delete;
    Engine& operator=(const Engine&) = delete;

    // Start the engine with a fully-realized config + pipeline. Throws on
    // setup failure (e.g. WinDivert open). Returns immediately - workers
    // run in background threads.
    void start(Config cfg, StrategyPipeline pipeline);

    // Block until stop() is called from another thread or all workers exit.
    void wait();

    // Tell workers to drain and exit.
    void stop() noexcept;

    [[nodiscard]] Stats&        stats()         noexcept { return stats_;        }
    [[nodiscard]] DomainFilter& domain_filter() noexcept { return domain_filter_; }
    [[nodiscard]] FlowTable&    flow_table()    noexcept { return flow_table_;   }

private:
    void worker_loop(int worker_id);

    Config            cfg_;
    StrategyPipeline  pipeline_;
    Divert            divert_;
    Stats             stats_;
    DomainFilter      domain_filter_;
    FlowTable         flow_table_{Millis{30'000}};
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
};

} // namespace sgdpi
