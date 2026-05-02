// Strategy framework + concrete bypass implementations.
//
// A Strategy takes the original packet (already parsed into a PacketView) +
// the divert address, and produces zero or more output packets to inject
// (each with its own address). Strategies do NOT call WinDivert directly -
// the engine takes their output and sends it.
//
// This indirection serves two purposes:
//   1) auto_tune can run strategies in a sandbox to grade them
//   2) strategies are independently unit-testable

#pragma once

#include "sgdpi/common.hpp"
#include "sgdpi/divert.hpp"
#include "sgdpi/packet.hpp"
#include "sgdpi/tls.hpp"
#include "sgdpi/http.hpp"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace sgdpi {

// One outbound packet that the engine should inject.
struct OutPacket {
    std::array<uint8_t, PacketBuilder::kMaxMtu> bytes{};
    size_t      len = 0;
    DivertAddr  addr{};
};

using OutQueue = std::vector<OutPacket>;

// Identifies what flow this strategy applies to. Each strategy advertises
// which traffic it wants to handle so the engine can short-circuit cheap
// checks.
enum class FlowKind : uint8_t {
    Any   = 0,
    Tls   = 1,
    Http  = 2,
};

// Context passed into a strategy. Exposes the parsed packet plus pre-parsed
// TLS/HTTP info if the engine has already classified the flow.
struct PacketContext {
    PacketView*                       view;
    DivertAddr*                       addr;
    const tls::ClientHelloInfo*       tls_info;     // null if not TLS handshake
    const http::RequestInfo*          http_info;    // null if not HTTP
};

// Common parameters bundle. Concrete strategies pull what they need.
struct StrategyParams {
    // TLS split
    std::string  tls_split_mode  = "midsni";   // midsni | presni | first | fixed
    size_t       tls_split_fixed = 0;

    // Fake TTL desync
    int          fake_ttl        = 4;          // 0 disables; -1 means "auto"
    int          fake_repeat     = 1;          // number of fake packets

    // HTTP host mangle
    bool         http_mangle_case  = true;     // Host -> hoSt
    bool         http_extra_space  = false;    // "Host: example" -> "Host:  example"
    bool         http_split_url    = false;    // also split TCP at start of URL

    // Zero-window: set window=0 on the first segment of a TLS split
    bool         zero_window = false;
};

// Strategy interface.
class IStrategy {
public:
    virtual ~IStrategy() = default;

    [[nodiscard]] virtual const char* name()  const noexcept = 0;
    [[nodiscard]] virtual FlowKind    kind()  const noexcept = 0;

    // Apply transformation. Returns true if the strategy *handled* the
    // packet (in which case the engine should NOT also re-inject the
    // original; the strategy must put any packets it wants sent into `out`).
    // Returns false to fall through (engine sends the original unchanged).
    virtual bool apply(const PacketContext& ctx, const StrategyParams& params,
                       OutQueue& out) = 0;
};

// ---------------------------------------------------------------------------
// A pipeline runs a list of strategies in order. The first strategy that
// returns `true` wins for that packet. There is no "compose" mode - if you
// want layered effects, write a strategy that does both internally.
// ---------------------------------------------------------------------------
class StrategyPipeline {
public:
    void add(std::unique_ptr<IStrategy> s);
    void clear() noexcept { stages_.clear(); }

    [[nodiscard]] size_t size() const noexcept { return stages_.size(); }
    [[nodiscard]] IStrategy* at(size_t i) const noexcept { return stages_[i].get(); }

    // Run the pipeline. Returns a pointer to the strategy that handled the
    // packet, or nullptr if none matched. Caller can use the returned
    // pointer's name() for stats attribution.
    IStrategy* run(const PacketContext& ctx, const StrategyParams& params, OutQueue& out);

private:
    std::vector<std::unique_ptr<IStrategy>> stages_;
};

// ---------------------------------------------------------------------------
// Factory functions for built-in strategies.
// ---------------------------------------------------------------------------
std::unique_ptr<IStrategy> make_tls_split();
std::unique_ptr<IStrategy> make_tls_record_frag();
std::unique_ptr<IStrategy> make_fake_ttl();
std::unique_ptr<IStrategy> make_http_host_mangle();
std::unique_ptr<IStrategy> make_disorder();
std::unique_ptr<IStrategy> make_oob();
std::unique_ptr<IStrategy> make_md5_fake_option();
std::unique_ptr<IStrategy> make_zero_window();
std::unique_ptr<IStrategy> make_wrong_checksum();

// Convenience: builds a pipeline matching a textual list of strategy names.
// Names: tls-split, tls-frag, fake-ttl, http-mangle, disorder, oob, md5-opt,
// zero-window, wrong-chksum. Unknown names are skipped with a warning.
StrategyPipeline build_pipeline(const std::vector<std::string>& names);

// Names of every built-in strategy, in the recommended ordering. Used by
// auto-tune.
[[nodiscard]] const std::vector<std::string>& all_strategy_names();

} // namespace sgdpi
