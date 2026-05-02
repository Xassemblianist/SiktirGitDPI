#include "sgdpi/engine.hpp"
#include "sgdpi/flow_table.hpp"
#include "sgdpi/log.hpp"
#include "sgdpi/packet.hpp"
#include "sgdpi/tls.hpp"
#include "sgdpi/http.hpp"

#include <algorithm>

namespace sgdpi {

void Engine::start(Config cfg, StrategyPipeline pipeline) {
    cfg_      = std::move(cfg);
    pipeline_ = std::move(pipeline);

    // Domain filter setup.
    domain_filter_.set_mode(cfg_.domain_mode);
    if (!cfg_.domain_file.empty()) {
        domain_filter_.load_file(cfg_.domain_file);
    }
    if (cfg_.domain_mode != FilterMode::Off) {
        SGDPI_LOG_INFO("Domain filter: ", filter_mode_name(cfg_.domain_mode),
                       " (", domain_filter_.pattern_count(), " patterns)");
    }
    flow_table_.set_ttl(cfg_.flow_ttl);
    flow_table_.clear();

    const std::string filter = build_divert_filter(cfg_);
    SGDPI_LOG_INFO("Filter: ", filter);

    divert_.open(filter, DivertLayer::Network, cfg_.divert_priority);
    divert_.set_queue_length(cfg_.queue_length);
    divert_.set_queue_size  (cfg_.queue_size_mb * 1024 * 1024);
    divert_.set_queue_time_ms(cfg_.queue_time_ms);

    int n = cfg_.worker_threads;
    if (n <= 0) n = static_cast<int>(std::max(1u, std::thread::hardware_concurrency()));
    SGDPI_LOG_INFO("Engine starting with ", n, " worker thread(s)");

    running_.store(true);
    workers_.reserve(n);
    for (int i = 0; i < n; ++i) {
        workers_.emplace_back([this, i] { worker_loop(i); });
    }
}

void Engine::stop() noexcept {
    // Signal-only: mark not-running and unblock recv calls. wait() / dtor
    // will do the actual joining + handle close. Idempotent so it's safe
    // to call from a Ctrl-C handler.
    if (!running_.exchange(false)) return;
    divert_.shutdown_recv();
}

void Engine::wait() {
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
    if (divert_.is_open()) {
        divert_.close();
        SGDPI_LOG_INFO("Engine stopped. Recv=", stats_.pkts_recv.load(),
                       " mod=", stats_.pkts_modified.load(),
                       " emit=", stats_.pkts_emitted.load());
    }
}

void Engine::worker_loop(int worker_id) {
    constexpr size_t kBufSize = 0x10000;
    std::vector<uint8_t> buf(kBufSize);

    SGDPI_LOG_DEBUG("[w", worker_id, "] worker entering loop");

    while (running_.load()) {
        DivertAddr addr;
        uint32_t   rlen = 0;
        uint32_t   err  = 0;
        if (!divert_.recv(buf.data(), kBufSize, &rlen, &addr, &err)) {
            if (!running_.load()) break;
            // Common transient: ERROR_NO_DATA when shutting down. Anything
            // else, log and keep going.
            stats_.errors_recv.fetch_add(1, std::memory_order_relaxed);
            if (err != 232 /*ERROR_NO_DATA*/) {
                SGDPI_LOG_WARN("[w", worker_id, "] recv error=", err);
            }
            continue;
        }
        stats_.pkts_recv.fetch_add(1, std::memory_order_relaxed);

        PacketView v(buf.data(), rlen);
        if (!v.valid() || !v.is_tcp()) {
            // Pass through unchanged.
            uint32_t sent = 0;
            if (!divert_.send(buf.data(), rlen, addr, &sent)) {
                stats_.errors_send.fetch_add(1, std::memory_order_relaxed);
            } else {
                stats_.pkts_passthrough.fetch_add(1, std::memory_order_relaxed);
                stats_.pkts_emitted   .fetch_add(1, std::memory_order_relaxed);
            }
            continue;
        }

        // Inbound RST drop: if this is an inbound RST packet and we have
        // rst-drop enabled, silently discard it. Turkish ISPs inject fake
        // RSTs after seeing a blocked SNI in the ClientHello.
        if (cfg_.inbound_rst_drop && !addr.is_outbound() && v.tcp_rst()) {
            stats_.pkts_dropped.fetch_add(1, std::memory_order_relaxed);
            SGDPI_LOG_DEBUG("[w", worker_id, "] dropped inbound RST from port ",
                            v.src_port());
            continue;
        }

        if (v.payload_size() == 0 || !addr.is_outbound()) {
            // Non-outbound or empty payload: pass through.
            uint32_t sent = 0;
            if (!divert_.send(buf.data(), rlen, addr, &sent)) {
                stats_.errors_send.fetch_add(1, std::memory_order_relaxed);
            } else {
                stats_.pkts_passthrough.fetch_add(1, std::memory_order_relaxed);
                stats_.pkts_emitted   .fetch_add(1, std::memory_order_relaxed);
            }
            continue;
        }

        const ByteView pl = v.payload_view();

        // Cheap sniffing.
        const bool is_tls  = tls::looks_like_tls_handshake(pl);
        const bool is_http = !is_tls && http::looks_like_http(pl);

        tls::ClientHelloInfo  ti;
        http::RequestInfo     hi;
        if (is_tls) {
            ti = tls::parse_client_hello(pl);
            if (ti.present) stats_.tls_seen.fetch_add(1, std::memory_order_relaxed);
        }
        if (is_http) {
            hi = http::parse_request(pl);
            if (hi.present) stats_.http_seen.fetch_add(1, std::memory_order_relaxed);
        }

        // Domain filter: short-circuit if this hostname is excluded.
        if (cfg_.domain_mode != FilterMode::Off) {
            std::string_view host;
            if      (ti.present && !ti.hostname.empty()) host = ti.hostname;
            else if (hi.present && !hi.hostname.empty()) host = hi.hostname;
            // No hostname: allowlist excludes by default, blocklist passes.
            const bool allow = host.empty()
                ? (cfg_.domain_mode == FilterMode::Blocklist)
                : domain_filter_.should_apply(host);
            if (!allow) {
                uint32_t sent = 0;
                if (!divert_.send(buf.data(), rlen, addr, &sent)) {
                    stats_.errors_send.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stats_.pkts_passthrough.fetch_add(1, std::memory_order_relaxed);
                    stats_.pkts_emitted   .fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }
        }

        // Flow tracking: avoid re-applying strategies on every segment of a
        // long-running flow. We only mark a flow as "first_handled" once the
        // pipeline actually claims a packet, so a connection whose first
        // segment was a non-handshake fragment can still be acted upon
        // later.
        FlowTable::Handle fh;
        FlowState         fs;
        const bool flow_relevant = is_tls || is_http;
        if (cfg_.flow_tracking && flow_relevant) {
            const FlowKey key = flow_key_from(v);
            fh = flow_table_.probe(key, &fs);
            if (fs.first_handled) {
                // Already handled this flow's first interesting packet.
                // Pass through unchanged.
                uint32_t sent = 0;
                if (!divert_.send(buf.data(), rlen, addr, &sent)) {
                    stats_.errors_send.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stats_.pkts_passthrough.fetch_add(1, std::memory_order_relaxed);
                    stats_.pkts_emitted   .fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }
        }

        PacketContext ctx{ &v, &addr, &ti, &hi };

        // Run strategy pipeline.
        OutQueue out;
        out.reserve(4);
        IStrategy* handled = pipeline_.run(ctx, cfg_.params, out);

        if (handled) {
            stats_.pkts_modified.fetch_add(1, std::memory_order_relaxed);
            stats_.bump_strategy(handled->name());
            if (cfg_.flow_tracking && flow_relevant && fh.bucket != ~size_t{0}) {
                fs.first_handled = true;
                flow_table_.update(fh, flow_key_from(v), fs);
            }
            for (const auto& p : out) {
                uint32_t sent = 0;
                if (!divert_.send(p.bytes.data(), static_cast<uint32_t>(p.len),
                                  p.addr, &sent)) {
                    stats_.errors_send.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stats_.pkts_emitted.fetch_add(1, std::memory_order_relaxed);
                }
            }
        } else {
            // No strategy claimed the packet - send unchanged.
            uint32_t sent = 0;
            if (!divert_.send(buf.data(), rlen, addr, &sent)) {
                stats_.errors_send.fetch_add(1, std::memory_order_relaxed);
            } else {
                stats_.pkts_passthrough.fetch_add(1, std::memory_order_relaxed);
                stats_.pkts_emitted   .fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    SGDPI_LOG_DEBUG("[w", worker_id, "] worker exiting");
}

} // namespace sgdpi
