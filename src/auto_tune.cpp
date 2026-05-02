#include "sgdpi/auto_tune.hpp"
#include "sgdpi/divert.hpp"
#include "sgdpi/log.hpp"
#include "sgdpi/packet.hpp"
#include "sgdpi/strategy.hpp"
#include "sgdpi/tls.hpp"
#include "sgdpi/http.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <random>
#include <sstream>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

namespace sgdpi::tune {

namespace {

// ---------------------------------------------------------------------------
// Build a *minimal* TLS 1.2 ClientHello with a single SNI extension. We
// don't bother with cipher-suite politics; servers will respond with a
// ServerHello (or an Alert) either way, which is all we need.
// ---------------------------------------------------------------------------
std::vector<uint8_t> build_client_hello(const std::string& hostname) {
    std::vector<uint8_t> body;
    body.reserve(256);

    // legacy_version: TLS 1.2
    body.push_back(0x03); body.push_back(0x03);

    // random: 32 bytes
    std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> d(0, 255);
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<uint8_t>(d(rng)));

    // session_id<0>
    body.push_back(0x00);

    // cipher_suites: just TLS_RSA_WITH_AES_128_GCM_SHA256 + TLS_AES_128_GCM_SHA256
    body.push_back(0x00); body.push_back(0x04);
    body.push_back(0x00); body.push_back(0x9C);
    body.push_back(0x13); body.push_back(0x01);

    // legacy_compression_methods: null
    body.push_back(0x01); body.push_back(0x00);

    // extensions length placeholder
    const size_t ext_len_pos = body.size();
    body.push_back(0x00); body.push_back(0x00);

    // SNI extension (type=0x0000)
    {
        body.push_back(0x00); body.push_back(0x00);  // ext type
        const uint16_t host_len = static_cast<uint16_t>(hostname.size());
        const uint16_t list_len = static_cast<uint16_t>(host_len + 3);
        const uint16_t ext_len  = static_cast<uint16_t>(list_len + 2);
        body.push_back(static_cast<uint8_t>(ext_len  >> 8));
        body.push_back(static_cast<uint8_t>(ext_len));
        body.push_back(static_cast<uint8_t>(list_len >> 8));
        body.push_back(static_cast<uint8_t>(list_len));
        body.push_back(0x00); // host_name
        body.push_back(static_cast<uint8_t>(host_len >> 8));
        body.push_back(static_cast<uint8_t>(host_len));
        body.insert(body.end(), hostname.begin(), hostname.end());
    }

    // supported_versions ext (TLS 1.3 + 1.2)
    {
        body.push_back(0x00); body.push_back(0x2B);
        body.push_back(0x00); body.push_back(0x05);
        body.push_back(0x04); // list len
        body.push_back(0x03); body.push_back(0x04); // TLS 1.3
        body.push_back(0x03); body.push_back(0x03); // TLS 1.2
    }

    // patch extensions length
    const uint16_t ext_total = static_cast<uint16_t>(body.size() - ext_len_pos - 2);
    body[ext_len_pos    ] = static_cast<uint8_t>(ext_total >> 8);
    body[ext_len_pos + 1] = static_cast<uint8_t>(ext_total);

    // Wrap in handshake header (type=ClientHello, length=24-bit body length)
    std::vector<uint8_t> hs;
    hs.reserve(body.size() + 4);
    hs.push_back(0x01);
    hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    hs.push_back(static_cast<uint8_t>((body.size() >>  8) & 0xFF));
    hs.push_back(static_cast<uint8_t>( body.size()        & 0xFF));
    hs.insert(hs.end(), body.begin(), body.end());

    // Wrap in TLS record (handshake)
    std::vector<uint8_t> rec;
    rec.reserve(hs.size() + 5);
    rec.push_back(0x16);
    rec.push_back(0x03); rec.push_back(0x01);
    rec.push_back(static_cast<uint8_t>((hs.size() >> 8) & 0xFF));
    rec.push_back(static_cast<uint8_t>( hs.size()       & 0xFF));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

// ---------------------------------------------------------------------------
// Synchronous TLS connect + send ClientHello + wait for first response byte.
// Returns success + ms-to-first-byte on success.
// ---------------------------------------------------------------------------
struct ConnTest {
    bool   ok = false;
    double first_byte_ms = 0.0;
    std::string error;
};

ConnTest test_connection(const std::string& host, uint16_t port,
                         std::chrono::milliseconds timeout) {
    ConnTest r;

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;

    char port_str[8] = {};
    std::snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(port));
    if (::getaddrinfo(host.c_str(), port_str, &hints, &res) != 0 || !res) {
        r.error = "getaddrinfo failed";
        return r;
    }

    SOCKET s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { ::freeaddrinfo(res); r.error = "socket failed"; return r; }

    // Non-blocking for connect with timeout.
    u_long nonblock = 1;
    ::ioctlsocket(s, FIONBIO, &nonblock);

    const auto t0 = Clock::now();
    int rc = ::connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    if (rc == SOCKET_ERROR && ::WSAGetLastError() != WSAEWOULDBLOCK) {
        ::closesocket(s); ::freeaddrinfo(res);
        r.error = "connect immediate failure";
        return r;
    }

    fd_set wset; FD_ZERO(&wset); FD_SET(s, &wset);
    timeval tv{};
    tv.tv_sec  = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    rc = ::select(0, nullptr, &wset, nullptr, &tv);
    if (rc <= 0) {
        ::closesocket(s); ::freeaddrinfo(res);
        r.error = "connect timeout";
        return r;
    }
    int err = 0; int errlen = sizeof(err);
    ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
    if (err != 0) {
        ::closesocket(s); ::freeaddrinfo(res);
        r.error = "connect refused/reset";
        return r;
    }

    // Send ClientHello.
    const auto hello = build_client_hello(host);
    int sent = ::send(s, reinterpret_cast<const char*>(hello.data()),
                      static_cast<int>(hello.size()), 0);
    if (sent != static_cast<int>(hello.size())) {
        ::closesocket(s); ::freeaddrinfo(res);
        r.error = "send failed";
        return r;
    }

    // Wait for first byte.
    fd_set rset; FD_ZERO(&rset); FD_SET(s, &rset);
    rc = ::select(0, &rset, nullptr, nullptr, &tv);
    if (rc <= 0) {
        ::closesocket(s); ::freeaddrinfo(res);
        r.error = "no response";
        return r;
    }
    char buf[16];
    const int got = ::recv(s, buf, sizeof(buf), 0);
    const auto t1 = Clock::now();
    ::closesocket(s); ::freeaddrinfo(res);

    if (got <= 0) { r.error = "recv failed"; return r; }
    // A real TLS ServerHello starts with 0x16. An ISP block-page TCP
    // response or a fake TLS Alert won't.
    if (static_cast<uint8_t>(buf[0]) != 0x16) {
        r.error = "non-TLS response (likely DPI block)";
        return r;
    }

    r.ok = true;
    r.first_byte_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    return r;
}

// ---------------------------------------------------------------------------
// Tester worker: drains a divert handle and applies one strategy.
// ---------------------------------------------------------------------------
class Worker {
public:
    Worker(std::string filter, std::unique_ptr<IStrategy> strat,
           StrategyParams params)
        : filter_(std::move(filter)), strat_(std::move(strat)), params_(params) {}

    void start() {
        try {
            divert_.open(filter_);
            divert_.set_queue_length(2048);
            divert_.set_queue_size  (16 * 1024 * 1024);
            divert_.set_queue_time_ms(2000);
        } catch (const std::exception& e) {
            SGDPI_LOG_WARN("auto_tune: divert open failed: ", e.what());
            return;
        }
        running_ = true;
        th_ = std::thread([this] { run(); });
    }

    void stop() {
        running_ = false;
        divert_.shutdown_recv();
        if (th_.joinable()) th_.join();
        divert_.close();
    }

private:
    void run() {
        std::vector<uint8_t> buf(0x10000);
        while (running_) {
            DivertAddr addr;
            uint32_t  rlen = 0;
            uint32_t  err  = 0;
            if (!divert_.recv(buf.data(), static_cast<uint32_t>(buf.size()),
                              &rlen, &addr, &err)) {
                if (!running_) return;
                continue;
            }
            PacketView v(buf.data(), rlen);
            if (!v.valid() || !v.is_tcp()) {
                divert_.send(buf.data(), rlen, addr);
                continue;
            }
            const ByteView pl = v.payload_view();

            tls::ClientHelloInfo  ti = tls::parse_client_hello(pl);
            http::RequestInfo     hi = http::parse_request(pl);

            PacketContext ctx{ &v, &addr, &ti, &hi };
            OutQueue out;
            if (strat_->apply(ctx, params_, out)) {
                for (auto& p : out) {
                    divert_.send(p.bytes.data(), static_cast<uint32_t>(p.len), p.addr);
                }
            } else {
                divert_.send(buf.data(), rlen, addr);
            }
        }
    }

    std::string                 filter_;
    std::unique_ptr<IStrategy>  strat_;
    StrategyParams              params_;
    Divert                      divert_;
    std::thread                 th_;
    std::atomic<bool>           running_{false};
};

std::string build_filter(const std::string& target_ipv4, uint16_t port) {
    std::ostringstream os;
    os << "outbound and ip and tcp and tcp.PayloadLength > 0 "
       << "and ip.DstAddr == " << target_ipv4
       << " and tcp.DstPort == " << port;
    return os.str();
}

} // namespace

TuneResult run(const TuneOptions& opts) {
    TuneResult r;

    // Resolve target to an IPv4 address so we can scope the filter.
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* ai = nullptr;
    if (::getaddrinfo(opts.target_host.c_str(), nullptr, &hints, &ai) != 0 || !ai) {
        SGDPI_LOG_ERROR("auto_tune: cannot resolve ", opts.target_host);
        return r;
    }
    char ip_buf[INET_ADDRSTRLEN] = {};
    auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
    inet_ntop(AF_INET, &sa->sin_addr, ip_buf, sizeof(ip_buf));
    ::freeaddrinfo(ai);
    const std::string ipv4 = ip_buf;
    const std::string filter = build_filter(ipv4, opts.target_port);

    SGDPI_LOG_INFO("auto_tune: target=", opts.target_host, " (", ipv4, ":",
                   opts.target_port, ")");

    auto candidates = opts.candidates;
    if (candidates.empty()) candidates = all_strategy_names();

    for (const auto& name : candidates) {
        StrategyScore sc;
        sc.name = name;

        SGDPI_LOG_INFO("auto_tune: testing strategy '", name, "'");

        StrategyParams params;
        params.fake_ttl = opts.fake_ttl;

        std::unique_ptr<IStrategy> strat;
        if      (name == "tls-split")   strat = make_tls_split();
        else if (name == "tls-frag")    strat = make_tls_record_frag();
        else if (name == "fake-ttl")    strat = make_fake_ttl();
        else if (name == "http-mangle") strat = make_http_host_mangle();
        else if (name == "disorder")    strat = make_disorder();
        else if (name == "oob")         strat = make_oob();
        else if (name == "md5-opt")     strat = make_md5_fake_option();
        else if (name == "zero-window") strat = make_zero_window();
        else if (name == "wrong-chksum")strat = make_wrong_checksum();
        else { SGDPI_LOG_WARN("  unknown strategy, skipping"); continue; }

        Worker w(filter, std::move(strat), params);
        w.start();
        // Give WinDivert a moment to bind the filter before the first probe.
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        double total_ms = 0.0;
        for (int i = 0; i < std::max(1, opts.attempts_per_strategy); ++i) {
            ++sc.attempts;
            auto t = test_connection(opts.target_host, opts.target_port, opts.timeout);
            if (t.ok) {
                ++sc.successes;
                total_ms += t.first_byte_ms;
                SGDPI_LOG_DEBUG("  attempt ", i + 1, ": OK in ", t.first_byte_ms, " ms");
            } else {
                SGDPI_LOG_DEBUG("  attempt ", i + 1, ": FAIL (", t.error, ")");
            }
        }
        if (sc.successes > 0) sc.avg_first_byte_ms = total_ms / sc.successes;

        w.stop();
        r.scores.push_back(sc);
        SGDPI_LOG_INFO("  -> ", sc.successes, "/", sc.attempts,
                       " success, avg ", sc.avg_first_byte_ms, " ms");
    }

    // Pick best: highest success rate, ties broken by lowest avg latency.
    StrategyScore best;
    best.name = "";
    for (const auto& s : r.scores) {
        if (s.successes == 0) continue;
        if (best.name.empty() ||
            s.success_rate() > best.success_rate() ||
            (s.success_rate() == best.success_rate() &&
             s.avg_first_byte_ms < best.avg_first_byte_ms)) {
            best = s;
        }
    }
    if (!best.name.empty()) {
        r.ok = true;
        r.best_strategy = best.name;
        SGDPI_LOG_INFO("auto_tune: best = '", best.name, "' (",
                       best.successes, "/", best.attempts, ")");
    } else {
        SGDPI_LOG_WARN("auto_tune: no strategy succeeded for ", opts.target_host);
    }

    return r;
}

} // namespace sgdpi::tune
