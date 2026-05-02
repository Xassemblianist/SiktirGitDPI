#include "sgdpi/ttl_probe.hpp"
#include "sgdpi/log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <cstring>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace sgdpi::ttl {

namespace {

bool resolve_ipv4(const std::string& host, IN_ADDR* out, std::string* pretty) noexcept {
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    auto* sa = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    *out = sa->sin_addr;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
    if (pretty) *pretty = buf;
    ::freeaddrinfo(res);
    return true;
}

bool probe_hop(HANDLE icmp, IN_ADDR target, int ttl, int timeout_ms,
               bool* reached) noexcept {
    *reached = false;
    constexpr DWORD reply_size =
        sizeof(ICMP_ECHO_REPLY) + 32 + 8;       // base + payload + RFC slack
    BYTE reply_buf[reply_size]{};
    BYTE send_data[32]{};

    IP_OPTION_INFORMATION opts{};
    opts.Ttl = static_cast<UCHAR>(ttl);

    const DWORD n = ::IcmpSendEcho2(
        icmp,
        nullptr, nullptr, nullptr,
        target.s_addr,
        send_data, sizeof(send_data),
        &opts,
        reply_buf, reply_size,
        static_cast<DWORD>(timeout_ms));

    if (n == 0) {
        // No reply or hop didn't respond. Not necessarily fatal.
        return false;
    }

    auto* rep = reinterpret_cast<ICMP_ECHO_REPLY*>(reply_buf);
    // Status IP_SUCCESS (0) means we reached the destination.
    if (rep->Status == 0) {
        *reached = true;
        return true;
    }
    // IP_TTL_EXPIRED_TRANSIT (11013) is the expected intermediate response.
    return true;
}

} // namespace

ProbeResult discover(const std::string& host, int max_hops, int per_hop_timeout_ms) noexcept {
    ProbeResult r;

    IN_ADDR addr{};
    if (!resolve_ipv4(host, &addr, &r.target_ipv4)) {
        SGDPI_LOG_WARN("ttl_probe: cannot resolve ", host);
        return r;
    }

    HANDLE icmp = ::IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        SGDPI_LOG_WARN("ttl_probe: IcmpCreateFile failed");
        return r;
    }

    int hops = 0;
    for (int t = 1; t <= max_hops; ++t) {
        bool reached = false;
        const bool any = probe_hop(icmp, addr, t, per_hop_timeout_ms, &reached);
        if (any && reached) {
            hops = t;
            break;
        }
        // Continue even if a hop didn't answer - some routers drop ICMP.
    }

    ::IcmpCloseHandle(icmp);

    if (hops == 0) {
        SGDPI_LOG_WARN("ttl_probe: target ", host, " (", r.target_ipv4,
                       ") not reachable within ", max_hops, " hops");
        return r;
    }

    r.ok                  = true;
    r.hops_to_target      = hops;
    // Heuristic: DPI sits a few hops in. Picking floor(hops/2) keeps the
    // fake within the operator's network without reaching the destination.
    r.suggested_fake_ttl  = std::max(2, hops / 2);

    SGDPI_LOG_INFO("ttl_probe: ", host, " (", r.target_ipv4, ") = ",
                   hops, " hops, fake TTL = ", r.suggested_fake_ttl);
    return r;
}

} // namespace sgdpi::ttl
