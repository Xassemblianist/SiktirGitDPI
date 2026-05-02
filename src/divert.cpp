#include "sgdpi/divert.hpp"
#include "sgdpi/log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windivert.h>

#include <cassert>
#include <cstring>

namespace sgdpi {

static_assert(sizeof(WINDIVERT_ADDRESS) <= sizeof(DivertAddr::bytes),
              "DivertAddr buffer too small for WINDIVERT_ADDRESS");

namespace {
inline       WINDIVERT_ADDRESS* raw(      DivertAddr& a) noexcept { return reinterpret_cast<WINDIVERT_ADDRESS*>(a.bytes); }
inline const WINDIVERT_ADDRESS* raw(const DivertAddr& a) noexcept { return reinterpret_cast<const WINDIVERT_ADDRESS*>(a.bytes); }
} // namespace

bool DivertAddr::is_outbound() const noexcept { return raw(*this)->Outbound != 0; }
bool DivertAddr::is_loopback() const noexcept { return raw(*this)->Loopback != 0; }
bool DivertAddr::is_ipv6()     const noexcept { return raw(*this)->IPv6 != 0; }
uint32_t DivertAddr::if_idx()  const noexcept { return raw(*this)->Network.IfIdx;    }
uint32_t DivertAddr::sub_idx() const noexcept { return raw(*this)->Network.SubIfIdx; }

void DivertAddr::mark_impostor() noexcept {
    raw(*this)->Impostor = 1;
}
void DivertAddr::clear_checksums() noexcept {
    raw(*this)->IPChecksum  = 0;
    raw(*this)->TCPChecksum = 0;
    raw(*this)->UDPChecksum = 0;
}

// ---------------------------------------------------------------------------
// Divert
// ---------------------------------------------------------------------------
Divert::~Divert() { close(); }

Divert::Divert(Divert&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}
Divert& Divert::operator=(Divert&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void Divert::open(const std::string& filter, DivertLayer layer, int16_t priority,
                  DivertFlag flags) {
    HANDLE h = ::WinDivertOpen(
        filter.c_str(),
        static_cast<WINDIVERT_LAYER>(layer),
        priority,
        static_cast<UINT64>(flags));
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        std::string hint;
        switch (err) {
            case 2:    hint = " (WinDivert.dll not found - place next to sgdpi.exe)"; break;
            case 5:    hint = " (access denied - run as Administrator)"; break;
            case 87:   hint = " (bad filter expression)"; break;
            case 577:  hint = " (driver not signed - disable driver signature enforcement)"; break;
            case 1275: hint = " (driver blocked by policy)"; break;
            case 1753: hint = " (WinDivert64.sys not found - place next to sgdpi.exe)"; break;
            default:   break;
        }
        throw Error("WinDivertOpen failed: error=" + std::to_string(err) +
                    hint + " filter=" + filter);
    }
    handle_ = h;
    SGDPI_LOG_DEBUG("WinDivert opened: filter='", filter, "' priority=", priority);
}

void Divert::close() noexcept {
    if (handle_) {
        ::WinDivertClose(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
}

bool Divert::recv(uint8_t* buf, uint32_t buf_len, uint32_t* recv_len,
                  DivertAddr* addr, uint32_t* err) {
    UINT recv = 0;
    const BOOL ok = ::WinDivertRecv(
        static_cast<HANDLE>(handle_),
        buf, buf_len, &recv,
        addr ? raw(*addr) : nullptr);
    if (recv_len) *recv_len = recv;
    if (!ok) {
        const DWORD e = ::GetLastError();
        if (err) *err = static_cast<uint32_t>(e);
        return false;
    }
    return true;
}

bool Divert::send(const uint8_t* buf, uint32_t buf_len, const DivertAddr& addr,
                  uint32_t* send_len) noexcept {
    UINT sent = 0;
    const BOOL ok = ::WinDivertSend(
        static_cast<HANDLE>(handle_),
        buf, buf_len, &sent, raw(addr));
    if (send_len) *send_len = sent;
    return ok != FALSE;
}

bool Divert::send_ex(const uint8_t* buf, uint32_t buf_len, uint32_t* send_len,
                     const DivertAddr* addrs, size_t addr_count) noexcept {
    UINT sent = 0;
    const BOOL ok = ::WinDivertSendEx(
        static_cast<HANDLE>(handle_),
        buf, buf_len, &sent, 0,
        addrs ? raw(*addrs) : nullptr,
        static_cast<UINT>(addr_count * sizeof(WINDIVERT_ADDRESS)),
        nullptr);
    if (send_len) *send_len = sent;
    return ok != FALSE;
}

void Divert::shutdown_recv() noexcept {
    if (handle_) ::WinDivertShutdown(static_cast<HANDLE>(handle_), WINDIVERT_SHUTDOWN_RECV);
}
void Divert::shutdown_send() noexcept {
    if (handle_) ::WinDivertShutdown(static_cast<HANDLE>(handle_), WINDIVERT_SHUTDOWN_SEND);
}

void Divert::set_queue_length(uint64_t n) {
    if (!::WinDivertSetParam(static_cast<HANDLE>(handle_), WINDIVERT_PARAM_QUEUE_LENGTH, n))
        SGDPI_LOG_WARN("Failed to set QUEUE_LENGTH=", n);
}
void Divert::set_queue_size(uint64_t n) {
    if (!::WinDivertSetParam(static_cast<HANDLE>(handle_), WINDIVERT_PARAM_QUEUE_SIZE, n))
        SGDPI_LOG_WARN("Failed to set QUEUE_SIZE=", n);
}
void Divert::set_queue_time_ms(uint64_t ms) {
    if (!::WinDivertSetParam(static_cast<HANDLE>(handle_), WINDIVERT_PARAM_QUEUE_TIME, ms))
        SGDPI_LOG_WARN("Failed to set QUEUE_TIME=", ms);
}

bool Divert::helper_recompute(uint8_t* pkt, uint32_t len, DivertAddr* addr) noexcept {
    return ::WinDivertHelperCalcChecksums(pkt, len, addr ? raw(*addr) : nullptr, 0) != FALSE;
}

} // namespace sgdpi
