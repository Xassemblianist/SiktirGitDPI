// RAII C++ wrapper around the WinDivert C API.
//
// Wraps:
//   - Handle lifecycle (open / close / shutdown)
//   - Recv with WINDIVERT_ADDRESS
//   - Send (with optional batch)
//   - SetParam / GetParam
//   - HelperCalcChecksums (used as a redundant safety net after our own)
//
// We deliberately do NOT include <windivert.h> from this header: instead we
// forward-declare the address struct and an opaque handle so the rest of the
// project can include this header without dragging Win32 macros around.

#pragma once

#include "sgdpi/common.hpp"

#include <memory>

namespace sgdpi {

enum class DivertLayer : int {
    Network        = 0, // intercepts IPv4/IPv6 packets at the network layer
    NetworkForward = 1, // forwarded packets (router scenarios)
    Flow           = 2, // flow events (no packet payload)
    Socket         = 3, // socket events
    Reflect        = 4, // self-reflection
};

enum class DivertFlag : uint64_t {
    None      = 0,
    Sniff     = 0x0001, // copy packets, do not divert
    Drop      = 0x0002, // drop matched packets
    RecvOnly  = 0x0004,
    SendOnly  = 0x0008,
    NoInstall = 0x0010, // do not auto-install the driver
    Fragments = 0x0020, // capture IP fragments
};
constexpr DivertFlag operator|(DivertFlag a, DivertFlag b) {
    return static_cast<DivertFlag>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

// Opaque holder; matches the size of WINDIVERT_ADDRESS (80 bytes on x64).
// We deliberately do NOT expose a typed pointer here - WinDivert's address
// struct is an anonymous typedef and cannot be forward-declared. Internal
// callers in divert.cpp / dns_redirect.cpp / auto_tune.cpp reinterpret this
// buffer when they need to read individual fields.
struct DivertAddr {
    alignas(8) uint8_t bytes[80] = {};

    [[nodiscard]] bool is_outbound() const noexcept;
    [[nodiscard]] bool is_loopback() const noexcept;
    [[nodiscard]] bool is_ipv6()     const noexcept;
    [[nodiscard]] uint32_t if_idx()  const noexcept;
    [[nodiscard]] uint32_t sub_idx() const noexcept;

    void mark_impostor()    noexcept;   // set Impostor=1 - tells WinDivert this packet is synthetic
    void clear_checksums()  noexcept;   // clear cached checksum flags so the kernel recomputes
};

// Thin wrapper around the WinDivert HANDLE. Move-only.
class Divert {
public:
    Divert() noexcept = default;
    ~Divert();

    Divert(const Divert&)            = delete;
    Divert& operator=(const Divert&) = delete;

    Divert(Divert&& other) noexcept;
    Divert& operator=(Divert&& other) noexcept;

    // Open a divert handle. Throws sgdpi::Error on failure.
    void open(const std::string& filter,
              DivertLayer        layer    = DivertLayer::Network,
              int16_t            priority = 0,
              DivertFlag         flags    = DivertFlag::None);

    void close() noexcept;
    [[nodiscard]] bool is_open() const noexcept { return handle_ != nullptr; }

    // Receive one packet. Returns true on success. On a recoverable failure
    // (e.g. shutdown) returns false and *err is set if non-null.
    [[nodiscard]] bool recv(uint8_t* buf, uint32_t buf_len, uint32_t* recv_len,
                            DivertAddr* addr, uint32_t* err = nullptr);

    // Send one packet. Returns true on success. Always sets *send_len if non-null.
    bool send(const uint8_t* buf, uint32_t buf_len, const DivertAddr& addr,
              uint32_t* send_len = nullptr) noexcept;

    // Send a batch (up to ~0xFF packets). All addrs must come from a single
    // recv batch or be synthesised consistently.
    bool send_ex(const uint8_t* buf, uint32_t buf_len, uint32_t* send_len,
                 const DivertAddr* addrs, size_t addr_count) noexcept;

    // Cleanly stop a blocked recv() in another thread.
    void shutdown_recv() noexcept;
    void shutdown_send() noexcept;

    // Bulk parameter knobs.
    void set_queue_length (uint64_t n);   // packets queued in driver
    void set_queue_size   (uint64_t n);   // bytes queued in driver
    void set_queue_time_ms(uint64_t ms);  // packet timeout

    // Calls WinDivertHelperCalcChecksums - a fallback to fix up checksums on
    // arbitrary packets. We recompute ourselves in PacketBuilder, but using
    // this is safe and robust if you didn't.
    static bool helper_recompute(uint8_t* pkt, uint32_t len, DivertAddr* addr) noexcept;

private:
    void* handle_ = nullptr;  // HANDLE
};

} // namespace sgdpi
