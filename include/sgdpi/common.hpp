// SiktirGitDPI - common types, byte order, span, helpers.
//
// Header-only utilities used across the project. Kept small on purpose -
// anything that needs a translation unit goes elsewhere.

#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

namespace sgdpi {

using std::int8_t;
using std::int16_t;
using std::int32_t;
using std::int64_t;
using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::size_t;

using Clock     = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Millis    = std::chrono::milliseconds;
using Micros    = std::chrono::microseconds;

// ---------------------------------------------------------------------------
// Lightweight non-owning byte view (we target C++17 - no std::span yet).
// ---------------------------------------------------------------------------
class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const uint8_t* p, size_t n) noexcept : p_(p), n_(n) {}

    [[nodiscard]] constexpr const uint8_t* data() const noexcept { return p_; }
    [[nodiscard]] constexpr size_t         size() const noexcept { return n_; }
    [[nodiscard]] constexpr bool           empty() const noexcept { return n_ == 0; }

    [[nodiscard]] constexpr uint8_t operator[](size_t i) const noexcept { return p_[i]; }

    [[nodiscard]] constexpr ByteView subview(size_t off, size_t n) const noexcept {
        return (off > n_) ? ByteView{} : ByteView{p_ + off, std::min(n, n_ - off)};
    }
    [[nodiscard]] constexpr ByteView drop(size_t n) const noexcept {
        return subview(n, n_ > n ? n_ - n : 0);
    }
    [[nodiscard]] constexpr ByteView take(size_t n) const noexcept {
        return subview(0, n);
    }

private:
    const uint8_t* p_ = nullptr;
    size_t         n_ = 0;
};

class ByteSpan {
public:
    constexpr ByteSpan() noexcept = default;
    constexpr ByteSpan(uint8_t* p, size_t n) noexcept : p_(p), n_(n) {}

    [[nodiscard]] constexpr uint8_t*  data() const noexcept { return p_; }
    [[nodiscard]] constexpr size_t    size() const noexcept { return n_; }
    [[nodiscard]] constexpr bool      empty() const noexcept { return n_ == 0; }
    [[nodiscard]] constexpr uint8_t&  operator[](size_t i) const noexcept { return p_[i]; }

    [[nodiscard]] constexpr ByteSpan subspan(size_t off, size_t n) const noexcept {
        return (off > n_) ? ByteSpan{} : ByteSpan{p_ + off, std::min(n, n_ - off)};
    }
    [[nodiscard]] constexpr ByteView view() const noexcept { return ByteView{p_, n_}; }

private:
    uint8_t* p_ = nullptr;
    size_t   n_ = 0;
};

// ---------------------------------------------------------------------------
// Byte order. Network = big-endian. We don't pull in winsock here on purpose.
// ---------------------------------------------------------------------------
[[nodiscard]] constexpr uint16_t bswap16(uint16_t v) noexcept {
    return static_cast<uint16_t>((v << 8) | (v >> 8));
}
[[nodiscard]] constexpr uint32_t bswap32(uint32_t v) noexcept {
    return  ((v & 0x000000FFu) << 24)
          | ((v & 0x0000FF00u) <<  8)
          | ((v & 0x00FF0000u) >>  8)
          | ((v & 0xFF000000u) >> 24);
}

// We assume little-endian host (every supported Windows arch is LE).
[[nodiscard]] constexpr uint16_t hton16(uint16_t v) noexcept { return bswap16(v); }
[[nodiscard]] constexpr uint32_t hton32(uint32_t v) noexcept { return bswap32(v); }
[[nodiscard]] constexpr uint16_t ntoh16(uint16_t v) noexcept { return bswap16(v); }
[[nodiscard]] constexpr uint32_t ntoh32(uint32_t v) noexcept { return bswap32(v); }

// Read big-endian integer from a raw pointer (no alignment requirement).
[[nodiscard]] inline uint16_t rd_be16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0]) << 8 | static_cast<uint16_t>(p[1]);
}
[[nodiscard]] inline uint32_t rd_be24(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 16)
         | (static_cast<uint32_t>(p[1]) <<  8)
         |  static_cast<uint32_t>(p[2]);
}
[[nodiscard]] inline uint32_t rd_be32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) <<  8)
         |  static_cast<uint32_t>(p[3]);
}

inline void wr_be16(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}
inline void wr_be32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >>  8);
    p[3] = static_cast<uint8_t>(v);
}

// ---------------------------------------------------------------------------
// Misc.
// ---------------------------------------------------------------------------
[[nodiscard]] inline std::string trim(std::string_view s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
    return std::string{s.substr(a, b - a)};
}

[[nodiscard]] inline bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        const auto da = (ca >= 'A' && ca <= 'Z') ? ca + 32 : ca;
        const auto db = (cb >= 'A' && cb <= 'Z') ? cb + 32 : cb;
        if (da != db) return false;
    }
    return true;
}

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Compile-time assertions about platform expectations.
static_assert(sizeof(uint8_t)  == 1);
static_assert(sizeof(uint16_t) == 2);
static_assert(sizeof(uint32_t) == 4);

} // namespace sgdpi
