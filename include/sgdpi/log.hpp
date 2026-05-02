// Thread-safe logging with severity levels and a single global sink.
//
// We keep this dead simple: lock + ostream write. Throughput from the engine
// goes through Stats, not the log, so contention here doesn't matter.

#pragma once

#include "sgdpi/common.hpp"

#include <iosfwd>
#include <sstream>

namespace sgdpi::log {

enum class Level : int {
    Trace = 0,
    Debug = 1,
    Info  = 2,
    Warn  = 3,
    Error = 4,
    Off   = 5,
};

[[nodiscard]] const char* level_name(Level lvl) noexcept;
[[nodiscard]] Level       level_from_string(std::string_view s) noexcept;

void set_level(Level lvl) noexcept;
[[nodiscard]] Level get_level() noexcept;

// Call once at startup if you want logs duplicated to a file.
// Pass empty path to disable file logging again.
void set_file(const std::string& path);

// Internal - prefer the macros below.
void emit(Level lvl, std::string_view msg);

// Variadic stream-style emit. The whole expression is evaluated only when the
// level is enabled.
template <typename... Args>
inline void log(Level lvl, Args&&... args) {
    if (static_cast<int>(lvl) < static_cast<int>(get_level())) return;
    std::ostringstream os;
    (os << ... << std::forward<Args>(args));
    emit(lvl, os.str());
}

} // namespace sgdpi::log

#define SGDPI_LOG_TRACE(...) ::sgdpi::log::log(::sgdpi::log::Level::Trace, __VA_ARGS__)
#define SGDPI_LOG_DEBUG(...) ::sgdpi::log::log(::sgdpi::log::Level::Debug, __VA_ARGS__)
#define SGDPI_LOG_INFO(...)  ::sgdpi::log::log(::sgdpi::log::Level::Info , __VA_ARGS__)
#define SGDPI_LOG_WARN(...)  ::sgdpi::log::log(::sgdpi::log::Level::Warn , __VA_ARGS__)
#define SGDPI_LOG_ERROR(...) ::sgdpi::log::log(::sgdpi::log::Level::Error, __VA_ARGS__)
