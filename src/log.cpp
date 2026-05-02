#include "sgdpi/log.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>

namespace sgdpi::log {

namespace {

std::atomic<Level> g_level{Level::Info};
std::mutex         g_mu;
std::ofstream      g_file;
bool               g_have_file = false;

const char* color_for(Level lvl) noexcept {
    // ANSI - Windows 10+ terminal supports these by default.
    switch (lvl) {
        case Level::Trace: return "\x1b[90m";   // gray
        case Level::Debug: return "\x1b[36m";   // cyan
        case Level::Info:  return "\x1b[37m";   // white
        case Level::Warn:  return "\x1b[33m";   // yellow
        case Level::Error: return "\x1b[31m";   // red
        default:           return "";
    }
}
const char* color_reset() noexcept { return "\x1b[0m"; }

void format_timestamp(std::ostream& os) {
    using namespace std::chrono;
    const auto now      = system_clock::now();
    const auto t        = system_clock::to_time_t(now);
    const auto micros   = duration_cast<microseconds>(now.time_since_epoch()).count() % 1'000'000;
    std::tm    tm{};
    localtime_s(&tm, &t);
    os << std::put_time(&tm, "%H:%M:%S") << '.'
       << std::setw(6) << std::setfill('0') << micros;
}

} // namespace

const char* level_name(Level lvl) noexcept {
    switch (lvl) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO ";
        case Level::Warn:  return "WARN ";
        case Level::Error: return "ERROR";
        case Level::Off:   return "OFF  ";
    }
    return "?    ";
}

Level level_from_string(std::string_view s) noexcept {
    if (iequals(s, "trace")) return Level::Trace;
    if (iequals(s, "debug")) return Level::Debug;
    if (iequals(s, "info") ) return Level::Info;
    if (iequals(s, "warn") ) return Level::Warn;
    if (iequals(s, "error")) return Level::Error;
    if (iequals(s, "off")  ) return Level::Off;
    return Level::Info;
}

void set_level(Level lvl) noexcept { g_level.store(lvl, std::memory_order_relaxed); }
Level get_level() noexcept         { return g_level.load(std::memory_order_relaxed); }

void set_file(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_file.is_open()) g_file.close();
    g_have_file = false;
    if (!path.empty()) {
        g_file.open(path, std::ios::app);
        g_have_file = g_file.is_open();
    }
}

void emit(Level lvl, std::string_view msg) {
    std::lock_guard<std::mutex> lk(g_mu);

    auto& out = (lvl >= Level::Warn) ? std::cerr : std::cout;
    out << color_for(lvl);
    format_timestamp(out);
    out << " [" << level_name(lvl) << "] " << msg << color_reset() << '\n';
    out.flush();

    if (g_have_file) {
        format_timestamp(g_file);
        g_file << " [" << level_name(lvl) << "] " << msg << '\n';
        g_file.flush();
    }
}

} // namespace sgdpi::log
