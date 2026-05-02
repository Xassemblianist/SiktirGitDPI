// Minimal header-only test framework. We don't pull in gtest/catch because
// (a) we want to compile from any toolchain and (b) WinDivert isn't required
// to test the parsers, so we keep dependencies to zero.
//
// Usage:
//
//   #include "test_main.hpp"
//   TEST(group, name) {
//       EXPECT_EQ(1 + 1, 2);
//       EXPECT_TRUE(some_predicate());
//   }
//   int main() { return ::sgdpi_tests::run(); }

#pragma once

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace sgdpi_tests {

// Plain function pointer - we don't need std::function's type erasure here
// and avoiding it sidesteps subtle MinGW static-destruction ordering bugs.
using TestFn = void (*)();

struct Case {
    std::string group;
    std::string name;
    TestFn      fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}

struct Registrar {
    Registrar(const char* g, const char* n, TestFn f) {
        registry().push_back({g, n, f});
    }
};

struct Failure : std::exception {
    std::string msg;
    explicit Failure(std::string s) : msg(std::move(s)) {}
    const char* what() const noexcept override { return msg.c_str(); }
};

inline void fail(const std::string& file, int line, const std::string& expr,
                 const std::string& detail = {}) {
    std::ostringstream os;
    os << file << ":" << line << ": " << expr;
    if (!detail.empty()) os << "\n    " << detail;
    throw Failure(os.str());
}

inline int run() {
    int passed = 0, failed = 0;
    std::string last_group;
    auto& reg = registry();
    for (size_t i = 0; i < reg.size(); ++i) {
        const auto& c = reg[i];
        if (c.group != last_group) {
            std::cout << "\n[" << c.group << "]\n";
            last_group = c.group;
        }
        std::cout << "  " << c.name << " ... " << std::flush;
        try {
            c.fn();
            std::cout << "ok\n" << std::flush;
            ++passed;
        } catch (const Failure& f) {
            std::cout << "FAIL\n      " << f.msg << "\n" << std::flush;
            ++failed;
        } catch (const std::exception& e) {
            std::cout << "EXCEPTION\n      " << e.what() << "\n" << std::flush;
            ++failed;
        } catch (...) {
            std::cout << "UNKNOWN_EXCEPTION\n" << std::flush;
            ++failed;
        }
    }
    std::cout << "\n" << passed << " passed, " << failed << " failed.\n" << std::flush;
    std::cerr.flush();
    return failed == 0 ? 0 : 1;
}

} // namespace sgdpi_tests

#define SGDPI_CONCAT_(a, b) a##b
#define SGDPI_CONCAT(a, b)  SGDPI_CONCAT_(a, b)

#define TEST(group, name)                                                       \
    static void SGDPI_CONCAT(sgdpi_test_, __LINE__)();                          \
    static ::sgdpi_tests::Registrar SGDPI_CONCAT(sgdpi_reg_, __LINE__){         \
        #group, #name, &SGDPI_CONCAT(sgdpi_test_, __LINE__)};                   \
    static void SGDPI_CONCAT(sgdpi_test_, __LINE__)()

#define EXPECT_TRUE(expr) do {                                                  \
    if (!(expr)) ::sgdpi_tests::fail(__FILE__, __LINE__, "EXPECT_TRUE("#expr")"); \
} while (0)

#define EXPECT_FALSE(expr) do {                                                 \
    if ((expr)) ::sgdpi_tests::fail(__FILE__, __LINE__, "EXPECT_FALSE("#expr")"); \
} while (0)

#define EXPECT_EQ(a, b) do {                                                    \
    auto _a = (a); auto _b = (b);                                               \
    if (!(_a == _b)) {                                                          \
        std::ostringstream _os;                                                 \
        _os << "got=" << _a << " expected=" << _b;                              \
        ::sgdpi_tests::fail(__FILE__, __LINE__, "EXPECT_EQ("#a", "#b")", _os.str()); \
    }                                                                           \
} while (0)

#define EXPECT_NE(a, b) do {                                                    \
    auto _a = (a); auto _b = (b);                                               \
    if (!(_a != _b)) {                                                          \
        ::sgdpi_tests::fail(__FILE__, __LINE__, "EXPECT_NE("#a", "#b")");       \
    }                                                                           \
} while (0)

#define EXPECT_GE(a, b) do {                                                    \
    auto _a = (a); auto _b = (b);                                               \
    if (!(_a >= _b)) {                                                          \
        std::ostringstream _os;                                                 \
        _os << "got=" << _a << " expected>=" << _b;                             \
        ::sgdpi_tests::fail(__FILE__, __LINE__, "EXPECT_GE("#a", "#b")", _os.str()); \
    }                                                                           \
} while (0)

#define EXPECT_LE(a, b) do {                                                    \
    auto _a = (a); auto _b = (b);                                               \
    if (!(_a <= _b)) {                                                          \
        std::ostringstream _os;                                                 \
        _os << "got=" << _a << " expected<=" << _b;                             \
        ::sgdpi_tests::fail(__FILE__, __LINE__, "EXPECT_LE("#a", "#b")", _os.str()); \
    }                                                                           \
} while (0)
