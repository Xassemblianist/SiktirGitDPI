#include "test_main.hpp"
#include "sgdpi/http.hpp"

#include <string>

using namespace sgdpi;

namespace {

ByteView make_view(const std::string& s) {
    return ByteView{reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

} // namespace

TEST(http, sniffs_methods) {
    EXPECT_TRUE (http::looks_like_http(make_view("GET / HTTP/1.1\r\n")));
    EXPECT_TRUE (http::looks_like_http(make_view("POST /x HTTP/1.1\r\n")));
    EXPECT_TRUE (http::looks_like_http(make_view("CONNECT host:443 HTTP/1.1\r\n")));
    EXPECT_FALSE(http::looks_like_http(make_view("\x16\x03\x01...")));
    EXPECT_FALSE(http::looks_like_http(make_view("HELLO world")));
}

TEST(http, parses_simple_get) {
    const std::string req =
        "GET /path?q=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: x\r\n"
        "\r\n";
    auto info = http::parse_request(make_view(req));
    EXPECT_TRUE(info.present);
    EXPECT_EQ(std::string(info.method),  std::string("GET"));
    EXPECT_EQ(std::string(info.target),  std::string("/path?q=1"));
    EXPECT_EQ(std::string(info.hostname),std::string("example.com"));
}

TEST(http, finds_host_case_insensitive) {
    const std::string req =
        "GET / HTTP/1.1\r\n"
        "User-Agent: x\r\n"
        "hOsT:    foo.bar.com   \r\n"   // weird case + extra whitespace
        "\r\n";
    auto info = http::parse_request(make_view(req));
    EXPECT_TRUE(info.present);
    EXPECT_EQ(std::string(info.hostname), std::string("foo.bar.com"));
    EXPECT_EQ(info.host_header_len, size_t{4});
}

TEST(http, missing_host_header) {
    const std::string req =
        "GET / HTTP/1.1\r\n"
        "User-Agent: x\r\n"
        "\r\n";
    auto info = http::parse_request(make_view(req));
    EXPECT_TRUE(info.present);          // still a valid request
    EXPECT_EQ(info.host_header_len, size_t{0});
    EXPECT_TRUE(info.hostname.empty());
}

TEST(http, garbage_payload_rejected) {
    const std::string req = "this is not http at all\r\n";
    auto info = http::parse_request(make_view(req));
    EXPECT_FALSE(info.present);
}

TEST(http, host_offsets_are_correct) {
    const std::string req =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";
    auto info = http::parse_request(make_view(req));
    EXPECT_TRUE(info.present);

    // Verify the recorded offsets actually point at the right substrings.
    const auto* p = reinterpret_cast<const char*>(req.data());
    EXPECT_EQ(std::string(p + info.host_header_off, info.host_header_len),
              std::string("Host"));
    EXPECT_EQ(std::string(p + info.host_value_off,  info.host_value_len),
              std::string("example.com"));
}
