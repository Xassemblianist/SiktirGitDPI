// HTTP/1.x request line + Host header parser. Used both to detect HTTP
// traffic (so we can apply HTTP-specific strategies) and to mangle the Host
// header in place.
//
// We don't try to be a general HTTP parser - just enough to find the method,
// the request-target, and the Host header value.

#pragma once

#include "sgdpi/common.hpp"

#include <string_view>

namespace sgdpi::http {

struct RequestInfo {
    bool             present = false;
    std::string_view method;          // "GET", "POST", ...
    std::string_view target;          // "/path?q=1"

    // Offsets into the TCP payload.
    size_t           method_off = 0;
    size_t           method_len = 0;
    size_t           host_header_off  = 0;  // start of "Host" or "host" or "HoSt" etc.
    size_t           host_header_len  = 0;  // length of just the field-name token "Host"
    size_t           host_value_off   = 0;  // start of the value (after colon and OWS)
    size_t           host_value_len   = 0;
    std::string_view hostname;              // points into payload, may include port
};

// Parse an HTTP request from the start of a TCP payload. Returns present=false
// if it doesn't look like one.
[[nodiscard]] RequestInfo parse_request(ByteView tcp_payload) noexcept;

// Quick sniff: does this look like an HTTP request (method + space + path)?
[[nodiscard]] bool looks_like_http(ByteView tcp_payload) noexcept;

} // namespace sgdpi::http
