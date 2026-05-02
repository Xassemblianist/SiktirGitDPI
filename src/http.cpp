#include "sgdpi/http.hpp"

namespace sgdpi::http {

namespace {

// Methods we care about. We only do a cheap prefix check before trusting it.
constexpr std::string_view kMethods[] = {
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
    "CONNECT ", "PATCH ", "TRACE "
};

inline bool starts_with(ByteView v, std::string_view s) noexcept {
    if (v.size() < s.size()) return false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (v[i] != static_cast<uint8_t>(s[i])) return false;
    }
    return true;
}

// Find a CRLF starting at `from`; returns offset of the first byte of CRLF
// or v.size() if not found.
size_t find_crlf(ByteView v, size_t from) noexcept {
    for (size_t i = from; i + 1 < v.size(); ++i) {
        if (v[i] == '\r' && v[i + 1] == '\n') return i;
    }
    return v.size();
}

inline bool is_token_char(uint8_t c) noexcept {
    // RFC 7230 token: any visible ASCII char minus separators.
    if (c <= 0x20 || c >= 0x7F) return false;
    switch (c) {
        case '(': case ')': case ',': case '/': case ':':
        case ';': case '<': case '=': case '>': case '?':
        case '@': case '[': case '\\': case ']': case '{':
        case '}': case '"':
            return false;
    }
    return true;
}

} // namespace

bool looks_like_http(ByteView v) noexcept {
    for (const auto& m : kMethods) if (starts_with(v, m)) return true;
    return false;
}

RequestInfo parse_request(ByteView v) noexcept {
    RequestInfo r;
    if (!looks_like_http(v)) return r;

    // ---- request-line ------------------------------------------------------
    size_t sp1 = 0;
    while (sp1 < v.size() && v[sp1] != ' ') ++sp1;
    if (sp1 == v.size()) return r;
    r.method = std::string_view(reinterpret_cast<const char*>(v.data()), sp1);
    r.method_off = 0;
    r.method_len = sp1;

    size_t target_start = sp1 + 1;
    size_t sp2 = target_start;
    while (sp2 < v.size() && v[sp2] != ' ') ++sp2;
    if (sp2 == v.size()) return r;
    r.target = std::string_view(
        reinterpret_cast<const char*>(v.data() + target_start),
        sp2 - target_start);

    size_t line_end = find_crlf(v, sp2);
    if (line_end == v.size()) return r;
    size_t pos = line_end + 2;

    // ---- headers -----------------------------------------------------------
    while (pos < v.size()) {
        // End of headers?
        if (pos + 1 < v.size() && v[pos] == '\r' && v[pos + 1] == '\n') break;

        // Token (field name).
        const size_t name_start = pos;
        bool bad_token = false;
        while (pos < v.size() && v[pos] != ':' && v[pos] != '\r') {
            if (!is_token_char(v[pos])) {
                pos = find_crlf(v, pos) + 2;
                bad_token = true;
                break;
            }
            ++pos;
        }
        if (bad_token) continue;
        if (pos >= v.size() || v[pos] != ':') {
            pos = find_crlf(v, pos) + 2;
            continue;
        }
        const size_t name_end = pos;  // exclusive
        ++pos; // skip ':'
        // OWS
        while (pos < v.size() && (v[pos] == ' ' || v[pos] == '\t')) ++pos;
        const size_t val_start = pos;
        const size_t eol       = find_crlf(v, pos);
        if (eol == v.size()) return r; // truncated
        size_t val_end = eol;
        // Trim trailing OWS.
        while (val_end > val_start && (v[val_end - 1] == ' ' || v[val_end - 1] == '\t')) --val_end;

        const std::string_view name(reinterpret_cast<const char*>(v.data() + name_start),
                                    name_end - name_start);
        if (iequals(name, "Host")) {
            r.host_header_off = name_start;
            r.host_header_len = name_end - name_start;
            r.host_value_off  = val_start;
            r.host_value_len  = val_end - val_start;
            r.hostname = std::string_view(
                reinterpret_cast<const char*>(v.data() + val_start),
                val_end - val_start);
            r.present = true;
            return r;
        }
        pos = eol + 2;
    }

    // No Host header, but still a valid-looking request.
    r.present = true;
    return r;
}

} // namespace sgdpi::http
