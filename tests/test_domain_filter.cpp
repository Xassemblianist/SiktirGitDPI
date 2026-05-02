#include "test_main.hpp"
#include "sgdpi/domain_filter.hpp"

using namespace sgdpi;

TEST(domain_filter, off_passes_everything) {
    DomainFilter f;
    f.set_mode(FilterMode::Off);
    EXPECT_TRUE(f.should_apply("youtube.com"));
    EXPECT_TRUE(f.should_apply("anything.example.com"));
}

TEST(domain_filter, allowlist_exact) {
    DomainFilter f;
    f.set_mode(FilterMode::Allowlist);
    f.add_pattern("youtube.com");
    EXPECT_TRUE (f.should_apply("youtube.com"));
    EXPECT_TRUE (f.should_apply("YouTube.Com"));     // case-insensitive
    EXPECT_FALSE(f.should_apply("www.youtube.com")); // exact only
    EXPECT_FALSE(f.should_apply("evil.com"));
}

TEST(domain_filter, allowlist_wildcard) {
    DomainFilter f;
    f.set_mode(FilterMode::Allowlist);
    f.add_pattern("*.googlevideo.com");
    EXPECT_FALSE(f.should_apply("googlevideo.com"));         // wildcard skips bare
    EXPECT_TRUE (f.should_apply("a.googlevideo.com"));
    EXPECT_TRUE (f.should_apply("foo.bar.googlevideo.com"));
    EXPECT_FALSE(f.should_apply("notgooglevideo.com"));       // boundary check
    EXPECT_FALSE(f.should_apply("x-googlevideo.com"));
}

TEST(domain_filter, allowlist_root_suffix) {
    DomainFilter f;
    f.set_mode(FilterMode::Allowlist);
    f.add_pattern(".example.com");
    EXPECT_TRUE (f.should_apply("example.com"));
    EXPECT_TRUE (f.should_apply("a.example.com"));
    EXPECT_TRUE (f.should_apply("a.b.example.com"));
    EXPECT_FALSE(f.should_apply("evil-example.com"));
    EXPECT_FALSE(f.should_apply("example.org"));
}

TEST(domain_filter, blocklist_inverts) {
    DomainFilter f;
    f.set_mode(FilterMode::Blocklist);
    f.add_pattern(".banking.com.tr");
    // Banks are blocked from being mangled (we don't want to break TLS).
    EXPECT_FALSE(f.should_apply("isbank.banking.com.tr"));
    EXPECT_FALSE(f.should_apply("banking.com.tr"));
    EXPECT_TRUE (f.should_apply("youtube.com"));
}

TEST(domain_filter, host_with_port_stripped) {
    DomainFilter f;
    f.set_mode(FilterMode::Allowlist);
    f.add_pattern("example.com");
    EXPECT_TRUE(f.should_apply("example.com:443"));
    EXPECT_TRUE(f.should_apply("example.com:80"));
}

TEST(domain_filter, allowlist_no_match_when_no_hostname) {
    // Defensive default: an empty/missing hostname is "not in allowlist".
    // (engine.cpp uses this fact directly to decide whether to pass through.)
    DomainFilter f;
    f.set_mode(FilterMode::Allowlist);
    f.add_pattern("youtube.com");
    EXPECT_FALSE(f.should_apply(""));
}

TEST(domain_filter, multiple_pattern_kinds) {
    DomainFilter f;
    f.set_mode(FilterMode::Allowlist);
    f.add_pattern("foo.com");          // exact
    f.add_pattern("*.bar.com");        // strict subdomain
    f.add_pattern(".baz.com");         // root + subdomains

    EXPECT_TRUE (f.should_apply("foo.com"));
    EXPECT_FALSE(f.should_apply("a.foo.com"));
    EXPECT_FALSE(f.should_apply("bar.com"));
    EXPECT_TRUE (f.should_apply("a.bar.com"));
    EXPECT_TRUE (f.should_apply("baz.com"));
    EXPECT_TRUE (f.should_apply("x.baz.com"));
}
