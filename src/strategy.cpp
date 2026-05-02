#include "sgdpi/strategy.hpp"
#include "sgdpi/log.hpp"

#include <algorithm>
#include <cstring>
#include <random>
#include <string>
#include <unordered_map>

namespace sgdpi {

namespace {

// ---------------------------------------------------------------------------
// Helpers shared by every strategy.
// ---------------------------------------------------------------------------

thread_local std::mt19937 g_rng{std::random_device{}()};

inline uint16_t random_ip_id() {
    std::uniform_int_distribution<int> d(1, 65534);
    return static_cast<uint16_t>(d(g_rng));
}

inline void fill_random(uint8_t* dst, size_t n) {
    std::uniform_int_distribution<int> d(0, 255);
    for (size_t i = 0; i < n; ++i) dst[i] = static_cast<uint8_t>(d(g_rng));
}

// Initialize an OutPacket from a PacketBuilder. Returns false on overflow.
bool emit(OutQueue& out, PacketBuilder& b, const DivertAddr& src_addr,
          bool mark_impostor) {
    if (b.size() == 0 || b.size() > PacketBuilder::kMaxMtu) return false;
    out.emplace_back();
    OutPacket& op = out.back();
    std::memcpy(op.bytes.data(), b.data(), b.size());
    op.len  = b.size();
    op.addr = src_addr;
    if (mark_impostor) op.addr.mark_impostor();
    op.addr.clear_checksums();   // we just computed them; tell driver not to overwrite
    return true;
}

// Build a fake/decoy packet that mirrors `view` but with garbage payload and
// a low TTL. Caller chooses TTL.
bool build_fake(const PacketView& view, uint8_t ttl, PacketBuilder& out) {
    out.from_view(view);
    out.set_ttl(ttl);
    out.set_ip_identification(random_ip_id());

    // Replace the entire TCP payload with random bytes. We keep length the
    // same so that any DPI that key-tracks by seq+len sees a real-looking
    // segment.
    const size_t pl = view.payload_size();
    std::vector<uint8_t> garbage(pl);
    fill_random(garbage.data(), pl);
    // Force the first byte to look like a TLS handshake header so DPI
    // engaged in TLS heuristics is sure to inspect it (and get poisoned).
    if (pl >= 5) {
        garbage[0] = 0x16;          // TLS handshake
        garbage[1] = 0x03;
        garbage[2] = 0x01;           // record version 1.0
        const uint16_t fake_rec_len = static_cast<uint16_t>(pl - 5);
        garbage[3] = static_cast<uint8_t>(fake_rec_len >> 8);
        garbage[4] = static_cast<uint8_t>(fake_rec_len);
    }
    out.replace_payload(garbage.data(), pl);
    return out.recompute();
}

// Split TCP payload at `offset` into two builders. `a` gets payload[0..offset)
// and `b` gets payload[offset..]. Both end up with the same IP/TCP flags
// initially - caller can mutate per strategy needs (zero-window, etc.).
bool split_payload(const PacketView& view, size_t offset,
                   PacketBuilder& a, PacketBuilder& b) {
    const size_t pl = view.payload_size();
    if (offset == 0 || offset >= pl) return false;

    // FIRST half ----------------------------------------------------------
    a.from_view(view);
    a.set_ip_identification(random_ip_id());
    a.replace_payload(view.payload(), offset);
    if (!a.recompute()) return false;

    // SECOND half ---------------------------------------------------------
    b.from_view(view);
    b.set_ip_identification(random_ip_id());
    b.set_seq(view.seq() + static_cast<uint32_t>(offset));
    b.replace_payload(view.payload() + offset, pl - offset);
    if (!b.recompute()) return false;

    return true;
}

// Resolve fake TTL: if -1, use a sensible default. (auto_tune may have
// pre-resolved this to a real number; if it didn't we fall back to 4.)
inline uint8_t resolve_fake_ttl(int requested) noexcept {
    if (requested < 0) return 4;
    if (requested == 0) return 4;
    if (requested > 255) return 255;
    return static_cast<uint8_t>(requested);
}

// ---------------------------------------------------------------------------
// 1. TLS split: optional fake -> first half -> second half
// ---------------------------------------------------------------------------
class TlsSplit final : public IStrategy {
public:
    const char* name() const noexcept override { return "tls-split"; }
    FlowKind    kind() const noexcept override { return FlowKind::Tls; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        if (!ctx.tls_info || !ctx.tls_info->present) return false;

        const size_t off = tls::choose_split_offset(*ctx.tls_info, p.tls_split_mode,
                                                    p.tls_split_fixed);
        if (off == 0) return false;

        // (Optional) fake decoys with low TTL.
        if (p.fake_ttl != 0) {
            const uint8_t ttl = resolve_fake_ttl(p.fake_ttl);
            for (int i = 0; i < std::max(1, p.fake_repeat); ++i) {
                PacketBuilder fb;
                if (!build_fake(*ctx.view, ttl, fb)) continue;
                emit(out, fb, *ctx.addr, /*mark_impostor=*/true);
            }
        }

        PacketBuilder first, second;
        if (!split_payload(*ctx.view, off, first, second)) {
            SGDPI_LOG_DEBUG("tls-split: split failed off=", off,
                            " pl=", ctx.view->payload_size());
            return false;
        }
        if (p.zero_window) {
            first.set_tcp_window(0);
            first.recompute();
        }
        emit(out, first,  *ctx.addr, false);
        emit(out, second, *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// 2. TLS record fragmentation: split the single TLS record into two records
//    inside one TCP segment. The handshake message inside is preserved (its
//    length field is unchanged), but DPIs that peek only at the first record
//    no longer see the SNI.
// ---------------------------------------------------------------------------
class TlsRecordFrag final : public IStrategy {
public:
    const char* name() const noexcept override { return "tls-frag"; }
    FlowKind    kind() const noexcept override { return FlowKind::Tls; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        if (!ctx.tls_info || !ctx.tls_info->present) return false;
        if (ctx.tls_info->record_end <= 6) return false;

        const ByteView pl = ctx.view->payload_view();
        if (pl.size() < ctx.tls_info->record_end) return false;

        // Record body bytes are payload[5 .. record_end)
        const size_t body_start = 5;
        const size_t body_end   = ctx.tls_info->record_end;
        const size_t body_len   = body_end - body_start;
        if (body_len < 4) return false;     // need at least handshake header

        // Split into two halves of body. Aim for roughly equal sizes but
        // prefer the boundary that hides the SNI.
        size_t cut = body_len / 2;
        if (ctx.tls_info->sni_hostname_off >= body_start &&
            ctx.tls_info->sni_hostname_off <  body_end) {
            cut = ctx.tls_info->sni_hostname_off - body_start;
            if (cut == 0) cut = 1;
            if (cut >= body_len) cut = body_len - 1;
        }

        // New payload layout:
        //   [TLS record hdr1: 0x16 0x03 0x01 hi lo][body[0..cut)]
        //   [TLS record hdr2: 0x16 0x03 0x01 hi lo][body[cut..end)]
        //   ... + the rest of the original payload after this record ...
        std::vector<uint8_t> rebuilt;
        rebuilt.reserve(pl.size() + 5);

        auto append_record = [&](const uint8_t* data, size_t n) {
            rebuilt.push_back(0x16);
            rebuilt.push_back(0x03);
            rebuilt.push_back(0x01);            // pinned to TLS 1.0 - tolerated everywhere
            rebuilt.push_back(static_cast<uint8_t>(n >> 8));
            rebuilt.push_back(static_cast<uint8_t>(n));
            rebuilt.insert(rebuilt.end(), data, data + n);
        };

        append_record(pl.data() + body_start,        cut);
        append_record(pl.data() + body_start + cut,  body_len - cut);
        if (body_end < pl.size()) {
            rebuilt.insert(rebuilt.end(),
                           pl.data() + body_end,
                           pl.data() + pl.size());
        }

        if (rebuilt.size() > PacketBuilder::kMaxMtu - 60) {
            // Won't fit - bail.
            return false;
        }

        // Optional fakes first.
        if (p.fake_ttl != 0) {
            const uint8_t ttl = resolve_fake_ttl(p.fake_ttl);
            for (int i = 0; i < std::max(1, p.fake_repeat); ++i) {
                PacketBuilder fb;
                if (build_fake(*ctx.view, ttl, fb))
                    emit(out, fb, *ctx.addr, true);
            }
        }

        PacketBuilder b;
        b.from_view(*ctx.view);
        b.set_ip_identification(random_ip_id());
        b.replace_payload(rebuilt.data(), rebuilt.size());
        if (!b.recompute()) return false;
        emit(out, b, *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// 3. Standalone fake-TTL: send N decoy packets, then the original.
// ---------------------------------------------------------------------------
class FakeTtl final : public IStrategy {
public:
    const char* name() const noexcept override { return "fake-ttl"; }
    FlowKind    kind() const noexcept override { return FlowKind::Any; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        if (p.fake_ttl == 0) return false;
        const uint8_t ttl = resolve_fake_ttl(p.fake_ttl);

        for (int i = 0; i < std::max(1, p.fake_repeat); ++i) {
            PacketBuilder fb;
            if (!build_fake(*ctx.view, ttl, fb)) continue;
            emit(out, fb, *ctx.addr, true);
        }
        // Re-emit the original unchanged.
        PacketBuilder real;
        real.from_view(*ctx.view);
        if (!real.recompute()) return false;
        emit(out, real, *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// 4. HTTP Host header mangle.
// ---------------------------------------------------------------------------
class HttpHostMangle final : public IStrategy {
public:
    const char* name() const noexcept override { return "http-mangle"; }
    FlowKind    kind() const noexcept override { return FlowKind::Http; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        if (!ctx.http_info || !ctx.http_info->present) return false;
        if (ctx.http_info->host_header_len == 0)       return false;

        const ByteView pl = ctx.view->payload_view();
        std::vector<uint8_t> buf(pl.data(), pl.data() + pl.size());

        // Mangle the field-name token in place: alternate case "hOsT".
        if (p.http_mangle_case) {
            const size_t off = ctx.http_info->host_header_off;
            for (size_t i = 0; i < ctx.http_info->host_header_len; ++i) {
                uint8_t& c = buf[off + i];
                if (i % 2 == 0) {
                    if (c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c + 32);
                } else {
                    if (c >= 'a' && c <= 'z') c = static_cast<uint8_t>(c - 32);
                }
            }
        }

        // Insert an extra space between ':' and the value. This requires a
        // shift of subsequent bytes by 1.
        if (p.http_extra_space &&
            ctx.http_info->host_value_off > ctx.http_info->host_header_off + ctx.http_info->host_header_len + 1) {
            // No-op: there's already extra whitespace in the original.
        } else if (p.http_extra_space) {
            const size_t insert_at = ctx.http_info->host_header_off
                                   + ctx.http_info->host_header_len + 1; // after ':'
            if (buf.size() + 1 > PacketBuilder::kMaxMtu) return false;
            buf.insert(buf.begin() + insert_at, ' ');
        }

        // Optionally also do a TLS-style split right at start of URL/host
        // value, splitting the TCP segment so DPI can't reassemble cheaply.
        size_t split_off = 0;
        if (p.http_split_url && ctx.http_info->host_value_off > 1) {
            split_off = ctx.http_info->host_value_off;
        }

        // Build base packet from mangled buffer.
        PacketBuilder b;
        b.from_view(*ctx.view);
        b.set_ip_identification(random_ip_id());
        b.replace_payload(buf.data(), buf.size());
        if (!b.recompute()) return false;

        // Optional fakes before everything.
        if (p.fake_ttl != 0) {
            const uint8_t ttl = resolve_fake_ttl(p.fake_ttl);
            for (int i = 0; i < std::max(1, p.fake_repeat); ++i) {
                PacketBuilder fb;
                if (build_fake(*ctx.view, ttl, fb))
                    emit(out, fb, *ctx.addr, true);
            }
        }

        if (split_off == 0 || split_off >= buf.size()) {
            emit(out, b, *ctx.addr, false);
            return true;
        }

        // Split the mangled packet. We build a synthetic PacketView of `b`
        // and reuse split_payload.
        PacketView mv = b.view();
        PacketBuilder a1, a2;
        if (!split_payload(mv, split_off, a1, a2)) {
            emit(out, b, *ctx.addr, false);
            return true;
        }
        emit(out, a1, *ctx.addr, false);
        emit(out, a2, *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// 5. Disorder: split, but emit second half first.
// ---------------------------------------------------------------------------
class Disorder final : public IStrategy {
public:
    const char* name() const noexcept override { return "disorder"; }
    FlowKind    kind() const noexcept override { return FlowKind::Any; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        const size_t pl = ctx.view->payload_size();
        if (pl < 4) return false;

        size_t off = pl / 2;
        if (ctx.tls_info && ctx.tls_info->present && ctx.tls_info->sni_hostname_len > 0) {
            off = tls::choose_split_offset(*ctx.tls_info, p.tls_split_mode,
                                           p.tls_split_fixed);
        }
        if (off == 0 || off >= pl) return false;

        PacketBuilder first, second;
        if (!split_payload(*ctx.view, off, first, second)) return false;

        // Optional fake before everything (still useful with disorder).
        if (p.fake_ttl != 0) {
            const uint8_t ttl = resolve_fake_ttl(p.fake_ttl);
            PacketBuilder fb;
            if (build_fake(*ctx.view, ttl, fb))
                emit(out, fb, *ctx.addr, true);
        }

        // Reverse send order.
        emit(out, second, *ctx.addr, false);
        emit(out, first,  *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// 6. OOB: prepend a synthetic 1-byte segment with URG flag + fake URG ptr.
//    Some DPIs handle URG poorly and abort their inspection state.
// ---------------------------------------------------------------------------
class Oob final : public IStrategy {
public:
    const char* name() const noexcept override { return "oob"; }
    FlowKind    kind() const noexcept override { return FlowKind::Any; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        if (ctx.view->payload_size() == 0) return false;

        // 1) Synthetic OOB packet: same headers, payload = 1 random byte,
        //    URG flag set, urgent pointer = 1, seq unchanged so the byte
        //    "overlaps" the start of the real data. Most receivers will
        //    dedup it; the DPI hopefully chokes on the URG state machine.
        PacketBuilder oob;
        oob.from_view(*ctx.view);
        oob.set_ip_identification(random_ip_id());

        uint8_t b = 0;
        fill_random(&b, 1);
        oob.replace_payload(&b, 1);

        // Set URG flag (0x20) on top of existing flags, set urgent pointer.
        const uint8_t flags = ctx.view->tcp_flags() | 0x20;
        oob.set_tcp_flags(flags);

        // Urgent pointer (16-bit) lives at TCP[18..19]. Write 1.
        // PacketBuilder doesn't expose an urgent-ptr setter so we poke it.
        // Layout: ip_hdr_len + 18.
        {
            const size_t up_off = oob.view().ip_header_len() + 18;
            uint8_t* p = oob.data() + up_off;
            p[0] = 0; p[1] = 1;
        }
        if (!oob.recompute()) return false;
        emit(out, oob, *ctx.addr, true);

        // 2) Original packet, untouched.
        PacketBuilder real;
        real.from_view(*ctx.view);
        if (!real.recompute()) return false;
        emit(out, real, *ctx.addr, false);

        // We don't combine fake-TTL here because URG is itself the
        // disruptor. Add fake support easily if needed.
        return true;
    }
};

// ---------------------------------------------------------------------------
// 7. MD5 fake TCP option.
// ---------------------------------------------------------------------------
class Md5FakeOption final : public IStrategy {
public:
    const char* name() const noexcept override { return "md5-opt"; }
    FlowKind    kind() const noexcept override { return FlowKind::Any; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        if (ctx.view->payload_size() == 0) return false;

        // 1) Send a fake decoy with the MD5 option attached. The destination
        //    will reject it (no MD5 negotiated) but DPI may have already
        //    inspected and gotten confused.
        PacketBuilder fake;
        fake.from_view(*ctx.view);
        fake.set_ip_identification(random_ip_id());
        fake.set_ttl(resolve_fake_ttl(p.fake_ttl ? p.fake_ttl : 4));

        // Garbage payload, smallish.
        std::array<uint8_t, 16> garbage{};
        fill_random(garbage.data(), garbage.size());
        fake.replace_payload(garbage.data(), garbage.size());

        // Append option kind=19 (TCP_MD5SIG), len=18, 16 zero bytes.
        std::array<uint8_t, 16> md5_zero{};
        fake.append_tcp_option(19, ByteView{md5_zero.data(), md5_zero.size()});
        if (!fake.recompute()) return false;
        emit(out, fake, *ctx.addr, true);

        // 2) Original unchanged.
        PacketBuilder real;
        real.from_view(*ctx.view);
        if (!real.recompute()) return false;
        emit(out, real, *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// 8. Zero-window: standalone, sets window=0 on the original. Used in
//    combination with fake to confuse stateful TCP-tracking DPI. Not
//    typically useful alone but exposed as a building block.
// ---------------------------------------------------------------------------
class ZeroWindow final : public IStrategy {
public:
    const char* name() const noexcept override { return "zero-window"; }
    FlowKind    kind() const noexcept override { return FlowKind::Any; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        PacketBuilder b;
        b.from_view(*ctx.view);
        b.set_ip_identification(random_ip_id());
        b.set_tcp_window(0);
        if (!b.recompute()) return false;

        if (p.fake_ttl != 0) {
            PacketBuilder fb;
            if (build_fake(*ctx.view, resolve_fake_ttl(p.fake_ttl), fb))
                emit(out, fb, *ctx.addr, true);
        }
        emit(out, b, *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// 9. Wrong checksum: send a decoy with intentionally bad TCP checksum.
//    The destination host drops it (checksum fails) but many DPI boxes
//    inspect packets without verifying checksums, so they get poisoned.
//    This is one of GoodbyeDPI's most effective strategies.
// ---------------------------------------------------------------------------
class WrongChecksum final : public IStrategy {
public:
    const char* name() const noexcept override { return "wrong-chksum"; }
    FlowKind    kind() const noexcept override { return FlowKind::Any; }

    bool apply(const PacketContext& ctx, const StrategyParams& p, OutQueue& out) override {
        if (ctx.view->payload_size() == 0) return false;

        // Build a fake packet identical to the original but with a
        // deliberately corrupted TCP checksum. Most DPIs don't verify
        // checksums before inspecting, so this poisons their state.
        PacketBuilder fake;
        fake.from_view(*ctx.view);
        fake.set_ip_identification(random_ip_id());
        fake.set_ttl(resolve_fake_ttl(p.fake_ttl ? p.fake_ttl : 4));

        // Replace payload with random garbage.
        const size_t pl = ctx.view->payload_size();
        std::vector<uint8_t> garbage(pl);
        fill_random(garbage.data(), pl);
        if (pl >= 5) {
            garbage[0] = 0x16;
            garbage[1] = 0x03;
            garbage[2] = 0x01;
        }
        fake.replace_payload(garbage.data(), pl);
        if (!fake.recompute()) return false;

        // Corrupt the TCP checksum by flipping bits. The checksum lives
        // at tcp_header + 16. We XOR it so it's guaranteed wrong.
        auto fv = fake.view();
        uint8_t* tcp_cksum = fv.tcp_header() + 16;
        tcp_cksum[0] ^= 0xFF;
        tcp_cksum[1] ^= 0xFF;

        emit(out, fake, *ctx.addr, true);

        // Re-emit the original packet unchanged.
        PacketBuilder real;
        real.from_view(*ctx.view);
        if (!real.recompute()) return false;
        emit(out, real, *ctx.addr, false);
        return true;
    }
};

// ---------------------------------------------------------------------------
// Registry.
// ---------------------------------------------------------------------------

using Factory = std::unique_ptr<IStrategy>(*)();
const std::unordered_map<std::string, Factory>& registry() {
    static const std::unordered_map<std::string, Factory> r = {
        {"tls-split",    &make_tls_split},
        {"tls-frag",     &make_tls_record_frag},
        {"fake-ttl",     &make_fake_ttl},
        {"http-mangle",  &make_http_host_mangle},
        {"disorder",     &make_disorder},
        {"oob",          &make_oob},
        {"md5-opt",      &make_md5_fake_option},
        {"zero-window",  &make_zero_window},
        {"wrong-chksum", &make_wrong_checksum},
    };
    return r;
}

} // namespace

// Factory functions ---------------------------------------------------------
std::unique_ptr<IStrategy> make_tls_split()        { return std::make_unique<TlsSplit>(); }
std::unique_ptr<IStrategy> make_tls_record_frag()  { return std::make_unique<TlsRecordFrag>(); }
std::unique_ptr<IStrategy> make_fake_ttl()         { return std::make_unique<FakeTtl>(); }
std::unique_ptr<IStrategy> make_http_host_mangle() { return std::make_unique<HttpHostMangle>(); }
std::unique_ptr<IStrategy> make_disorder()         { return std::make_unique<Disorder>(); }
std::unique_ptr<IStrategy> make_oob()              { return std::make_unique<Oob>(); }
std::unique_ptr<IStrategy> make_md5_fake_option()  { return std::make_unique<Md5FakeOption>(); }
std::unique_ptr<IStrategy> make_zero_window()      { return std::make_unique<ZeroWindow>(); }
std::unique_ptr<IStrategy> make_wrong_checksum()   { return std::make_unique<WrongChecksum>(); }

const std::vector<std::string>& all_strategy_names() {
    static const std::vector<std::string> names = {
        "tls-split", "tls-frag", "fake-ttl", "wrong-chksum", "disorder",
        "http-mangle", "oob", "md5-opt", "zero-window",
    };
    return names;
}

// StrategyPipeline ----------------------------------------------------------
void StrategyPipeline::add(std::unique_ptr<IStrategy> s) {
    if (s) stages_.push_back(std::move(s));
}

IStrategy* StrategyPipeline::run(const PacketContext& ctx, const StrategyParams& params,
                                 OutQueue& out) {
    for (auto& s : stages_) {
        const FlowKind k = s->kind();
        if (k == FlowKind::Tls  && (!ctx.tls_info  || !ctx.tls_info->present))  continue;
        if (k == FlowKind::Http && (!ctx.http_info || !ctx.http_info->present)) continue;
        if (s->apply(ctx, params, out)) return s.get();
    }
    return nullptr;
}

StrategyPipeline build_pipeline(const std::vector<std::string>& names) {
    StrategyPipeline p;
    const auto& reg = registry();
    for (const auto& n : names) {
        auto it = reg.find(n);
        if (it == reg.end()) {
            SGDPI_LOG_WARN("Unknown strategy: '", n, "' - skipping");
            continue;
        }
        p.add(it->second());
    }
    return p;
}

} // namespace sgdpi
