//! Relay core: authenticated forwarding of sealed application frames.
//!
//! A relay forwards `0x50` app frames and `0x31` relay data between clients
//! it cannot read. Before this module it forwarded any frame to any member
//! destination, trusting the sender field, so anyone could inject frames in
//! another identity's name and one client could spend the whole send budget.
//!
//! Two facts make a sender authentic here:
//!
//!   - **Vouching.** An identity names its WireGuard key with its own Ed25519
//!     signature (a binding), through a trusted certificate, or by using the
//!     X25519 form of its Ed25519 key. Pings carry this; the relay records a
//!     *claim* identity → WireGuard key.
//!   - **Possession.** A WireGuard key is *proven* at a UDP endpoint when a
//!     Noise initiation from that endpoint decrypts under the key with a
//!     TAI64N timestamp newer than any seen for it. The relay answers that
//!     initiation statelessly, so proof uses no WireGuard peer slot.
//!
//! Proof is kept per WireGuard key, not per identity: an identity can sign
//! any key, including someone else's, but cannot prove a key it does not
//! hold, so a forged vouch can neither lock the owner out nor let anyone send
//! in the owner's name.
//!
//! A frame is forwarded only when it arrives from an endpoint where some key
//! is proven, its sender field names an admitted identity that vouches for
//! that key, the key's connection is within its packet and byte budgets, the
//! destination identity's key is proven somewhere, and the global forwarding
//! budget allows it.
//!
//! All state is owned by one thread (the SWIM event loop). Storage is
//! allocated at init; hash indexes use a per-process random seed so
//! attacker-chosen keys cannot be aimed at one bucket.

const std = @import("std");
const messages = @import("../protocol/messages.zig");
const Noise = @import("../wireguard/noise.zig");
const Binding = @import("../identity/binding.zig");
const Org = @import("../identity/org.zig");
const AppStatus = @import("../protocol/app_status.zig");

const ns_per_s: i128 = std.time.ns_per_s;
const NONE: u32 = std.math.maxInt(u32);

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn wallSeconds() i64 {
    return @intCast(std.Io.Timestamp.now(zio(), .real).toSeconds());
}

pub const Config = struct {
    /// Connections (WireGuard keys) tracked at once, proven or not.
    max_clients: u32 = 16384,
    /// Connections not proven yet. When full, the oldest unproven one makes
    /// room; proven connections are never displaced by new claims.
    max_unproven: u32 = 4096,
    /// Identity claims tracked at once. When full, the oldest claim whose key
    /// is not proven makes room first.
    max_claims: u32 = 32768,
    /// A proven connection silent for this long is forgotten.
    client_idle_timeout_ns: i128 = 120 * ns_per_s,
    /// A connection that does not prove an endpoint within this time is forgotten.
    unproven_timeout_ns: i128 = 30 * ns_per_s,
    /// Forwarding budget per connection.
    client_pps: f64 = 50,
    client_burst: f64 = 100,
    client_bytes_per_s: f64 = 256 * 1024,
    client_byte_burst: f64 = 512 * 1024,
    /// Forwarding budget shared by all connections.
    forward_pps: f64 = 20_000,
    forward_burst: f64 = 4_000,
    /// Handshake responses: per source address and overall.
    handshakes_per_source_per_s: f64 = 4,
    handshake_source_burst: f64 = 8,
    handshake_pps: f64 = 1_000,
    handshake_burst: f64 = 200,
    /// Source addresses tracked by the handshake limiter (and, separately,
    /// by the delivery-status limiter).
    max_handshake_sources: u32 = 8192,
    /// Delivery statuses (`0x51`) for frames the relay does not forward: per
    /// source address and overall. Zero `status_pps` turns them off.
    statuses_per_source_per_s: f64 = 2,
    status_source_burst: f64 = 4,
    status_pps: f64 = 2_000,
    status_burst: f64 = 400,
    /// An address whose handshakes are limited per endpoint (address and
    /// port) instead of per address, such as a co-located browser gateway
    /// whose sessions all share one loopback address.
    trusted_handshake_source: ?[16]u8 = null,
    /// Accept a WireGuard key learned from unsigned gossip for an admitted
    /// identity. Only for closed-trust relays during migration.
    legacy_wg_binding: bool = false,
    /// Clock difference tolerated with certificate issuers, in seconds.
    cert_skew_s: i64 = Org.DEFAULT_CERT_SKEW_S,
};

pub const DropReason = enum {
    malformed,
    unproven_sender,
    spoofed_sender,
    not_admitted,
    rate_limited,
    unknown_destination,
    overloaded,
};

pub const Route = union(enum) {
    forward: messages.Endpoint,
    drop: DropReason,
};

pub const KeySource = enum(u8) { legacy_gossip, derived, binding, certificate };

/// Whether an identity may use the relay. Called when the trust epoch
/// changes or the certificate that admitted a claim expires.
pub const Admission = struct {
    ctx: *anyopaque,
    admits: *const fn (ctx: *anyopaque, identity: [32]u8) bool,
};

pub const Stats = struct {
    claims: u64 = 0,
    proofs: u64 = 0,
    forwarded: u64 = 0,
    dropped: [@typeInfo(DropReason).@"enum".fields.len]u64 = .{0} ** @typeInfo(DropReason).@"enum".fields.len,
    handshakes_refused: u64 = 0,
    evicted: u64 = 0,

    pub fn droppedFor(self: *const Stats, reason: DropReason) u64 {
        return self.dropped[@intFromEnum(reason)];
    }
};

const TokenBucket = struct {
    tokens: f64,
    updated_ns: i128,

    fn full(burst: f64, now_ns: i128) TokenBucket {
        return .{ .tokens = burst, .updated_ns = now_ns };
    }

    fn take(self: *TokenBucket, rate: f64, burst: f64, cost: f64, now_ns: i128) bool {
        const elapsed: f64 = @floatFromInt(@max(now_ns - self.updated_ns, 0));
        self.tokens = @min(burst, self.tokens + elapsed / @as(f64, @floatFromInt(ns_per_s)) * rate);
        self.updated_ns = now_ns;
        if (self.tokens < cost) return false;
        self.tokens -= cost;
        return true;
    }
};

/// An endpoint as a fixed-size hash key: family, address, port.
pub const EndpointKey = struct {
    bytes: [19]u8,

    pub fn of(ep: messages.Endpoint) EndpointKey {
        var key = EndpointKey{ .bytes = std.mem.zeroes([19]u8) };
        if (ep.addr6) |a6| {
            key.bytes[0] = 6;
            @memcpy(key.bytes[1..17], &a6);
        } else {
            key.bytes[0] = 4;
            @memcpy(key.bytes[1..5], &ep.addr);
        }
        std.mem.writeInt(u16, key.bytes[17..19], ep.port, .little);
        return key;
    }

    /// The address alone (IPv4) or its /64 (IPv6), for per-source limits.
    pub fn sourceOf(ep: messages.Endpoint) EndpointKey {
        var key = of(ep);
        key.bytes[17] = 0;
        key.bytes[18] = 0;
        if (key.bytes[0] == 6) @memset(key.bytes[9..17], 0);
        return key;
    }
};

fn KeyContext(comptime K: type) type {
    return struct {
        seed: u64,

        pub fn hash(self: @This(), key: K) u64 {
            return std.hash.Wyhash.hash(self.seed, std.mem.asBytes(&key));
        }

        pub fn eql(_: @This(), a: K, b: K) bool {
            return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
        }
    };
}

const KeyMap = std.HashMapUnmanaged([32]u8, u32, KeyContext([32]u8), std.hash_map.default_max_load_percentage);

/// Token buckets per source address (IPv4 address or IPv6 /64) under an
/// overall budget. One `trusted` address is limited per port instead, for a
/// co-located gateway whose sessions all share it. A bounded table: when full,
/// refilled entries are dropped, and new sources are refused until room frees.
const SourceLimiter = struct {
    map: SourceMap = .{},
    per_source: f64,
    source_burst: f64,
    overall: f64,
    overall_bucket: TokenBucket,
    overall_burst: f64,
    max_sources: u32,
    trusted: ?[16]u8,

    fn allow(self: *SourceLimiter, allocator: std.mem.Allocator, ctx: KeyContext(EndpointKey), src: messages.Endpoint, now_ns: i128) bool {
        if (!self.overall_bucket.take(self.overall, self.overall_burst, 1, now_ns)) return false;
        const key = if (self.isTrusted(src)) EndpointKey.of(src) else EndpointKey.sourceOf(src);
        if (self.map.getPtrContext(key, ctx)) |bucket| {
            return bucket.take(self.per_source, self.source_burst, 1, now_ns);
        }
        if (self.map.count() >= self.max_sources) {
            self.prune(ctx, now_ns);
            if (self.map.count() >= self.max_sources) return false;
        }
        var bucket = TokenBucket.full(self.source_burst, now_ns);
        _ = bucket.take(self.per_source, self.source_burst, 1, now_ns);
        self.map.putContext(allocator, key, bucket, ctx) catch return false;
        return true;
    }

    fn isTrusted(self: *const SourceLimiter, src: messages.Endpoint) bool {
        const trusted = self.trusted orelse return false;
        return std.mem.eql(u8, EndpointKey.of(src).bytes[1..17], &trusted);
    }

    /// Forgets sources whose buckets have refilled completely.
    fn prune(self: *SourceLimiter, ctx: KeyContext(EndpointKey), now_ns: i128) void {
        const refill_ns: i128 = @intFromFloat(self.source_burst / self.per_source * @as(f64, @floatFromInt(ns_per_s)));
        var stale: [256]EndpointKey = undefined;
        var n: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (now_ns - entry.value_ptr.updated_ns >= refill_ns) {
                stale[n] = entry.key_ptr.*;
                n += 1;
                if (n == stale.len) break;
            }
        }
        for (stale[0..n]) |key| _ = self.map.removeContext(key, ctx);
    }
};
const EndpointMap = std.HashMapUnmanaged(EndpointKey, u32, KeyContext(EndpointKey), std.hash_map.default_max_load_percentage);
const SourceMap = std.HashMapUnmanaged(EndpointKey, TokenBucket, KeyContext(EndpointKey), std.hash_map.default_max_load_percentage);

/// One WireGuard key and where it is proven.
pub const Conn = struct {
    wg: [32]u8,
    endpoint: ?messages.Endpoint = null,
    /// Newest Noise TAI64N timestamp accepted for this key.
    latest_tai64n: [12]u8 = std.mem.zeroes([12]u8),
    last_seen_ns: i128,
    packets: TokenBucket,
    bytes: TokenBucket,
    prev: u32 = NONE,
    next: u32 = NONE,
    in_use: bool = false,
};

/// One identity and the WireGuard key it vouches for.
pub const Claim = struct {
    identity: [32]u8,
    wg: [32]u8,
    key_source: KeySource,
    /// Wall-clock expiry of the certificate that admitted it (0 = none).
    cert_expires_at: i64 = 0,
    trust_epoch: u64,
    last_seen_ns: i128,
    prev: u32 = NONE,
    next: u32 = NONE,
    in_use: bool = false,
};

/// A fixed pool of slots threaded on intrusive least-recently-seen lists.
fn Pool(comptime T: type) type {
    return struct {
        items: []T,
        free: []u32,
        free_count: u32,

        const Self = @This();

        fn init(allocator: std.mem.Allocator, n: u32) !Self {
            const items = try allocator.alloc(T, n);
            errdefer allocator.free(items);
            const free = try allocator.alloc(u32, n);
            for (items) |*item| item.in_use = false;
            for (free, 0..) |*slot, i| slot.* = n - 1 - @as(u32, @intCast(i));
            return .{ .items = items, .free = free, .free_count = n };
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.items);
            allocator.free(self.free);
        }

        fn take(self: *Self) ?u32 {
            if (self.free_count == 0) return null;
            self.free_count -= 1;
            return self.free[self.free_count];
        }

        fn give(self: *Self, i: u32) void {
            self.items[i].in_use = false;
            self.free[self.free_count] = i;
            self.free_count += 1;
        }
    };
}

fn Lru(comptime T: type) type {
    return struct {
        head: u32 = NONE,
        tail: u32 = NONE,
        len: u32 = 0,

        const Self = @This();

        fn pushBack(self: *Self, items: []T, i: u32) void {
            items[i].prev = self.tail;
            items[i].next = NONE;
            if (self.tail != NONE) items[self.tail].next = i else self.head = i;
            self.tail = i;
            self.len += 1;
        }

        fn remove(self: *Self, items: []T, i: u32) void {
            const item = &items[i];
            if (item.prev != NONE) items[item.prev].next = item.next else self.head = item.next;
            if (item.next != NONE) items[item.next].prev = item.prev else self.tail = item.prev;
            item.prev = NONE;
            item.next = NONE;
            self.len -= 1;
        }
    };
}

pub const RelayCore = struct {
    allocator: std.mem.Allocator,
    config: Config,
    static_private: [32]u8,
    static_public: [32]u8,
    admission: Admission,
    seed: u64,

    conns: Pool(Conn),
    unproven: Lru(Conn) = .{},
    proven: Lru(Conn) = .{},
    by_wg: KeyMap = .{},
    by_endpoint: EndpointMap = .{},

    claims: Pool(Claim),
    claim_lru: Lru(Claim) = .{},
    by_identity: KeyMap = .{},

    handshake_sources: SourceLimiter,
    status_sources: SourceLimiter,
    forward_budget: TokenBucket,
    next_index: u32,
    trust_epoch: u64 = 1,
    stats: Stats = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        static_private: [32]u8,
        static_public: [32]u8,
        admission: Admission,
        now_ns: i128,
    ) !RelayCore {
        var seed_bytes: [12]u8 = undefined;
        zio().random(&seed_bytes);
        var conns = try Pool(Conn).init(allocator, config.max_clients);
        errdefer conns.deinit(allocator);
        var claims = try Pool(Claim).init(allocator, config.max_claims);
        errdefer claims.deinit(allocator);

        var core = RelayCore{
            .allocator = allocator,
            .config = config,
            .static_private = static_private,
            .static_public = static_public,
            .admission = admission,
            .seed = std.mem.readInt(u64, seed_bytes[0..8], .little),
            .conns = conns,
            .claims = claims,
            .forward_budget = TokenBucket.full(config.forward_burst, now_ns),
            .handshake_sources = .{
                .per_source = config.handshakes_per_source_per_s,
                .source_burst = config.handshake_source_burst,
                .overall = config.handshake_pps,
                .overall_bucket = TokenBucket.full(config.handshake_burst, now_ns),
                .overall_burst = config.handshake_burst,
                .max_sources = config.max_handshake_sources,
                .trusted = config.trusted_handshake_source,
            },
            .status_sources = .{
                .per_source = config.statuses_per_source_per_s,
                .source_burst = config.status_source_burst,
                .overall = config.status_pps,
                .overall_bucket = TokenBucket.full(config.status_burst, now_ns),
                .overall_burst = config.status_burst,
                .max_sources = config.max_handshake_sources,
                .trusted = null,
            },
            .next_index = std.mem.readInt(u32, seed_bytes[8..12], .little),
        };
        errdefer core.deinitMaps();
        try core.by_wg.ensureTotalCapacityContext(allocator, config.max_clients, core.keyCtx());
        try core.by_endpoint.ensureTotalCapacityContext(allocator, config.max_clients, core.epCtx());
        try core.by_identity.ensureTotalCapacityContext(allocator, config.max_claims, core.keyCtx());
        try core.handshake_sources.map.ensureTotalCapacityContext(allocator, config.max_handshake_sources, core.epCtx());
        try core.status_sources.map.ensureTotalCapacityContext(allocator, config.max_handshake_sources, core.epCtx());
        return core;
    }

    fn deinitMaps(self: *RelayCore) void {
        self.by_wg.deinit(self.allocator);
        self.by_endpoint.deinit(self.allocator);
        self.by_identity.deinit(self.allocator);
        self.handshake_sources.map.deinit(self.allocator);
        self.status_sources.map.deinit(self.allocator);
    }

    pub fn deinit(self: *RelayCore) void {
        self.deinitMaps();
        self.conns.deinit(self.allocator);
        self.claims.deinit(self.allocator);
        std.crypto.secureZero(u8, &self.static_private);
    }

    fn keyCtx(self: *const RelayCore) KeyContext([32]u8) {
        return .{ .seed = self.seed };
    }

    fn epCtx(self: *const RelayCore) KeyContext(EndpointKey) {
        return .{ .seed = self.seed ^ 0x9e3779b97f4a7c15 };
    }

    pub fn connCount(self: *const RelayCore) u32 {
        return self.unproven.len + self.proven.len;
    }

    pub fn provenCount(self: *const RelayCore) u32 {
        return self.proven.len;
    }

    pub fn claimCount(self: *const RelayCore) u32 {
        return self.claim_lru.len;
    }

    fn claimOf(self: *const RelayCore, identity: [32]u8) ?*Claim {
        const i = self.by_identity.getContext(identity, self.keyCtx()) orelse return null;
        return &self.claims.items[i];
    }

    fn connOf(self: *const RelayCore, wg: [32]u8) ?*Conn {
        const i = self.by_wg.getContext(wg, self.keyCtx()) orelse return null;
        return &self.conns.items[i];
    }

    /// Where an identity can be reached, if its key is proven.
    pub fn endpointOf(self: *const RelayCore, identity: [32]u8) ?messages.Endpoint {
        const claim_ = self.claimOf(identity) orelse return null;
        const conn = self.connOf(claim_.wg) orelse return null;
        return conn.endpoint;
    }

    pub fn keySourceOf(self: *const RelayCore, identity: [32]u8) ?KeySource {
        const claim_ = self.claimOf(identity) orelse return null;
        return claim_.key_source;
    }

    /// Admission sources changed (trust reload, revocation): every claim is
    /// re-checked on its next frame.
    pub fn bumpTrustEpoch(self: *RelayCore) void {
        self.trust_epoch +%= 1;
    }

    // ─── Claims ───

    pub const ClaimInput = struct {
        identity: [32]u8,
        /// The identity's own signature over its WireGuard key.
        wg_binding: ?messages.WgBinding = null,
        /// A certificate the sender presented; verified here before its bound
        /// WireGuard key is used.
        org_cert: ?*const [messages.ORG_CERT_WIRE_SIZE]u8 = null,
        /// A key learned another way (gossip); used only when derived from
        /// the identity, or with `legacy_wg_binding`.
        known_wg: ?[32]u8 = null,
    };

    /// Records that an admitted identity vouches for a WireGuard key. The
    /// caller has already checked admission. Returns false when no
    /// vouched-for key is available or the tables are full of proven work.
    pub fn claim(self: *RelayCore, input: ClaimInput, now_ns: i128) bool {
        const current = self.claimOf(input.identity);
        const vouched = self.vouchedKey(input, current) orelse return false;
        const conn = self.ensureConn(vouched.wg, now_ns) orelse {
            self.stats.dropped[@intFromEnum(DropReason.overloaded)] += 1;
            return false;
        };
        conn.last_seen_ns = now_ns;
        self.touchConn(conn);

        if (current) |c| {
            c.wg = vouched.wg;
            c.key_source = vouched.source;
            if (vouched.cert_expires_at != 0) c.cert_expires_at = vouched.cert_expires_at;
            // The caller just admitted this identity (a renewed pass, a
            // reload that still trusts it), so the cached decision is fresh.
            c.trust_epoch = self.trust_epoch;
            c.last_seen_ns = now_ns;
            const i = self.by_identity.getContext(input.identity, self.keyCtx()).?;
            self.claim_lru.remove(self.claims.items, i);
            self.claim_lru.pushBack(self.claims.items, i);
            return true;
        }

        const i = self.allocateClaim() orelse {
            self.stats.dropped[@intFromEnum(DropReason.overloaded)] += 1;
            return false;
        };
        self.claims.items[i] = .{
            .identity = input.identity,
            .wg = vouched.wg,
            .key_source = vouched.source,
            .cert_expires_at = vouched.cert_expires_at,
            .trust_epoch = self.trust_epoch,
            .last_seen_ns = now_ns,
            .in_use = true,
        };
        self.by_identity.putContext(self.allocator, input.identity, i, self.keyCtx()) catch {
            self.claims.give(i);
            return false;
        };
        self.claim_lru.pushBack(self.claims.items, i);
        self.stats.claims += 1;
        return true;
    }

    const Vouched = struct { wg: [32]u8, source: KeySource, cert_expires_at: i64 = 0 };

    fn vouchedKey(self: *const RelayCore, input: ClaimInput, current: ?*const Claim) ?Vouched {
        if (input.org_cert) |cert_wire| {
            const cert = Org.NodeCertificate.deserialize(cert_wire);
            if (cert.boundWgPubkey()) |wg| {
                const seen = if (current) |c| c.key_source == .certificate and std.mem.eql(u8, &c.wg, &wg) else false;
                const valid = cert.isValidAt(wallSeconds(), self.config.cert_skew_s);
                if (valid and (seen or (std.mem.eql(u8, &cert.node_pubkey, &input.identity) and Org.verifyCertificate(&cert)))) {
                    return .{ .wg = wg, .source = .certificate, .cert_expires_at = cert.expires_at };
                }
            }
        }
        if (input.wg_binding) |binding| {
            // Verify only when the binding would change what is recorded.
            if (current) |c| {
                if (c.key_source == .binding and std.mem.eql(u8, &c.wg, &binding.wg_pubkey)) {
                    return .{ .wg = binding.wg_pubkey, .source = .binding };
                }
            }
            if (Binding.verify(input.identity, binding)) return .{ .wg = binding.wg_pubkey, .source = .binding };
        }
        if (current) |c| {
            // A bare ping keeps the key vouched for earlier.
            if (c.key_source != .legacy_gossip or self.config.legacy_wg_binding) {
                return .{ .wg = c.wg, .source = c.key_source, .cert_expires_at = c.cert_expires_at };
            }
        }
        if (input.known_wg) |wg| {
            if (Binding.isDerived(input.identity, wg)) return .{ .wg = wg, .source = .derived };
            if (self.config.legacy_wg_binding) return .{ .wg = wg, .source = .legacy_gossip };
        }
        return null;
    }

    fn ensureConn(self: *RelayCore, wg: [32]u8, now_ns: i128) ?*Conn {
        if (self.connOf(wg)) |conn| return conn;
        if (self.unproven.len >= self.config.max_unproven) self.evictOldestUnproven();
        const i = self.conns.take() orelse blk: {
            self.evictOldestUnproven();
            self.expireConns(now_ns, 4);
            break :blk self.conns.take() orelse return null;
        };
        self.conns.items[i] = .{
            .wg = wg,
            .last_seen_ns = now_ns,
            .packets = TokenBucket.full(self.config.client_burst, now_ns),
            .bytes = TokenBucket.full(self.config.client_byte_burst, now_ns),
            .in_use = true,
        };
        self.by_wg.putContext(self.allocator, wg, i, self.keyCtx()) catch {
            self.conns.give(i);
            return null;
        };
        self.unproven.pushBack(self.conns.items, i);
        return &self.conns.items[i];
    }

    fn evictOldestUnproven(self: *RelayCore) void {
        if (self.unproven.head == NONE) return;
        self.releaseConn(self.unproven.head);
        self.stats.evicted += 1;
    }

    /// Takes a claim slot, evicting first the oldest claim whose key is not
    /// proven (looking at a bounded number of the oldest), then the oldest.
    fn allocateClaim(self: *RelayCore) ?u32 {
        if (self.claims.take()) |i| return i;
        var i = self.claim_lru.head;
        var looked: u32 = 0;
        while (i != NONE and looked < 32) : (looked += 1) {
            const c = &self.claims.items[i];
            const proven = if (self.connOf(c.wg)) |conn| conn.endpoint != null else false;
            if (!proven) break;
            i = c.next;
        }
        if (i == NONE or looked == 32) i = self.claim_lru.head;
        if (i == NONE) return null;
        self.releaseClaim(i);
        self.stats.evicted += 1;
        return self.claims.take();
    }

    // ─── Endpoint proof ───

    /// Answers a Noise initiation, proving the source endpoint for the
    /// initiator's WireGuard key. Returns the response to send back, or null
    /// when the packet is not a valid, fresh initiation for a claimed key.
    pub fn handleInitiation(self: *RelayCore, packet: []const u8, src: messages.Endpoint, now_ns: i128) ?Noise.HandshakeResponse {
        if (packet.len != @sizeOf(Noise.HandshakeInitiation)) return null;
        if (std.mem.readInt(u32, packet[0..4], .little) != 1) return null;
        var msg: Noise.HandshakeInitiation = undefined;
        @memcpy(std.mem.asBytes(&msg), packet);
        if (!Noise.verifyMac1(self.static_public, &msg)) return null;
        if (!self.handshake_sources.allow(self.allocator, self.epCtx(), src, now_ns)) {
            self.stats.handshakes_refused += 1;
            return null;
        }

        const preamble = Noise.decryptInitiatorStatic(self.static_private, self.static_public, &msg) catch return null;
        const i = self.by_wg.getContext(preamble.initiator_static, self.keyCtx()) orelse return null;
        const conn = &self.conns.items[i];

        var hs = Noise.Handshake.init(self.static_private, self.static_public, conn.wg) catch return null;
        defer hs.deinit();
        hs.latest_timestamp = conn.latest_tai64n;
        hs.consumeInitiationFast(&msg, preamble) catch return null;
        self.next_index +%= 1;
        const response = hs.createResponse(self.next_index) catch return null;

        conn.latest_tai64n = hs.latest_timestamp;
        self.prove(i, src, now_ns);
        return response;
    }

    /// Marks a WireGuard key proven at an endpoint after a handshake another
    /// component verified (the userspace WireGuard device).
    pub fn markProven(self: *RelayCore, wg: [32]u8, src: messages.Endpoint, now_ns: i128) void {
        const i = self.by_wg.getContext(wg, self.keyCtx()) orelse return;
        self.prove(i, src, now_ns);
    }

    fn prove(self: *RelayCore, i: u32, src: messages.Endpoint, now_ns: i128) void {
        const conn = &self.conns.items[i];
        const key = EndpointKey.of(src);
        if (self.by_endpoint.getContext(key, self.epCtx())) |owner| {
            // A NAT mapping now belongs to another key.
            if (owner != i) self.unprove(owner);
        }
        if (conn.endpoint) |old| {
            if (!old.eql(src)) _ = self.by_endpoint.removeContext(EndpointKey.of(old), self.epCtx());
        }
        self.by_endpoint.putContext(self.allocator, key, i, self.epCtx()) catch return;
        if (conn.endpoint == null) {
            self.unproven.remove(self.conns.items, i);
            self.proven.pushBack(self.conns.items, i);
        }
        conn.endpoint = src;
        conn.last_seen_ns = now_ns;
        self.touchConn(conn);
        self.stats.proofs += 1;
    }

    fn unprove(self: *RelayCore, i: u32) void {
        const conn = &self.conns.items[i];
        const old = conn.endpoint orelse return;
        _ = self.by_endpoint.removeContext(EndpointKey.of(old), self.epCtx());
        conn.endpoint = null;
        self.proven.remove(self.conns.items, i);
        self.unproven.pushBack(self.conns.items, i);
    }

    /// The delivery status to send for a frame dropped for `reason`, or null
    /// when none applies or the status limits are spent.
    pub fn statusFor(self: *RelayCore, reason: DropReason, src: messages.Endpoint, now_ns: i128) ?AppStatus.Code {
        const code: AppStatus.Code = switch (reason) {
            .malformed => return null,
            // The endpoint is not (or no longer) proven for the sender's key.
            .unproven_sender, .spoofed_sender => .handshake_again,
            .not_admitted => .not_admitted,
            .rate_limited => .rate_limited,
            .unknown_destination => .offline,
            .overloaded => .overloaded,
        };
        if (self.config.status_pps <= 0) return null;
        if (!self.status_sources.allow(self.allocator, self.epCtx(), src, now_ns)) return null;
        return code;
    }

    // ─── Forwarding ───

    /// Decides where a frame from `src` claiming `sender` and addressed to
    /// `destination` goes. `len` is the frame size, charged to the sender.
    pub fn route(self: *RelayCore, sender: [32]u8, destination: [32]u8, len: usize, src: messages.Endpoint, now_ns: i128) Route {
        const decision = self.decide(sender, destination, len, src, now_ns);
        switch (decision) {
            .forward => self.stats.forwarded += 1,
            .drop => |reason| self.stats.dropped[@intFromEnum(reason)] += 1,
        }
        return decision;
    }

    fn decide(self: *RelayCore, sender: [32]u8, destination: [32]u8, len: usize, src: messages.Endpoint, now_ns: i128) Route {
        const ci = self.by_endpoint.getContext(EndpointKey.of(src), self.epCtx()) orelse return .{ .drop = .unproven_sender };
        const conn = &self.conns.items[ci];
        const claim_ = self.claimOf(sender) orelse return .{ .drop = .spoofed_sender };
        if (!std.mem.eql(u8, &claim_.wg, &conn.wg)) return .{ .drop = .spoofed_sender };
        if (!self.stillAdmitted(claim_)) return .{ .drop = .not_admitted };

        const bytes: f64 = @floatFromInt(len);
        if (!conn.packets.take(self.config.client_pps, self.config.client_burst, 1, now_ns)) return .{ .drop = .rate_limited };
        if (!conn.bytes.take(self.config.client_bytes_per_s, self.config.client_byte_burst, bytes, now_ns)) return .{ .drop = .rate_limited };
        conn.last_seen_ns = now_ns;
        self.touchConn(conn);

        const dest_ep = self.endpointOf(destination) orelse return .{ .drop = .unknown_destination };
        if (!self.forward_budget.take(self.config.forward_pps, self.config.forward_burst, 1, now_ns)) return .{ .drop = .overloaded };
        return .{ .forward = dest_ep };
    }

    fn stillAdmitted(self: *RelayCore, c: *Claim) bool {
        if (c.cert_expires_at != 0 and wallSeconds() >= c.cert_expires_at +| self.config.cert_skew_s) {
            return self.recheck(c);
        }
        if (c.trust_epoch == self.trust_epoch) return true;
        return self.recheck(c);
    }

    fn recheck(self: *RelayCore, c: *Claim) bool {
        if (!self.admission.admits(self.admission.ctx, c.identity)) return false;
        c.trust_epoch = self.trust_epoch;
        c.cert_expires_at = 0;
        return true;
    }

    // ─── Expiry ───

    /// Forgets connections and claims past their timeouts, oldest first, at
    /// most `budget` of each.
    pub fn expire(self: *RelayCore, now_ns: i128, budget: u32) void {
        self.expireConns(now_ns, budget);
        var left = budget;
        while (left > 0 and self.claim_lru.head != NONE) : (left -= 1) {
            const i = self.claim_lru.head;
            if (now_ns - self.claims.items[i].last_seen_ns < self.config.client_idle_timeout_ns) break;
            self.releaseClaim(i);
        }
    }

    fn expireConns(self: *RelayCore, now_ns: i128, budget: u32) void {
        var left = budget;
        while (left > 0 and self.unproven.head != NONE) : (left -= 1) {
            const i = self.unproven.head;
            if (now_ns - self.conns.items[i].last_seen_ns < self.config.unproven_timeout_ns) break;
            self.releaseConn(i);
        }
        left = budget;
        while (left > 0 and self.proven.head != NONE) : (left -= 1) {
            const i = self.proven.head;
            if (now_ns - self.conns.items[i].last_seen_ns < self.config.client_idle_timeout_ns) break;
            self.releaseConn(i);
        }
    }

    /// Forgets an identity at once (revocation, leave). Its key's proof stays
    /// until it expires, but no frame can name the identity as sender.
    pub fn forget(self: *RelayCore, identity: [32]u8) void {
        const i = self.by_identity.getContext(identity, self.keyCtx()) orelse return;
        self.releaseClaim(i);
    }

    fn touchConn(self: *RelayCore, conn: *Conn) void {
        const i: u32 = @intCast((@intFromPtr(conn) - @intFromPtr(self.conns.items.ptr)) / @sizeOf(Conn));
        const list = if (conn.endpoint != null) &self.proven else &self.unproven;
        list.remove(self.conns.items, i);
        list.pushBack(self.conns.items, i);
    }

    fn releaseConn(self: *RelayCore, i: u32) void {
        const conn = &self.conns.items[i];
        if (!conn.in_use) return;
        if (conn.endpoint) |ep| {
            _ = self.by_endpoint.removeContext(EndpointKey.of(ep), self.epCtx());
            self.proven.remove(self.conns.items, i);
        } else {
            self.unproven.remove(self.conns.items, i);
        }
        _ = self.by_wg.removeContext(conn.wg, self.keyCtx());
        std.crypto.secureZero(u8, &conn.latest_tai64n);
        conn.endpoint = null;
        self.conns.give(i);
    }

    fn releaseClaim(self: *RelayCore, i: u32) void {
        const c = &self.claims.items[i];
        if (!c.in_use) return;
        self.claim_lru.remove(self.claims.items, i);
        _ = self.by_identity.removeContext(c.identity, self.keyCtx());
        self.claims.give(i);
    }
};

// ─── Tests ───

const testing = std.testing;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;

const TestAdmission = struct {
    denied: ?[32]u8 = null,

    fn admits(ctx: *anyopaque, identity: [32]u8) bool {
        const self: *TestAdmission = @ptrCast(@alignCast(ctx));
        if (self.denied) |d| return !std.mem.eql(u8, &d, &identity);
        return true;
    }

    fn get(self: *TestAdmission) Admission {
        return .{ .ctx = self, .admits = admits };
    }
};

/// A client identity as mobile contexts derive it: WireGuard key = clamped seed.
const TestClient = struct {
    identity: [32]u8,
    wg_private: [32]u8,
    wg_public: [32]u8,
    binding: messages.WgBinding,
    ts: u64 = 1,

    fn init(seed_byte: u8) !TestClient {
        const seed = [_]u8{seed_byte} ** 32;
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        var private = seed;
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        const public = try X25519.recoverPublicKey(private);
        return .{
            .identity = kp.public_key.toBytes(),
            .wg_private = private,
            .wg_public = public,
            .binding = try Binding.signWithSeed(seed, public),
        };
    }

    fn claimInput(self: *const TestClient) RelayCore.ClaimInput {
        return .{ .identity = self.identity, .wg_binding = self.binding };
    }

    /// A Noise initiation with a strictly increasing TAI64N timestamp.
    fn initiation(self: *TestClient, relay_public: [32]u8) ![@sizeOf(Noise.HandshakeInitiation)]u8 {
        var hs = try Noise.Handshake.init(self.wg_private, self.wg_public, relay_public);
        defer hs.deinit();
        var ephemeral: [32]u8 = undefined;
        zio().random(&ephemeral);
        var ts = std.mem.zeroes([12]u8);
        std.mem.writeInt(u64, ts[0..8], 0x4000000000000000 + self.ts, .big);
        self.ts += 1;
        const msg = try hs.createInitiationWithEntropy(7, ephemeral, ts);
        return std.mem.toBytes(msg);
    }
};

const TestRelay = struct {
    admission: TestAdmission = .{},
    private: [32]u8,
    public: [32]u8,

    fn init() !TestRelay {
        var private = [_]u8{0x55} ** 32;
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        return .{ .private = private, .public = try X25519.recoverPublicKey(private) };
    }

    fn core(self: *TestRelay, config: Config) !RelayCore {
        return RelayCore.init(testing.allocator, config, self.private, self.public, self.admission.get(), 0);
    }
};

fn addr(last: u8, port: u16) messages.Endpoint {
    return messages.Endpoint.initV4(.{ 198, 51, 100, last }, port);
}

fn smallConfig() Config {
    return .{ .max_clients = 64, .max_unproven = 16, .max_claims = 128, .max_handshake_sources = 64 };
}

fn proveClient(core: *RelayCore, relay_public: [32]u8, client: *TestClient, at: messages.Endpoint, now: i128) !void {
    try testing.expect(core.claim(client.claimInput(), now));
    const init_bytes = try client.initiation(relay_public);
    try testing.expect(core.handleInitiation(&init_bytes, at, now) != null);
}

test "a proven client's frames reach a proven destination" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);

    const r = core.route(alice.identity, bob.identity, 200, addr(1, 4000), 1);
    try testing.expect(r == .forward);
    try testing.expect(r.forward.eql(addr(2, 4000)));
    try testing.expectEqual(@as(u32, 2), core.provenCount());
}

test "frames naming someone else as sender are dropped" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    var mallory = try TestClient.init(3);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);
    try proveClient(&core, relay.public, &mallory, addr(3, 4000), 0);

    try testing.expectEqual(Route{ .drop = .spoofed_sender }, core.route(alice.identity, bob.identity, 200, addr(3, 4000), 1));
    const stranger = try TestClient.init(4);
    try testing.expectEqual(Route{ .drop = .spoofed_sender }, core.route(stranger.identity, bob.identity, 200, addr(3, 4000), 1));
}

test "frames from an unproven endpoint are dropped" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    const alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    try testing.expect(core.claim(alice.claimInput(), 0));
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);

    try testing.expectEqual(Route{ .drop = .unproven_sender }, core.route(alice.identity, bob.identity, 100, addr(1, 4000), 1));
    // Bob cannot reach Alice until she proves an endpoint either.
    try testing.expectEqual(Route{ .drop = .unknown_destination }, core.route(bob.identity, alice.identity, 100, addr(2, 4000), 1));
}

test "a replayed initiation cannot move a client to another endpoint" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var alice = try TestClient.init(1);
    try testing.expect(core.claim(alice.claimInput(), 0));
    const captured = try alice.initiation(relay.public);
    try testing.expect(core.handleInitiation(&captured, addr(1, 4000), 0) != null);

    // An on-path observer replays the same initiation from its own address.
    try testing.expect(core.handleInitiation(&captured, addr(66, 5000), 1) == null);
    try testing.expect(core.endpointOf(alice.identity).?.eql(addr(1, 4000)));
}

test "a claim without a Noise handshake never forwards" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    const victim = try TestClient.init(1);
    var bob = try TestClient.init(2);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);
    // An attacker replays the victim's ping (binding included) from its endpoint.
    try testing.expect(core.claim(victim.claimInput(), 0));
    try testing.expectEqual(Route{ .drop = .unproven_sender }, core.route(victim.identity, bob.identity, 100, addr(66, 5000), 1));
}

test "a WireGuard key claimed without the owner's signature cannot be proven" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    const victim = try TestClient.init(1);
    var attacker = try TestClient.init(9);

    // The attacker claims the victim's identity with its own key, signed by itself.
    var forged = victim.claimInput();
    forged.wg_binding = attacker.binding;
    try testing.expect(!core.claim(forged, 0));
    // Or offers its key as an unsigned "known" key: refused unless derived.
    try testing.expect(!core.claim(.{ .identity = victim.identity, .known_wg = attacker.wg_public }, 0));

    const init_bytes = try attacker.initiation(relay.public);
    try testing.expect(core.handleInitiation(&init_bytes, addr(66, 5000), 0) == null);
    try testing.expect(core.endpointOf(victim.identity) == null);
}

test "vouching for someone else's key neither locks them out nor lets anyone send as them" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var victim = try TestClient.init(1);
    var bob = try TestClient.init(2);
    const attacker_seed = [_]u8{9} ** 32;
    const attacker = try Ed25519.KeyPair.generateDeterministic(attacker_seed);

    // The attacker signs the victim's public WireGuard key as its own, first.
    const stolen = try Binding.signWithSeed(attacker_seed, victim.wg_public);
    try testing.expect(core.claim(.{ .identity = attacker.public_key.toBytes(), .wg_binding = stolen }, 0));

    // The victim still claims and proves its key.
    try proveClient(&core, relay.public, &victim, addr(1, 4000), 1);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 1);
    try testing.expect(core.route(victim.identity, bob.identity, 100, addr(1, 4000), 2) == .forward);
    try testing.expect(core.route(bob.identity, victim.identity, 100, addr(2, 4000), 2) == .forward);

    // The attacker cannot prove the key from its own endpoint, so its frames go nowhere.
    try testing.expectEqual(Route{ .drop = .unproven_sender }, core.route(attacker.public_key.toBytes(), bob.identity, 100, addr(66, 5000), 2));
}

test "derived keys and certificate-bound keys are vouched for" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();

    const daemon = try Ed25519.KeyPair.generateDeterministic([_]u8{0x31} ** 32);
    const derived = try X25519.publicKeyFromEd25519(daemon.public_key);
    try testing.expect(core.claim(.{ .identity = daemon.public_key.toBytes(), .known_wg = derived }, 0));
    try testing.expectEqual(KeySource.derived, core.keySourceOf(daemon.public_key.toBytes()).?);

    const org = Org.generateOrgKeyPair();
    const node = try TestClient.init(4);
    const cert = try Org.issueCertificateV2(org, node.identity, node.wg_public, "n", 0);
    var wire: [messages.ORG_CERT_WIRE_SIZE]u8 = undefined;
    cert.serialize(&wire);
    try testing.expect(core.claim(.{ .identity = node.identity, .org_cert = &wire }, 0));
    try testing.expectEqual(KeySource.certificate, core.keySourceOf(node.identity).?);

    // A certificate for someone else does not vouch.
    const other = try TestClient.init(5);
    try testing.expect(!core.claim(.{ .identity = other.identity, .org_cert = &wire }, 0));
}

test "legacy gossip keys are accepted only when enabled" {
    var relay = try TestRelay.init();
    var plain = try relay.core(smallConfig());
    defer plain.deinit();
    var alice = try TestClient.init(1);
    try testing.expect(!plain.claim(.{ .identity = alice.identity, .known_wg = alice.wg_public }, 0));

    var config = smallConfig();
    config.legacy_wg_binding = true;
    var core = try relay.core(config);
    defer core.deinit();
    try testing.expect(core.claim(.{ .identity = alice.identity, .known_wg = alice.wg_public }, 0));
    const init_bytes = try alice.initiation(relay.public);
    try testing.expect(core.handleInitiation(&init_bytes, addr(1, 4000), 0) != null);
    // A signed binding later upgrades the source.
    try testing.expect(core.claim(alice.claimInput(), 1));
    try testing.expectEqual(KeySource.binding, core.keySourceOf(alice.identity).?);
}

test "a reused NAT mapping moves to the key that proved it last" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    var carol = try TestClient.init(3);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &carol, addr(3, 4000), 0);
    // Alice's mapping is reused for Bob.
    try proveClient(&core, relay.public, &bob, addr(1, 4000), 1);

    try testing.expect(core.endpointOf(alice.identity) == null);
    try testing.expectEqual(Route{ .drop = .spoofed_sender }, core.route(alice.identity, carol.identity, 100, addr(1, 4000), 2));
    try testing.expect(core.route(bob.identity, carol.identity, 100, addr(1, 4000), 2) == .forward);
    // Alice proves again from her new mapping.
    try proveClient(&core, relay.public, &alice, addr(1, 4001), 3);
    try testing.expect(core.route(alice.identity, carol.identity, 100, addr(1, 4001), 3) == .forward);
}

test "a flooding client is held to its budget and others keep flowing" {
    var relay = try TestRelay.init();
    var config = smallConfig();
    config.client_pps = 10;
    config.client_burst = 20;
    var core = try relay.core(config);
    defer core.deinit();
    var flooder = try TestClient.init(1);
    var alice = try TestClient.init(2);
    var bob = try TestClient.init(3);
    try proveClient(&core, relay.public, &flooder, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &alice, addr(2, 4000), 0);
    try proveClient(&core, relay.public, &bob, addr(3, 4000), 0);

    var forwarded: u32 = 0;
    for (0..1000) |_| {
        if (core.route(flooder.identity, bob.identity, 100, addr(1, 4000), 1) == .forward) forwarded += 1;
    }
    try testing.expectEqual(@as(u32, 20), forwarded);
    try testing.expect(core.stats.droppedFor(.rate_limited) >= 980);
    for (0..10) |_| {
        try testing.expect(core.route(alice.identity, bob.identity, 100, addr(2, 4000), 1) == .forward);
    }
    // The budget refills with time.
    try testing.expect(core.route(flooder.identity, bob.identity, 100, addr(1, 4000), 1 + ns_per_s) == .forward);
}

test "byte budgets cap large frames separately from packet counts" {
    var relay = try TestRelay.init();
    var config = smallConfig();
    config.client_bytes_per_s = 1000;
    config.client_byte_burst = 3000;
    var core = try relay.core(config);
    defer core.deinit();
    var alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);
    var forwarded: u32 = 0;
    for (0..10) |_| {
        if (core.route(alice.identity, bob.identity, 1000, addr(1, 4000), 1) == .forward) forwarded += 1;
    }
    try testing.expectEqual(@as(u32, 3), forwarded);
}

test "the global forwarding budget is separate from client budgets" {
    var relay = try TestRelay.init();
    var config = smallConfig();
    config.forward_pps = 1;
    config.forward_burst = 5;
    var core = try relay.core(config);
    defer core.deinit();
    var alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);
    var forwarded: u32 = 0;
    for (0..10) |_| {
        if (core.route(alice.identity, bob.identity, 100, addr(1, 4000), 1) == .forward) forwarded += 1;
    }
    try testing.expectEqual(@as(u32, 5), forwarded);
    try testing.expectEqual(@as(u64, 5), core.stats.droppedFor(.overloaded));
}

test "a flood of unproven claims never displaces proven clients" {
    var relay = try TestRelay.init();
    var config = smallConfig();
    config.max_clients = 8;
    config.max_unproven = 4;
    config.max_claims = 8;
    var core = try relay.core(config);
    defer core.deinit();
    var proven: [3]TestClient = undefined;
    for (&proven, 0..) |*c, n| {
        c.* = try TestClient.init(@intCast(n + 1));
        try proveClient(&core, relay.public, c, addr(@intCast(n + 1), 4000), 0);
    }
    for (0..100) |n| {
        const spammer = try TestClient.init(@intCast(n + 50));
        _ = core.claim(spammer.claimInput(), 1);
    }
    try testing.expectEqual(@as(u32, 3), core.provenCount());
    try testing.expect(core.connCount() <= 8);
    try testing.expect(core.claimCount() <= 8);
    try testing.expect(core.route(proven[0].identity, proven[1].identity, 100, addr(1, 4000), 2) == .forward);
}

test "silent clients expire, unproven ones sooner" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var alice = try TestClient.init(1);
    const bob = try TestClient.init(2);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try testing.expect(core.claim(bob.claimInput(), 0));

    core.expire(31 * ns_per_s, 64);
    try testing.expectEqual(@as(u32, 1), core.connCount());
    try testing.expect(core.endpointOf(alice.identity) != null);
    core.expire(121 * ns_per_s, 64);
    try testing.expectEqual(@as(u32, 0), core.connCount());
    try testing.expectEqual(@as(u32, 0), core.claimCount());
}

test "revoked identities stop forwarding after a trust change" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);
    relay.admission.denied = alice.identity;
    // Cached admission holds until the epoch changes.
    try testing.expect(core.route(alice.identity, bob.identity, 100, addr(1, 4000), 1) == .forward);
    core.bumpTrustEpoch();
    try testing.expectEqual(Route{ .drop = .not_admitted }, core.route(alice.identity, bob.identity, 100, addr(1, 4000), 2));
    try testing.expect(core.route(bob.identity, alice.identity, 100, addr(2, 4000), 2) == .forward);
    core.forget(alice.identity);
    try testing.expectEqual(Route{ .drop = .unknown_destination }, core.route(bob.identity, alice.identity, 100, addr(2, 4000), 3));
}

test "a fresh claim re-admits an identity after a trust change" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    var alice = try TestClient.init(1);
    var bob = try TestClient.init(2);
    try proveClient(&core, relay.public, &alice, addr(1, 4000), 0);
    try proveClient(&core, relay.public, &bob, addr(2, 4000), 0);
    relay.admission.denied = alice.identity;
    core.bumpTrustEpoch();
    try testing.expectEqual(Route{ .drop = .not_admitted }, core.route(alice.identity, bob.identity, 100, addr(1, 4000), 1));
    // Her next ping passed the caller's admission check (say, with a renewed pass).
    try testing.expect(core.claim(alice.claimInput(), 2));
    try testing.expect(core.route(alice.identity, bob.identity, 100, addr(1, 4000), 3) == .forward);
}

test "expired certificates stop vouching once past the skew" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    const org = Org.generateOrgKeyPair();
    const node = try TestClient.init(4);
    const now = wallSeconds();
    var wire: [messages.ORG_CERT_WIRE_SIZE]u8 = undefined;

    const recent = try Org.issueCertificateV2(org, node.identity, node.wg_public, "n", now - 10);
    recent.serialize(&wire);
    try testing.expect(core.claim(.{ .identity = node.identity, .org_cert = &wire }, 0));

    const stale = try Org.issueCertificateV2(org, (try TestClient.init(5)).identity, node.wg_public, "n", now - 1000);
    stale.serialize(&wire);
    try testing.expect(!core.claim(.{ .identity = (try TestClient.init(5)).identity, .org_cert = &wire }, 0));
}

test "handshakes are limited per source address except a trusted gateway" {
    var relay = try TestRelay.init();
    var config = smallConfig();
    config.handshakes_per_source_per_s = 1;
    config.handshake_source_burst = 2;
    config.trusted_handshake_source = blk: {
        var a = std.mem.zeroes([16]u8);
        a[0..4].* = .{ 127, 0, 0, 1 };
        break :blk a;
    };
    var core = try relay.core(config);
    defer core.deinit();

    var accepted: u32 = 0;
    for (0..4) |n| {
        var c = try TestClient.init(@intCast(n + 1));
        const at = addr(9, @intCast(4000 + n)); // one address, many ports
        try testing.expect(core.claim(c.claimInput(), 0));
        const bytes = try c.initiation(relay.public);
        if (core.handleInitiation(&bytes, at, 0) != null) accepted += 1;
    }
    try testing.expectEqual(@as(u32, 2), accepted);

    // Gateway sessions share 127.0.0.1 but are limited per port.
    accepted = 0;
    for (0..4) |n| {
        var c = try TestClient.init(@intCast(n + 20));
        const at = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, @intCast(40000 + n));
        try testing.expect(core.claim(c.claimInput(), 0));
        const bytes = try c.initiation(relay.public);
        if (core.handleInitiation(&bytes, at, 0) != null) accepted += 1;
    }
    try testing.expectEqual(@as(u32, 4), accepted);
}

test "the handshake response completes the client's Noise session" {
    var relay = try TestRelay.init();
    var core = try relay.core(smallConfig());
    defer core.deinit();
    const alice = try TestClient.init(1);
    try testing.expect(core.claim(alice.claimInput(), 0));

    var hs = try Noise.Handshake.init(alice.wg_private, alice.wg_public, relay.public);
    defer hs.deinit();
    const msg = try hs.createInitiation(42);
    const response = core.handleInitiation(std.mem.asBytes(&msg), addr(1, 4000), 0) orelse return error.NoResponse;
    try hs.consumeResponse(&response);
    try testing.expectEqual(@as(u32, 42), std.mem.readInt(u32, std.mem.asBytes(&response)[8..12], .little));
}

test "dropped frames get rate-limited delivery statuses with matching codes" {
    var relay = try TestRelay.init();
    var config = smallConfig();
    config.statuses_per_source_per_s = 1;
    config.status_source_burst = 2;
    var core = try relay.core(config);
    defer core.deinit();
    try testing.expectEqual(AppStatus.Code.handshake_again, core.statusFor(.unproven_sender, addr(1, 4000), 0).?);
    try testing.expectEqual(AppStatus.Code.offline, core.statusFor(.unknown_destination, addr(1, 4001), 0).?);
    // The third status for one address in the same instant is suppressed.
    try testing.expect(core.statusFor(.rate_limited, addr(1, 4002), 0) == null);
    try testing.expectEqual(AppStatus.Code.not_admitted, core.statusFor(.not_admitted, addr(2, 4000), 0).?);
    try testing.expect(core.statusFor(.malformed, addr(3, 4000), 0) == null);

    config.status_pps = 0;
    var silent = try relay.core(config);
    defer silent.deinit();
    try testing.expect(silent.statusFor(.unproven_sender, addr(1, 4000), 0) == null);
}

test "endpoint keys distinguish ports and fold IPv6 sources to /64" {
    const a = EndpointKey.of(messages.Endpoint.initV4(.{ 1, 2, 3, 4 }, 5));
    const b = EndpointKey.of(messages.Endpoint.initV4(.{ 1, 2, 3, 4 }, 6));
    try testing.expect(!std.mem.eql(u8, &a.bytes, &b.bytes));
    try testing.expectEqualSlices(u8, &EndpointKey.sourceOf(messages.Endpoint.initV4(.{ 1, 2, 3, 4 }, 5)).bytes, &EndpointKey.sourceOf(messages.Endpoint.initV4(.{ 1, 2, 3, 4 }, 6)).bytes);
    var v6a = std.mem.zeroes([16]u8);
    v6a[0] = 0x20;
    var v6b = v6a;
    v6b[15] = 9;
    try testing.expectEqualSlices(u8, &EndpointKey.sourceOf(messages.Endpoint.initV6(v6a, 1)).bytes, &EndpointKey.sourceOf(messages.Endpoint.initV6(v6b, 2)).bytes);
}
