//! meshguard FFI — C-ABI surface for embedding in mobile and desktop apps.
//!
//! This module exposes a minimal C-compatible API for:
//!   - Lifecycle: init, join mesh via seed, leave, destroy
//!   - Messaging: send/receive encrypted app-level messages
//!   - Events: peer join/leave callbacks
//!
//! Built as libmeshguard-ffi.so (Linux, Android), libmeshguard-ffi.dylib /
//! a static library (macOS, iOS) and meshguard-ffi.dll (Windows), with the
//! same exports everywhere. Hosts call it from their own threads (JNI, Swift,
//! P/Invoke, ctypes, dart:ffi...) while each joined context runs its own
//! event-loop thread.
//! Does NOT include the WireGuard TUN dataplane — application-level
//! encrypted messaging and userspace tunnels over the context's UDP socket.

const std = @import("std");
const builtin = @import("builtin");
const lib = @import("lib.zig");
const AppPacket = @import("app_packet.zig");
const AppStatus = @import("protocol/app_status.zig");
const atomic64 = @import("atomic64.zig");

// 32-bit ARM Android is .androideabi; isAndroid() covers every Android ABI.
const is_android = builtin.abi.isAndroid();
const is_mobile = is_android or builtin.os.tag == .ios;

// Mobile panic handler: Zig's default panic handler tries to load debug info
// from the library. On Android the library is embedded inside the APK, and on
// iOS simulator the default Mach-O unwinder can reference unavailable dyld
// private symbols. Override to simply abort.
pub const std_options: std.Options = .{
    .logFn = if (is_android) androidLogFn else std.log.defaultLog,
};

fn androidLogFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = level;
    _ = scope;
    _ = format;
    _ = args;
    // On Android embedded in APK, logging is best-effort via std.debug.print
    // which writes to stderr (logcat picks it up).
}

pub const panic = if (is_mobile)
    std.debug.FullPanic(mobilePanic)
else
    std.debug.FullPanic(std.debug.defaultPanic);

fn mobilePanic(msg: []const u8, _: ?usize) noreturn {
    // Bypass debug-info-based stack traces completely.
    _ = msg;
    std.process.abort();
}

const Membership = lib.discovery.Membership;
const SwimProtocol = lib.discovery.Swim.SwimProtocol;
const EventHandler = lib.discovery.Swim.EventHandler;
const SwimConfig = lib.discovery.Swim.SwimConfig;
const LanDiscovery = lib.discovery.Lan.LanDiscovery;
const Udp = lib.net.Udp;
const noise = lib.wireguard.Noise;

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn fillIdentitySeed(out: *[32]u8) void {
    if (builtin.os.tag.isDarwin()) {
        std.c.arc4random_buf(out, out.len);
        return;
    }

    zio().random(out);
}

const crypto = lib.wireguard.Crypto;
const Device = lib.wireguard.Device;
const WgDevice = Device.WgDevice;
const messages = @import("protocol/messages.zig");
const codec = @import("protocol/codec.zig");
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

// ─── Opaque handle ───

/// Opaque context for a meshguard instance.
/// Owns the SWIM protocol, membership table, crypto keys,
/// and the background event loop thread.
pub const MeshguardContext = struct {
    // Identity
    ed25519_seed: [32]u8,
    ed25519_public: [32]u8,
    x25519_private: [32]u8,
    x25519_public: [32]u8,
    /// Our Ed25519 signature over x25519_public, advertised on pings and acks.
    wg_binding: messages.WgBinding,
    /// Organization certificate (for example a relay pass) set by the host.
    /// Written under `org_cert_lock` on the host thread; the event loop
    /// applies it to SWIM when `org_cert_dirty` is set.
    org_cert: ?[messages.ORG_CERT_WIRE_SIZE]u8,
    org_cert_lock: std.Io.Mutex,
    org_cert_dirty: std.atomic.Value(bool),

    // Contacts registered by the host: Ed25519 identity -> WireGuard key. They
    // seal and open app frames for peers a relay does not describe (opaque
    // relays) and take precedence over keys learned from gossip.
    contacts: std.AutoHashMapUnmanaged([32]u8, [32]u8),
    contacts_lock: std.Io.Mutex,
    contacts_only: std.atomic.Value(bool),

    // Frames recently sent through a relay, to match its delivery statuses.
    sent_frames: [256]SentFrame,
    sent_next: usize,
    sent_lock: std.Io.Mutex,
    on_delivery_status_cb: ?*const fn ([*]const u8, [*]const u8, u8) callconv(.c) void,
    // The same statuses for hosts that poll (`meshguard_recv_delivery_status`).
    status_inbox: [64]StatusEntry,
    status_write: std.atomic.Value(u32),
    status_read: std.atomic.Value(u32),

    // Last packet time (ns), mirrored from SWIM by the event loop so host
    // threads never read SWIM while leave() replaces it.
    last_recv_ns: atomic64.Value(i64),

    // Host-tunable timers (0 = default), read by the event loop.
    keepalive_ms: std.atomic.Value(u32),
    relay_proof_ms: std.atomic.Value(u32),

    // Networking
    membership: Membership.MembershipTable,
    swim: ?SwimProtocol,
    socket: ?Udp.UdpSocket,
    lan_discovery: ?LanDiscovery,
    event_loop_thread: ?std.Thread,
    running: std.atomic.Value(bool),
    suspended: std.atomic.Value(bool), // low-power mode: recv only, no send
    // Set by meshguard_resume() on the host thread; consumed by the event-loop
    // thread, which owns SWIM/LAN state, to perform the post-resume re-announce
    // without racing tick(). See meshguard_resume / eventLoop.
    resume_requested: std.atomic.Value(bool),

    // App routing is configured before join and remains immutable while running.
    app_relay_key: ?[32]u8,
    force_app_relay: bool,
    last_relay_auth_ns: i128,
    app_direct_sent: atomic64.Value(u64),
    app_relay_sent: atomic64.Value(u64),
    app_route_failed: atomic64.Value(u64),
    app_duplicate_dropped: atomic64.Value(u64),
    app_seen: [128]AppSeen,
    app_seen_next: usize,

    // Callbacks (set by host app)
    on_message_cb: ?*const fn ([*]const u8, usize, [*]const u8) callconv(.c) void,
    on_peer_event_cb: ?*const fn (u8, [*]const u8) callconv(.c) void,
    // Called when meshguard_send() fails to deliver (peer unknown/dead/no endpoint).
    // Signature: void callback(dest_pubkey_ptr, data_ptr, data_len, error_code)
    on_undeliverable_cb: ?*const fn ([*]const u8, [*]const u8, u32, i32) callconv(.c) void,

    // App-level message inbox (ring buffer)
    inbox: [64]AppMessage,
    inbox_write: std.atomic.Value(u32),
    inbox_read: std.atomic.Value(u32),

    // WireGuard tunnel device (for encrypted audio/data tunnels)
    wg_device: ?WgDevice,
    // RwLock: exclusive for handshake/add/remove, shared for encrypt/decrypt
    wg_lock: std.Io.RwLock,

    // Tunnel data inbox (separate from app messages, higher throughput)
    tunnel_inbox: [256]TunnelMessage,
    tunnel_inbox_write: std.atomic.Value(u32),
    tunnel_inbox_read: std.atomic.Value(u32),

    // Allocator for this context's heap needs
    alloc: std.mem.Allocator,
};

// Initialize the heap allocation directly. Returning this large aggregate by
// value can create stack temporaries larger than a physical iOS host thread.
fn initContextStorage(ctx: *MeshguardContext, allocator: std.mem.Allocator) void {
    ctx.ed25519_seed = undefined;
    ctx.ed25519_public = undefined;
    ctx.x25519_private = undefined;
    ctx.x25519_public = undefined;
    ctx.wg_binding = undefined;
    ctx.org_cert = null;
    ctx.org_cert_lock = .init;
    ctx.org_cert_dirty = std.atomic.Value(bool).init(false);
    ctx.contacts = .empty;
    ctx.contacts_lock = .init;
    ctx.contacts_only = std.atomic.Value(bool).init(false);
    ctx.sent_frames = std.mem.zeroes([256]SentFrame);
    ctx.sent_next = 0;
    ctx.sent_lock = .init;
    ctx.on_delivery_status_cb = null;
    ctx.status_inbox = std.mem.zeroes([64]StatusEntry);
    ctx.status_write = std.atomic.Value(u32).init(0);
    ctx.status_read = std.atomic.Value(u32).init(0);
    ctx.keepalive_ms = std.atomic.Value(u32).init(0);
    ctx.last_recv_ns = atomic64.Value(i64).init(0);
    ctx.relay_proof_ms = std.atomic.Value(u32).init(0);
    ctx.membership = Membership.MembershipTable.init(allocator, 15000);
    ctx.swim = null;
    ctx.socket = null;
    ctx.lan_discovery = null;
    ctx.event_loop_thread = null;
    ctx.running = std.atomic.Value(bool).init(false);
    ctx.suspended = std.atomic.Value(bool).init(false);
    ctx.resume_requested = std.atomic.Value(bool).init(false);
    ctx.app_relay_key = null;
    ctx.force_app_relay = false;
    ctx.last_relay_auth_ns = 0;
    ctx.app_direct_sent = atomic64.Value(u64).init(0);
    ctx.app_relay_sent = atomic64.Value(u64).init(0);
    ctx.app_route_failed = atomic64.Value(u64).init(0);
    ctx.app_duplicate_dropped = atomic64.Value(u64).init(0);
    @memset(std.mem.asBytes(&ctx.app_seen), 0);
    ctx.app_seen_next = 0;
    ctx.on_message_cb = null;
    ctx.on_peer_event_cb = null;
    ctx.on_undeliverable_cb = null;
    @memset(std.mem.asBytes(&ctx.inbox), 0);
    ctx.inbox_write = std.atomic.Value(u32).init(0);
    ctx.inbox_read = std.atomic.Value(u32).init(0);
    ctx.wg_device = null;
    ctx.wg_lock = .init;
    @memset(std.mem.asBytes(&ctx.tunnel_inbox), 0);
    ctx.tunnel_inbox_write = std.atomic.Value(u32).init(0);
    ctx.tunnel_inbox_read = std.atomic.Value(u32).init(0);
    ctx.alloc = allocator;
}

fn closeContextSocket(ctx: *MeshguardContext) void {
    if (ctx.socket) |*s| {
        s.close();
    }
    ctx.socket = null;
}

fn destroyContext(ctx: *MeshguardContext) void {
    meshguard_leave(ctx);
    closeContextSocket(ctx);
    ctx.membership.deinit();
    ctx.contacts.deinit(ctx.alloc);
    ctx.alloc.destroy(ctx);
}

fn tunnelFramePayloadLen(frame_len: usize, encoded_payload_len: u16) ?usize {
    const payload_len: usize = @intCast(encoded_payload_len);
    if (payload_len + 4 > frame_len) return null;
    return payload_len;
}

const SentFrame = struct {
    valid: bool,
    destination: [32]u8,
    nonce: [12]u8,
};

const MAX_CONTACTS: u32 = 4096;
const DEFAULT_RELAY_PROOF_MS: u32 = 15_000;

/// Application-level encrypted message in the inbox.
const AppMessage = struct {
    sender_pubkey: [32]u8,
    data: [1024]u8,
    len: u16,
    valid: bool,
};

/// A delivery status waiting for the host to poll it.
const StatusEntry = struct {
    destination: [32]u8,
    nonce: [12]u8,
    code: u8,
    valid: bool,
};

/// Tunnel data message in the tunnel inbox.
const TunnelMessage = struct {
    sender_identity: [32]u8,
    data: [1500]u8,
    len: u16,
    valid: bool,
};

const AppSeen = struct {
    valid: bool,
    sender: [32]u8,
    nonce: [12]u8,
};

const AppRoute = struct {
    direct: ?messages.Endpoint,
    relay: ?messages.Endpoint,
};

fn appRoute(peer: Membership.Peer, relay: ?Membership.Peer, force_relay: bool) AppRoute {
    const relay_ep = if (relay) |r| r.gossip_endpoint orelse r.public_endpoint else null;
    if (force_relay) return .{ .direct = null, .relay = relay_ep };
    return .{
        .direct = if (peer.state == .alive or peer.state == .suspected) peer.gossip_endpoint orelse peer.public_endpoint else null,
        .relay = relay_ep,
    };
}

/// Advertise our binding and any certificate on a freshly created SWIM.
fn prepareSwim(c: *MeshguardContext) void {
    const swim = if (c.swim) |*s| s else return;
    swim.setWgBinding(c.wg_binding);
    c.org_cert_lock.lockUncancelable(zio());
    defer c.org_cert_lock.unlock(zio());
    if (c.org_cert) |cert| swim.setOrgCert(cert);
    c.org_cert_dirty.store(false, .release);
}

/// Validates a certificate for this context: v1 (186 bytes) or v2 (314),
/// issued to our Ed25519 key, binding our WireGuard key if v2, correctly
/// signed by its issuer, and valid now (allowing the usual clock skew).
/// Whether the issuer is trusted is for the relay to decide.
fn checkOwnCertificate(c: *const MeshguardContext, cert: []const u8) ?[messages.ORG_CERT_WIRE_SIZE]u8 {
    const Org = lib.identity.Org;
    if (cert.len != Org.V1_CERT_WIRE_SIZE and cert.len != messages.ORG_CERT_WIRE_SIZE) return null;
    var wire = std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8);
    @memcpy(wire[0..cert.len], cert);
    const parsed = Org.NodeCertificate.deserialize(&wire);
    if (!std.mem.eql(u8, &parsed.node_pubkey, &c.ed25519_public)) return null;
    if (parsed.boundWgPubkey()) |wg| {
        if (!std.mem.eql(u8, &wg, &c.x25519_public)) return null;
    } else if (parsed.version == Org.CERT_VERSION_V2) return null;
    const now: i64 = @intCast(std.Io.Timestamp.now(zio(), .real).toSeconds());
    if (!parsed.isValidAt(now, Org.DEFAULT_CERT_SKEW_S)) return null;
    if (!Org.verifyCertificate(&parsed)) return null;
    return wire;
}

/// Install or replace this context's organization certificate, such as a
/// relay pass, while stopped or running. A running context advertises it from
/// its next ping and pings its peers and re-proves its relay endpoint at once.
/// Returns 0, -1 (no context), -3 (wrong length), or -4 (not this identity's,
/// badly signed, or not valid now).
export fn meshguard_set_org_cert(ctx: ?*MeshguardContext, cert: ?[*]const u8, len: u32) i32 {
    const c = ctx orelse return -1;
    const bytes = cert orelse return -3;
    if (len != lib.identity.Org.V1_CERT_WIRE_SIZE and len != messages.ORG_CERT_WIRE_SIZE) return -3;
    const wire = checkOwnCertificate(c, bytes[0..len]) orelse return -4;
    c.org_cert_lock.lockUncancelable(zio());
    c.org_cert = wire;
    c.org_cert_lock.unlock(zio());
    c.org_cert_dirty.store(true, .release);
    return 0;
}

/// Stop advertising an organization certificate. Returns 0 or -1.
export fn meshguard_clear_org_cert(ctx: ?*MeshguardContext) i32 {
    const c = ctx orelse return -1;
    c.org_cert_lock.lockUncancelable(zio());
    c.org_cert = null;
    c.org_cert_lock.unlock(zio());
    c.org_cert_dirty.store(true, .release);
    return 0;
}

/// On the event loop: apply a certificate the host changed.
fn applyPendingOrgCert(c: *MeshguardContext, swim: *SwimProtocol) void {
    if (!c.org_cert_dirty.swap(false, .acq_rel)) return;
    c.org_cert_lock.lockUncancelable(zio());
    const cert = c.org_cert;
    c.org_cert_lock.unlock(zio());
    if (cert) |wire| swim.setOrgCert(wire) else swim.clearOrgCert();
    // Present it now, and prove the relay endpoint again under it.
    swim.pingAllAlive();
    c.last_relay_auth_ns = 0;
}

/// Pin a relay identity and optionally require app messages to use it exclusively.
/// Configure before joining. A forced route fails closed while that relay is absent.
export fn meshguard_set_app_relay(ctx: ?*MeshguardContext, relay_pubkey: ?[*]const u8, force: bool) i32 {
    const c = ctx orelse return -1;
    if (c.running.load(.acquire)) return -2;
    if (force and relay_pubkey == null) return -3;
    c.app_relay_key = if (relay_pubkey) |key| key[0..32].* else null;
    c.force_app_relay = force;
    return 0;
}

/// Four LE u64 counters: direct UDP sends, relay UDP sends, failed routes, duplicate drops.
/// Counts represent socket sends, never confirmed delivery.
export fn meshguard_app_route_stats(ctx: ?*MeshguardContext, out: [*]u8) void {
    const c = ctx orelse {
        @memset(out[0..32], 0);
        return;
    };
    const values = [_]u64{ c.app_direct_sent.load(.acquire), c.app_relay_sent.load(.acquire), c.app_route_failed.load(.acquire), c.app_duplicate_dropped.load(.acquire) };
    for (values, 0..) |value, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], value, .little);
}

// ─── Lifecycle ───

/// Initialize a new meshguard instance.
/// Returns an opaque pointer, or null on failure.
///
/// `identity_seed`: 32 bytes of Ed25519 seed (from secure storage).
///                  Pass null to auto-generate a new identity.
/// `listen_port`:   UDP port for SWIM gossip (0 = ephemeral).
export fn meshguard_init(
    identity_seed: ?[*]const u8,
    listen_port: u16,
) ?*MeshguardContext {
    // Use c_allocator on Android (Bionic's malloc), GPA elsewhere
    const allocator = if (is_android)
        std.heap.c_allocator
    else blk: {
        // For non-Android, use GPA for debug safety
        break :blk std.heap.c_allocator; // TODO: restore GPA for desktop when needed
    };

    const ctx = allocator.create(MeshguardContext) catch return null;
    initContextStorage(ctx, allocator);

    // Identity: use provided seed or generate.
    var identity_seed_bytes: [32]u8 = undefined;
    if (identity_seed) |seed| {
        @memcpy(&identity_seed_bytes, seed[0..32]);
    } else {
        fillIdentitySeed(&identity_seed_bytes);
    }

    const kp = Ed25519.KeyPair.generateDeterministic(identity_seed_bytes) catch {
        destroyContext(ctx);
        return null;
    };
    const pub_bytes = kp.public_key.toBytes();
    @memcpy(&ctx.ed25519_seed, &identity_seed_bytes);
    @memcpy(&ctx.ed25519_public, &pub_bytes);

    // Derive X25519 keys for Noise handshakes
    // Use first 32 bytes of Ed25519 seed, clamped for Curve25519
    var x_priv = ctx.ed25519_seed;
    x_priv[0] &= 248;
    x_priv[31] &= 127;
    x_priv[31] |= 64;
    ctx.x25519_private = x_priv;
    ctx.x25519_public = X25519.recoverPublicKey(x_priv);
    ctx.wg_binding = lib.identity.Binding.signWithSeed(ctx.ed25519_seed, ctx.x25519_public) catch {
        destroyContext(ctx);
        return null;
    };

    // Initialize WireGuard device for tunnel support
    ctx.wg_device = @as(WgDevice, undefined);
    WgDevice.initInPlace(&ctx.wg_device.?, ctx.x25519_private, ctx.x25519_public);

    // Bind UDP socket — use ephemeral port (0) on mobile for reliability
    ctx.socket = Udp.UdpSocket.bind(listen_port) catch {
        destroyContext(ctx);
        return null;
    };

    return ctx;
}

/// Initialize a new meshguard instance with an IPv6 UDP socket.
export fn meshguard_init_ipv6(
    identity_seed: ?[*]const u8,
    listen_port: u16,
) ?*MeshguardContext {
    const ctx = meshguard_init(identity_seed, listen_port) orelse return null;
    closeContextSocket(ctx);
    ctx.socket = Udp.UdpSocket.bindAddr6(@splat(0), listen_port) catch {
        destroyContext(ctx);
        return null;
    };
    return ctx;
}

/// Initialize, binding the UDP socket to a SPECIFIC local IPv4 address instead
/// of INADDR_ANY. On a multi-homed / public-IP host this binds the daemon only
/// to the intended interface, so it never listens on or sources traffic from
/// LAN interfaces. `bind_ip`: 4 address bytes (e.g. {187,16,79,234}).
/// Returns the context, or null on failure.
export fn meshguard_init_bind(
    identity_seed: ?[*]const u8,
    listen_port: u16,
    bind_ip: ?[*]const u8,
) ?*MeshguardContext {
    // C-ABI entrypoint: a caller can pass NULL. Null-check before any deref or
    // allocation so a bad pointer fails cleanly instead of crashing in @memcpy.
    const ip_ptr = bind_ip orelse return null;
    const ctx = meshguard_init(identity_seed, listen_port) orelse return null;
    closeContextSocket(ctx);
    var addr: [4]u8 = undefined;
    @memcpy(&addr, ip_ptr[0..4]);
    ctx.socket = Udp.UdpSocket.bindAddr(addr, listen_port) catch {
        destroyContext(ctx);
        return null;
    };
    return ctx;
}

/// Destroy a meshguard instance, stopping all networking.
export fn meshguard_destroy(ctx: ?*MeshguardContext) void {
    const c = ctx orelse return;
    destroyContext(c);
}

/// Get our Ed25519 public key (32 bytes).
export fn meshguard_get_pubkey(ctx: ?*MeshguardContext, out: [*]u8) void {
    const c = ctx orelse return;
    @memcpy(out[0..32], &c.ed25519_public);
}

/// Get our Ed25519 public key as base64 (44 bytes + null terminator).
/// Get our WireGuard (X25519) public key (32 bytes), for example to request
/// a certificate that binds it.
export fn meshguard_get_wg_pubkey(ctx: ?*MeshguardContext, out: [*]u8) void {
    const c = ctx orelse return;
    @memcpy(out[0..32], &c.x25519_public);
}

export fn meshguard_get_pubkey_b64(ctx: ?*MeshguardContext, out: [*]u8) void {
    const c = ctx orelse return;
    var buf: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&buf, &c.ed25519_public);
    @memcpy(out[0..44], &buf);
    out[44] = 0;
}

/// Get our Ed25519 seed (32 bytes) for persistence.
/// The caller should store this securely (e.g., Android Keystore, iOS Keychain).
export fn meshguard_get_seed(ctx: ?*MeshguardContext, out: [*]u8) void {
    const c = ctx orelse return;
    @memcpy(out[0..32], &c.ed25519_seed);
}

// ─── Mesh join/leave ───

/// Join the mesh by connecting to a seed peer.
///
/// `seed_ip`:   IPv4 address as 4 bytes (e.g., {1, 2, 3, 4}).
/// `seed_port`: UDP port of the seed peer.
///
/// Returns 0 on success, -1 on failure.
export fn meshguard_join(
    ctx: ?*MeshguardContext,
    seed_ip: [*]const u8,
    seed_port: u16,
) i32 {
    const c = ctx orelse return -1;
    if (c.running.load(.acquire)) return -2; // already running

    // Derive mesh IP from our pubkey
    const ip_mod = @import("wireguard/ip.zig");
    const pk = Ed25519.PublicKey.fromBytes(c.ed25519_public) catch return -1;
    const mesh_ip = ip_mod.deriveFromPubkey(pk);

    // The actual gossip port is the seed's port (for the seed endpoint)
    const target_seed_port = if (seed_port == 0) @as(u16, 51821) else seed_port;

    // OUR gossip port is our actual bound port (could be ephemeral on mobile)
    const our_port = c.socket.?.port;

    // Create SWIM event handler
    const handler = EventHandler{
        .ctx = @ptrCast(c),
        .onPeerJoin = &onPeerJoinCallback,
        .onPeerDead = &onPeerDeadCallback,
        .onPeerPunched = null,
        .onAppMessage = &onAppMessageCallback,
        .onWgPacket = &onWgPacketCallback,
        .onRelayWgPacket = &onRelayWgPacketCallback,
        .hasActiveTunnel = &hasActiveTunnelCallback,
        .reinitiateHandshake = &reinitiateHandshakeCallback,
        .onAppStatus = &onAppStatusCallback,
    };

    // Initialize SWIM protocol — use OUR port, not the seed's port
    c.swim = SwimProtocol.init(
        &c.membership,
        c.socket.?,
        SwimConfig{
            .gossip_port = our_port, // Our actual bound port
            .gossip_interval_ms = 3000, // 3s for mobile (battery)
            .ping_timeout_ms = 5000, // 5s generous for mobile
        },
        c.ed25519_public,
        c.x25519_public,
        mesh_ip,
        our_port, // Our port for SWIM to advertise
        handler,
    );
    prepareSwim(c);

    // Seed the mesh — use the SEED's port for the seed endpoint
    var seed_addr: [4]u8 = undefined;
    @memcpy(&seed_addr, seed_ip[0..4]);
    const seeds = [_]messages.Endpoint{messages.Endpoint.initV4(seed_addr, target_seed_port)};
    c.swim.?.seedPeers(&seeds);

    // Start event loop on a background thread
    c.running.store(true, .release);
    c.event_loop_thread = std.Thread.spawn(.{}, eventLoop, .{c}) catch {
        c.running.store(false, .release);
        c.swim = null;
        return -1;
    };

    return 0;
}

/// Join the mesh by connecting to an IPv6 seed peer.
export fn meshguard_join_ipv6(
    ctx: ?*MeshguardContext,
    seed_ip: [*]const u8,
    seed_port: u16,
) i32 {
    const c = ctx orelse return -1;
    if (c.running.load(.acquire)) return -2;

    const ip_mod = @import("wireguard/ip.zig");
    const pk = Ed25519.PublicKey.fromBytes(c.ed25519_public) catch return -1;
    const mesh_ip = ip_mod.deriveFromPubkey(pk);
    const target_seed_port = if (seed_port == 0) @as(u16, 51821) else seed_port;
    const our_port = c.socket.?.port;

    const handler = EventHandler{
        .ctx = @ptrCast(c),
        .onPeerJoin = &onPeerJoinCallback,
        .onPeerDead = &onPeerDeadCallback,
        .onPeerPunched = null,
        .onAppMessage = &onAppMessageCallback,
        .onWgPacket = &onWgPacketCallback,
        .onRelayWgPacket = &onRelayWgPacketCallback,
        .hasActiveTunnel = &hasActiveTunnelCallback,
        .reinitiateHandshake = &reinitiateHandshakeCallback,
        .onAppStatus = &onAppStatusCallback,
    };

    c.swim = SwimProtocol.init(
        &c.membership,
        c.socket.?,
        SwimConfig{
            .gossip_port = our_port,
            .gossip_interval_ms = 3000,
            .ping_timeout_ms = 5000,
        },
        c.ed25519_public,
        c.x25519_public,
        mesh_ip,
        our_port,
        handler,
    );
    prepareSwim(c);

    var seed_addr6: [16]u8 = undefined;
    @memcpy(&seed_addr6, seed_ip[0..16]);
    const seeds = [_]messages.Endpoint{messages.Endpoint.initV6(seed_addr6, target_seed_port)};
    c.swim.?.seedPeers(&seeds);

    c.running.store(true, .release);
    c.event_loop_thread = std.Thread.spawn(.{}, eventLoop, .{c}) catch {
        c.running.store(false, .release);
        c.swim = null;
        return -1;
    };

    return 0;
}

/// Join the mesh via LAN multicast discovery (no seed required).
/// Peers on the same LAN will discover each other automatically.
///
/// Returns 0 on success, -1 on failure.
export fn meshguard_join_lan(
    ctx: ?*MeshguardContext,
) i32 {
    const c = ctx orelse return -1;
    if (c.running.load(.acquire)) return -2; // already running

    // Derive mesh IP from our pubkey
    const ip_mod = @import("wireguard/ip.zig");
    const pk = Ed25519.PublicKey.fromBytes(c.ed25519_public) catch return -1;
    const mesh_ip = ip_mod.deriveFromPubkey(pk);

    // OUR gossip port is our actual bound port
    const socket = c.socket orelse return -3; // Socket not initialized
    const our_port = socket.port;

    // Create SWIM event handler
    const handler = EventHandler{
        .ctx = @ptrCast(c),
        .onPeerJoin = &onPeerJoinCallback,
        .onPeerDead = &onPeerDeadCallback,
        .onPeerPunched = null,
        .onAppMessage = &onAppMessageCallback,
        .onWgPacket = &onWgPacketCallback,
        .onRelayWgPacket = &onRelayWgPacketCallback,
        .hasActiveTunnel = &hasActiveTunnelCallback,
        .reinitiateHandshake = &reinitiateHandshakeCallback,
        .onAppStatus = &onAppStatusCallback,
    };

    // Initialize SWIM protocol
    c.swim = SwimProtocol.init(
        &c.membership,
        socket,
        SwimConfig{
            .gossip_port = our_port,
        },
        c.ed25519_public,
        c.x25519_public,
        mesh_ip,
        our_port,
        handler,
    );
    prepareSwim(c);

    // Trust is open by default (enforce_trust = false)
    // For production, add authorized keys before join

    // Initialize LAN discovery (multicast beacon with the default app ID)
    c.lan_discovery = LanDiscovery.init(
        c.ed25519_public,
        our_port,
        lib.discovery.Lan.APP_ID_DEFAULT,
        &onLanPeerDiscovered,
        @ptrCast(c),
    ) catch |err| blk: {
        std.debug.print("  ⚠️  LAN discovery init failed: {}\n", .{err});
        break :blk null;
    };

    if (c.lan_discovery != null) {
        std.debug.print("  🔍 LAN discovery active on 239.99.99.1:{d}\n", .{lib.discovery.Lan.MULTICAST_PORT});
    }

    // Start event loop on a background thread
    c.running.store(true, .release);
    c.event_loop_thread = std.Thread.spawn(.{}, eventLoop, .{c}) catch {
        c.running.store(false, .release);
        c.swim = null;
        if (c.lan_discovery) |*lan| lan.deinit();
        c.lan_discovery = null;
        return -1;
    };

    return 0;
}

/// Leave the mesh gracefully.
export fn meshguard_leave(ctx: ?*MeshguardContext) void {
    const c = ctx orelse return;
    if (!c.running.load(.acquire)) return;

    // Broadcast leave to peers
    if (c.swim) |*swim| {
        swim.broadcastLeave();
        swim.stop();
    }

    // Stop LAN discovery
    if (c.lan_discovery) |*lan| {
        lan.deinit();
    }
    c.lan_discovery = null;

    c.running.store(false, .release);

    // Wait for event loop thread
    if (c.event_loop_thread) |t| {
        t.join();
    }
    c.event_loop_thread = null;
    c.swim = null;
    forgetNetwork(c);
}

/// After leaving: the next join may go through another relay, so drop every
/// peer, the WireGuard sessions with them, and the relay proof state. The
/// identity, contacts, certificate and settings stay.
fn forgetNetwork(c: *MeshguardContext) void {
    if (c.wg_device) |*dev| {
        var keys: [256][32]u8 = undefined;
        var n: usize = 0;
        {
            c.membership.lock.lockSharedUncancelable(zio());
            defer c.membership.lock.unlockShared(zio());
            var iter = c.membership.peers.iterator();
            while (iter.next()) |entry| {
                const wg = entry.value_ptr.wg_pubkey orelse continue;
                if (n == keys.len) break;
                keys[n] = wg;
                n += 1;
            }
        }
        c.wg_lock.lockUncancelable(zio());
        defer c.wg_lock.unlock(zio());
        for (keys[0..n]) |wg| dev.removePeer(wg);
    }
    c.membership.clear();
    c.last_relay_auth_ns = 0;
    c.last_recv_ns.store(0, .release);
    c.sent_lock.lockUncancelable(zio());
    c.sent_frames = std.mem.zeroes([256]SentFrame);
    c.sent_lock.unlock(zio());
}

/// Moves this context to another relay: leaves the current network (if
/// joined), pins `relay_pubkey` and joins through `seed_ip:seed_port`. The
/// identity, contacts and certificate carry over. Returns what
/// `meshguard_set_app_relay` or `meshguard_join` returns.
///
/// To use several relays at once, create one context per relay with the same
/// identity seed instead; each binds its own socket.
export fn meshguard_switch_relay(
    ctx: ?*MeshguardContext,
    relay_pubkey: [*]const u8,
    force: bool,
    seed_ip: [*]const u8,
    seed_port: u16,
) i32 {
    const c = ctx orelse return -1;
    meshguard_leave(c);
    const rc = meshguard_set_app_relay(c, relay_pubkey, force);
    if (rc != 0) return rc;
    return meshguard_join(c, seed_ip, seed_port);
}

// ─── Messaging ───

/// Send an encrypted app-level message to a peer.
///
/// `peer_pubkey`: 32-byte Ed25519 public key of the recipient.
/// `data`:        message payload.
/// `len`:         payload length (max 1024 bytes).
///
/// Returns 0 on success, -1 on failure.
///
/// Wire format (0x50):
///   [1B type=0x50] [32B dest_pubkey] [32B sender_pubkey] [12B nonce] [N ciphertext] [16B tag]
export fn meshguard_send(
    ctx: ?*MeshguardContext,
    peer_pubkey: [*]const u8,
    data: [*]const u8,
    len: u32,
) i32 {
    return sendApp(ctx, peer_pubkey, data, len, null);
}

/// Like `meshguard_send`, and writes the frame's 12-byte nonce to `out_nonce`
/// so the host can match a delivery status (`meshguard_set_on_delivery_status`).
export fn meshguard_send_ex(
    ctx: ?*MeshguardContext,
    peer_pubkey: [*]const u8,
    data: [*]const u8,
    len: u32,
    out_nonce: [*]u8,
) i32 {
    return sendApp(ctx, peer_pubkey, data, len, out_nonce);
}

fn sendApp(ctx: ?*MeshguardContext, peer_pubkey: [*]const u8, data: [*]const u8, len: u32, out_nonce: ?[*]u8) i32 {
    const c = ctx orelse return -1;
    if (!c.running.load(.acquire)) return -2;
    if (len > 1024) return -3;

    var target_key: [32]u8 = undefined;
    @memcpy(&target_key, peer_pubkey[0..32]);
    const contact_wg = contactKey(c, target_key);

    // Copy both entries under the membership lock; never retain iterator pointers.
    const snapshot = blk: {
        c.membership.lock.lockSharedUncancelable(zio());
        defer c.membership.lock.unlockShared(zio());
        const peer = c.membership.peers.get(target_key);
        var relay: ?Membership.Peer = null;
        if (c.app_relay_key) |pin| {
            if (!std.mem.eql(u8, &pin, &target_key) and !std.mem.eql(u8, &pin, &c.ed25519_public)) {
                if (c.membership.peers.get(pin)) |candidate| {
                    if (candidate.state == .alive and candidate.nat_type == .public and candidate.is_relay_capable) relay = candidate;
                }
            }
        } else if (lib.nat.Relay.selectRelayForPair(&c.membership.peers, c.ed25519_public, target_key)) |candidate| {
            relay = candidate.*;
        }
        break :blk .{ .peer = peer, .relay = relay };
    };
    // A contact that no relay describes (opaque relays) is reached through the relay only.
    const peer = snapshot.peer orelse if (contact_wg != null) contactOnlyPeer(target_key) else {
        if (c.on_undeliverable_cb) |cb| cb(peer_pubkey, data, len, -4);
        return -4;
    };
    const route = appRoute(peer, snapshot.relay, c.force_app_relay);
    if (route.direct == null and route.relay == null) {
        _ = c.app_route_failed.fetchAdd(1, .release);
        const rc: i32 = if (c.force_app_relay) -11 else -10;
        if (c.on_undeliverable_cb) |cb| cb(peer_pubkey, data, len, rc);
        return rc;
    }

    var msg_buf: [AppPacket.max_packet]u8 = undefined;
    var nonce: [12]u8 = undefined;
    zio().random(&nonce);
    const peer_x25519 = contact_wg orelse peer.wg_pubkey orelse {
        if (c.on_undeliverable_cb) |cb| cb(peer_pubkey, data, len, -6);
        return -6;
    };
    const total_len = AppPacket.seal(c.ed25519_public, c.x25519_private, target_key, peer_x25519, nonce, data[0..len], &msg_buf) catch return -7;
    const socket = c.socket orelse return -8;
    var sent_direct = false;
    if (route.direct) |ep| {
        if (socket.sendToEndpoint(msg_buf[0..total_len], ep)) |_| {
            sent_direct = true;
            _ = c.app_direct_sent.fetchAdd(1, .release);
        } else |_| {}
    }
    var sent_relay = false;
    if (c.force_app_relay or peer.nat_type != .public or !sent_direct) {
        if (route.relay) |ep| {
            if (socket.sendToEndpoint(msg_buf[0..total_len], ep)) |_| {
                sent_relay = true;
                _ = c.app_relay_sent.fetchAdd(1, .release);
                rememberSentFrame(c, target_key, nonce);
            } else |_| {}
        }
    }
    if (!sent_direct and !sent_relay) {
        _ = c.app_route_failed.fetchAdd(1, .release);
        return -9;
    }
    if (out_nonce) |out| @memcpy(out[0..12], &nonce);
    return 0;
}

// ─── Contacts ───

fn contactKey(c: *MeshguardContext, identity: [32]u8) ?[32]u8 {
    c.contacts_lock.lockUncancelable(zio());
    defer c.contacts_lock.unlock(zio());
    return c.contacts.get(identity);
}

/// A membership-shaped record for a contact we only know from the host:
/// no direct endpoint, so it is reached through the relay.
fn contactOnlyPeer(identity: [32]u8) Membership.Peer {
    return .{ .pubkey = identity, .name = "", .state = .dead, .gossip_endpoint = null, .wg_pubkey = null, .mesh_ip = .{ 0, 0, 0, 0 }, .wg_port = 0, .lamport = 0, .last_seen_ns = 0, .suspected_at_ns = null, .last_rtt_ns = null, .handshake_complete = false };
}

fn validContactKeys(ed25519: [32]u8, wg: [32]u8) bool {
    _ = Ed25519.PublicKey.fromBytes(ed25519) catch return false;
    // Reject low-order WireGuard keys: they make every shared secret predictable.
    const probe = [_]u8{0x48} ++ @as([30]u8, @splat(0x11)) ++ [_]u8{0x41};
    _ = X25519.scalarmult(probe, wg) catch return false;
    return true;
}

/// Register a contact: an identity and its WireGuard key, as learned by the
/// host (for example from a signed contact card). Frames to and from it use
/// this key, and it is reachable through the pinned relay even when the relay
/// does not describe it. Returns 0, -1 (no context), -3 (invalid key), or -5
/// (4096 contacts already registered).
export fn meshguard_add_contact(ctx: ?*MeshguardContext, ed25519: [*]const u8, wg: [*]const u8) i32 {
    const c = ctx orelse return -1;
    const identity = ed25519[0..32].*;
    const wg_key = wg[0..32].*;
    if (!validContactKeys(identity, wg_key)) return -3;
    c.contacts_lock.lockUncancelable(zio());
    defer c.contacts_lock.unlock(zio());
    if (!c.contacts.contains(identity) and c.contacts.count() >= MAX_CONTACTS) return -5;
    c.contacts.put(c.alloc, identity, wg_key) catch return -5;
    return 0;
}

/// Forget a contact. Returns 0 when it was registered, 1 when it was not.
export fn meshguard_remove_contact(ctx: ?*MeshguardContext, ed25519: [*]const u8) i32 {
    const c = ctx orelse return -1;
    c.contacts_lock.lockUncancelable(zio());
    defer c.contacts_lock.unlock(zio());
    return if (c.contacts.remove(ed25519[0..32].*)) 0 else 1;
}

export fn meshguard_clear_contacts(ctx: ?*MeshguardContext) void {
    const c = ctx orelse return;
    c.contacts_lock.lockUncancelable(zio());
    defer c.contacts_lock.unlock(zio());
    c.contacts.clearRetainingCapacity();
}

export fn meshguard_contact_count(ctx: ?*MeshguardContext) u32 {
    const c = ctx orelse return 0;
    c.contacts_lock.lockUncancelable(zio());
    defer c.contacts_lock.unlock(zio());
    return c.contacts.count();
}

/// Accept app frames only from registered contacts; others are dropped before
/// any decryption work.
export fn meshguard_set_contacts_only(ctx: ?*MeshguardContext, enabled: bool) void {
    const c = ctx orelse return;
    c.contacts_only.store(enabled, .release);
}

// ─── Delivery status ───

fn rememberSentFrame(c: *MeshguardContext, destination: [32]u8, nonce: [12]u8) void {
    c.sent_lock.lockUncancelable(zio());
    defer c.sent_lock.unlock(zio());
    c.sent_frames[c.sent_next] = .{ .valid = true, .destination = destination, .nonce = nonce };
    c.sent_next = (c.sent_next + 1) % c.sent_frames.len;
}

/// True (and forgets it) when we recently sent this frame through a relay.
fn takeSentFrame(c: *MeshguardContext, destination: [32]u8, nonce: [12]u8) bool {
    c.sent_lock.lockUncancelable(zio());
    defer c.sent_lock.unlock(zio());
    for (&c.sent_frames) |*frame| {
        if (frame.valid and std.mem.eql(u8, &frame.destination, &destination) and std.mem.eql(u8, &frame.nonce, &nonce)) {
            frame.valid = false;
            return true;
        }
    }
    return false;
}

/// Delivery statuses are accepted only from the pinned relay's endpoint and
/// only for a frame we sent through it. "Handshake again" re-proves our relay
/// endpoint at once; the host hears about every accepted status.
fn onAppStatusCallback(raw_ctx: *anyopaque, data: []const u8, src: messages.Endpoint) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    const status = AppStatus.decode(data) orelse return;
    const pin = ctx.app_relay_key orelse return;
    const relay_ep = blk: {
        ctx.membership.lock.lockSharedUncancelable(zio());
        defer ctx.membership.lock.unlockShared(zio());
        const relay = ctx.membership.peers.get(pin) orelse return;
        break :blk relay.gossip_endpoint orelse relay.public_endpoint orelse return;
    };
    if (!relay_ep.eql(src)) return;
    if (!takeSentFrame(ctx, status.destination, status.nonce)) return;
    if (status.code == .handshake_again) ctx.last_relay_auth_ns = 0;
    enqueueStatus(ctx, status);
    if (ctx.on_delivery_status_cb) |cb| cb(&status.destination, &status.nonce, @backingInt(status.code));
}

/// Single producer (the event loop); drops new statuses while the queue is full.
fn enqueueStatus(ctx: *MeshguardContext, status: AppStatus.Status) void {
    const read_idx = ctx.status_read.load(.acquire);
    const write_idx = ctx.status_write.load(.acquire);
    if (write_idx -% read_idx >= ctx.status_inbox.len) return;
    const slot = &ctx.status_inbox[write_idx % ctx.status_inbox.len];
    slot.destination = status.destination;
    slot.nonce = status.nonce;
    slot.code = @backingInt(status.code);
    @atomicStore(bool, &slot.valid, true, .release);
    _ = ctx.status_write.fetchAdd(1, .release);
}

/// Called on the event loop with (destination, nonce, code) when the pinned
/// relay reports a frame it did not forward: 1 offline, 2 destination not
/// admitted, 3 rate limited, 4 handshake again (re-proved automatically),
/// 5 not admitted, 6 relay overloaded. The pointers are valid only during the
/// call: hosts that handle statuses later, on another thread, poll
/// `meshguard_recv_delivery_status` instead.
export fn meshguard_set_on_delivery_status(
    ctx: ?*MeshguardContext,
    cb: ?*const fn ([*]const u8, [*]const u8, u8) callconv(.c) void,
) void {
    const c = ctx orelse return;
    c.on_delivery_status_cb = cb;
}

/// Take the next delivery status, for hosts that poll rather than handle the
/// callback on the event loop. Writes the destination identity (32 bytes), the
/// frame's nonce (12 bytes) and the code. Up to 64 statuses wait; newer ones
/// are dropped while the queue is full. Returns 0 when one was taken, 1 when
/// none is waiting, -1 without a context.
export fn meshguard_recv_delivery_status(
    ctx: ?*MeshguardContext,
    out_destination: [*]u8,
    out_nonce: [*]u8,
    out_code: *u8,
) i32 {
    const c = ctx orelse return -1;
    const read_idx = c.status_read.load(.acquire);
    if (read_idx == c.status_write.load(.acquire)) return 1;
    const slot = &c.status_inbox[read_idx % c.status_inbox.len];
    if (!@atomicLoad(bool, &slot.valid, .acquire)) return 1;
    @memcpy(out_destination[0..32], &slot.destination);
    @memcpy(out_nonce[0..12], &slot.nonce);
    out_code.* = slot.code;
    @atomicStore(bool, &slot.valid, false, .release);
    _ = c.status_read.fetchAdd(1, .release);
    return 0;
}

// ─── Timers ───

/// Milliseconds between pings to the relay (and other peers) while active;
/// mobile contexts default to 3000. Longer saves battery; delivery statuses tell
/// the client when it must prove its endpoint again. Returns 0 or -3.
export fn meshguard_set_keepalive_interval(ctx: ?*MeshguardContext, ms: u32) i32 {
    const c = ctx orelse return -1;
    if (ms != 0 and (ms < 1000 or ms > 600_000)) return -3;
    c.keepalive_ms.store(ms, .release);
    return 0;
}

/// Interval between proofs of our endpoint to the pinned relay (default
/// 15000 ms). Returns 0 or -3.
export fn meshguard_set_relay_proof_interval(ctx: ?*MeshguardContext, ms: u32) i32 {
    const c = ctx orelse return -1;
    if (ms != 0 and (ms < 5000 or ms > 3_600_000)) return -3;
    c.relay_proof_ms.store(ms, .release);
    return 0;
}

/// Receive the next app-level message from the inbox.
///
/// `out_data`:       buffer for message payload (must be >= 1024 bytes).
/// `out_len`:        receives the actual message length.
/// `out_sender`:     receives the 32-byte sender pubkey.
///
/// Returns 0 if a message was received, 1 if inbox empty, -1 on error.
export fn meshguard_recv(
    ctx: ?*MeshguardContext,
    out_data: [*]u8,
    out_len: *u32,
    out_sender: [*]u8,
) i32 {
    const c = ctx orelse return -1;

    const read_idx = c.inbox_read.load(.acquire);
    const write_idx = c.inbox_write.load(.acquire);
    if (read_idx == write_idx) return 1; // empty

    const slot = read_idx % 64;
    const msg = &c.inbox[slot];
    if (!@atomicLoad(bool, &msg.valid, .acquire)) return 1;

    @memcpy(out_data[0..msg.len], msg.data[0..msg.len]);
    out_len.* = msg.len;
    @memcpy(out_sender[0..32], &msg.sender_pubkey);

    @atomicStore(bool, &msg.valid, false, .release);
    _ = c.inbox_read.fetchAdd(1, .release);

    return 0;
}

// ─── Callbacks ───

/// Set the callback for incoming messages.
/// Called from the SWIM event loop thread.
///
/// Signature: void callback(data_ptr, data_len, sender_pubkey_ptr)
export fn meshguard_set_on_message(
    ctx: ?*MeshguardContext,
    cb: ?*const fn ([*]const u8, usize, [*]const u8) callconv(.c) void,
) void {
    const c = ctx orelse return;
    c.on_message_cb = cb;
}

/// Set the callback for peer events.
/// Called from the SWIM event loop thread.
///
/// Signature: void callback(event_type, peer_pubkey_ptr)
///   event_type: 1 = peer_joined, 2 = peer_left
export fn meshguard_set_on_peer_event(
    ctx: ?*MeshguardContext,
    cb: ?*const fn (u8, [*]const u8) callconv(.c) void,
) void {
    const c = ctx orelse return;
    c.on_peer_event_cb = cb;
}

/// Set the callback for undeliverable messages.
/// Called synchronously from meshguard_send() when the message cannot be delivered
/// (peer unknown, dead, no endpoint, or no WG pubkey).
///
/// Signature: void callback(dest_pubkey_ptr, data_ptr, data_len, error_code)
///   error_code: -4 = unknown peer, -5 = no endpoint, -6 = no WG pubkey, -10 = peer dead/left
export fn meshguard_set_on_undeliverable(
    ctx: ?*MeshguardContext,
    cb: ?*const fn ([*]const u8, [*]const u8, u32, i32) callconv(.c) void,
) void {
    const c = ctx orelse return;
    c.on_undeliverable_cb = cb;
}

// ─── Query ───

/// Get the number of alive peers.
export fn meshguard_peer_count(ctx: ?*MeshguardContext) u32 {
    const c = ctx orelse return 0;
    // SECURITY (H7): read lock vs the SWIM thread mutating `peers`.
    c.membership.lock.lockSharedUncancelable(zio());
    defer c.membership.lock.unlockShared(zio());
    var count: u32 = 0;
    var iter = c.membership.peers.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.state == .alive) count += 1;
    }
    return count;
}

/// Check if the mesh is currently running.
export fn meshguard_is_running(ctx: ?*MeshguardContext) bool {
    const c = ctx orelse return false;
    return c.running.load(.acquire);
}

// ─── Background lifecycle ───

/// Enter low-power suspended mode.
/// The event loop continues to receive incoming packets (messages, SOS,
/// WireGuard handshakes) but stops sending PINGs and LAN beacons to
/// conserve battery. Call meshguard_resume() to restore full operation.
export fn meshguard_suspend(ctx: ?*MeshguardContext) void {
    const c = ctx orelse return;
    c.suspended.store(true, .release);
    std.debug.print("  ⏸️  meshguard suspended (receive-only mode)\n", .{});
}

/// Resume full mesh operation from suspended mode.
/// Immediately re-announces to all known peers and restores normal
/// gossip intervals to refresh peer states.
export fn meshguard_resume(ctx: ?*MeshguardContext) void {
    const c = ctx orelse return;
    const was_suspended = c.suspended.load(.acquire);
    c.suspended.store(false, .release);

    if (was_suspended) {
        std.debug.print("  ▶️  meshguard resumed — re-pinging all peers\n", .{});
        // Defer the actual re-announce (pingAllAlive + LAN beacon) to the event-loop
        // thread. Those mutate SWIM/LAN state the loop owns — seq, pending[], the
        // gossip queue, membership iteration — so running them here on the host thread
        // races the loop's tick() (torn pending_count, iterator invalidation). Flip an
        // atomic and let the loop do it next active tick, mirroring how suspend works.
        c.resume_requested.store(true, .release);
    }
}

/// Check if the mesh is currently in suspended (low-power) mode.
export fn meshguard_is_suspended(ctx: ?*MeshguardContext) bool {
    const c = ctx orelse return false;
    return c.suspended.load(.acquire);
}

/// Get the timestamp (epoch ms) of the last received SWIM packet.
/// Returns 0 if no packets have been received.
/// Used by the host app for heartbeat/liveness detection.
export fn meshguard_last_recv_time(ctx: ?*MeshguardContext) u64 {
    const c = ctx orelse return 0;
    const ns = c.last_recv_ns.load(.acquire);
    if (ns <= 0) return 0;
    return @intCast(@divTrunc(ns, 1_000_000));
}

/// Get our actual bound UDP port.
export fn meshguard_get_bound_port(ctx: ?*MeshguardContext) u16 {
    const c = ctx orelse return 0;
    if (c.socket) |s| return s.port;
    return 0;
}

/// Debug info: write diagnostic data to out buffer (at least 32 bytes).
///   [0..2]   bound_port (LE)
///   [2..4]   total_peers (LE)
///   [4..6]   alive_peers (LE)
///   [6..7]   is_running (0/1)
///   [7..8]   has_swim (0/1)
///   [8..10]  swim_gossip_port (LE)
///   [10..14] membership_size (LE)
///   [14..18] pkts_sent (LE)
///   [18..22] pkts_recv (LE)
export fn meshguard_debug_info(ctx: ?*MeshguardContext, out: [*]u8) void {
    const c = ctx orelse {
        @memset(out[0..22], 0);
        return;
    };
    // SECURITY (H7): read lock over the membership reads below vs SWIM rehash.
    c.membership.lock.lockSharedUncancelable(zio());
    defer c.membership.lock.unlockShared(zio());

    // Bound port
    const bp = if (c.socket) |s| s.port else @as(u16, 0);
    out[0] = @intCast(bp & 0xFF);
    out[1] = @intCast((bp >> 8) & 0xFF);

    // Peer counts
    var total: u16 = 0;
    var alive: u16 = 0;
    var iter = c.membership.peers.iterator();
    while (iter.next()) |entry| {
        total += 1;
        if (entry.value_ptr.state == .alive) alive += 1;
    }
    out[2] = @intCast(total & 0xFF);
    out[3] = @intCast((total >> 8) & 0xFF);
    out[4] = @intCast(alive & 0xFF);
    out[5] = @intCast((alive >> 8) & 0xFF);

    // Flags
    out[6] = if (c.running.load(.acquire)) 1 else 0;
    out[7] = if (c.swim != null) 1 else 0;

    // SWIM gossip port
    const gp = if (c.swim) |s| s.config.gossip_port else @as(u16, 0);
    out[8] = @intCast(gp & 0xFF);
    out[9] = @intCast((gp >> 8) & 0xFF);

    // Membership map size
    const ms: u32 = @intCast(c.membership.peers.count());
    out[10] = @intCast(ms & 0xFF);
    out[11] = @intCast((ms >> 8) & 0xFF);
    out[12] = @intCast((ms >> 16) & 0xFF);
    out[13] = @intCast((ms >> 24) & 0xFF);

    // Packet counters
    const ps = if (c.swim) |s| s.pkts_sent else @as(u32, 0);
    out[14] = @intCast(ps & 0xFF);
    out[15] = @intCast((ps >> 8) & 0xFF);
    out[16] = @intCast((ps >> 16) & 0xFF);
    out[17] = @intCast((ps >> 24) & 0xFF);

    const pr = if (c.swim) |s| s.pkts_recv else @as(u32, 0);
    out[18] = @intCast(pr & 0xFF);
    out[19] = @intCast((pr >> 8) & 0xFF);
    out[20] = @intCast((pr >> 16) & 0xFF);
    out[21] = @intCast((pr >> 24) & 0xFF);

    // Raw recv (before decode) and tick count
    const rr = if (c.swim) |s| s.raw_recv else @as(u32, 0);
    out[22] = @intCast(rr & 0xFF);
    out[23] = @intCast((rr >> 8) & 0xFF);
    out[24] = @intCast((rr >> 16) & 0xFF);
    out[25] = @intCast((rr >> 24) & 0xFF);

    const tc = if (c.swim) |s| s.tick_count else @as(u32, 0);
    out[26] = @intCast(tc & 0xFF);
    out[27] = @intCast((tc >> 8) & 0xFF);
    out[28] = @intCast((tc >> 16) & 0xFF);
    out[29] = @intCast((tc >> 24) & 0xFF);
}

/// Get pubkeys of all alive peers.
///
/// `out_pubkeys`: flat buffer for N × 32-byte pubkeys (must be >= max_peers × 32).
/// `max_peers`:   maximum peers to return.
///
/// Returns the actual number of alive peers written.
export fn meshguard_get_peers(
    ctx: ?*MeshguardContext,
    out_pubkeys: [*]u8,
    max_peers: u32,
) u32 {
    const c = ctx orelse return 0;
    // SECURITY (H7): read lock vs the SWIM thread mutating `peers`.
    c.membership.lock.lockSharedUncancelable(zio());
    defer c.membership.lock.unlockShared(zio());
    var count: u32 = 0;
    var iter = c.membership.peers.iterator();
    while (iter.next()) |entry| {
        if (count >= max_peers) break;
        if (entry.value_ptr.state == .alive) {
            const offset = count * 32;
            @memcpy(out_pubkeys[offset..][0..32], &entry.value_ptr.pubkey);
            count += 1;
        }
    }
    return count;
}

/// Get info about a specific peer by pubkey.
///
/// `peer_pubkey`: 32-byte Ed25519 public key.
/// `out_info`:    48-byte buffer for peer info:
///   [0..4]   = IPv4 address (gossip endpoint)
///   [4..6]   = gossip port (big-endian)
///   [6..10]  = mesh IP
///   [10..11] = state (0=alive, 1=suspected, 2=dead, 3=left)
///   [11..12] = has_wg_pubkey (0/1)
///   [12..44] = wg_pubkey (if has_wg_pubkey)
///   [44..45] = connection_type (0=direct, 1=relayed, 2=unknown)
///   [45..46] = nat_type (0=unknown, 1=public, 2=cone, 3=symmetric)
///   [46..47] = is_relay_capable (0/1)
///
/// Returns 0 on success, -1 if peer not found.
export fn meshguard_get_peer_info(
    ctx: ?*MeshguardContext,
    peer_pubkey: [*]const u8,
    out_info: [*]u8,
) i32 {
    const c = ctx orelse return -1;

    var key: [32]u8 = undefined;
    @memcpy(&key, peer_pubkey[0..32]);

    // SECURITY (H7): copy the peer out under a read lock vs SWIM-thread rehash.
    const peer = blk: {
        c.membership.lock.lockSharedUncancelable(zio());
        defer c.membership.lock.unlockShared(zio());
        break :blk c.membership.peers.get(key);
    } orelse return -1;

    // Gossip endpoint IP + port
    if (peer.gossip_endpoint) |ep| {
        @memcpy(out_info[0..4], &ep.addr);
        out_info[4] = @intCast((ep.port >> 8) & 0xFF);
        out_info[5] = @intCast(ep.port & 0xFF);
    } else {
        @memset(out_info[0..6], 0);
    }

    // Mesh IP
    @memcpy(out_info[6..10], &peer.mesh_ip);

    // State
    out_info[10] = switch (peer.state) {
        .alive => 0,
        .suspected => 1,
        .dead => 2,
        .left => 3,
    };

    // WG pubkey
    if (peer.wg_pubkey) |wgpk| {
        out_info[11] = 1;
        @memcpy(out_info[12..44], &wgpk);
    } else {
        out_info[11] = 0;
        @memset(out_info[12..44], 0);
    }

    // Connection type: check if gossip endpoint matches a known relay peer
    // For now, use NAT type as a heuristic:
    //   - public NAT = direct connection likely
    //   - cone/symmetric = may be relayed
    //   - if peer's endpoint matches our seed servers = relayed
    out_info[44] = switch (peer.nat_type) {
        .public => 0, // direct
        .cone => 0, // hole-punched direct
        .symmetric => 1, // likely relayed
        .unknown => 2, // unknown
    };

    // NAT type
    out_info[45] = switch (peer.nat_type) {
        .unknown => 0,
        .public => 1,
        .cone => 2,
        .symmetric => 3,
    };

    // Relay capability
    out_info[46] = if (peer.is_relay_capable) 1 else 0;

    return 0;
}

// ─── Hostname-based join ───

/// Join the mesh by connecting to a seed peer specified by hostname:port string.
///
/// `host_str`:  Null-terminated hostname:port string (e.g., "relay.example.org:51821").
///
/// Resolves the hostname via DNS A record, then delegates to meshguard_join().
/// Returns 0 on success, -1 on failure, -11 on DNS resolution failure.
export fn meshguard_join_host(
    ctx: ?*MeshguardContext,
    host_str: [*:0]const u8,
) i32 {
    if (ctx == null) return -1;

    // Find the string length (null-terminated)
    var str_len: usize = 0;
    while (host_str[str_len] != 0) : (str_len += 1) {
        if (str_len > 255) return -11; // hostname too long
    }
    const host_slice = host_str[0..str_len];

    // Split hostname:port
    const colon_idx = std.mem.lastIndexOfScalar(u8, host_slice, ':') orelse return -11;
    const hostname = host_slice[0..colon_idx];
    const port_str = host_slice[colon_idx + 1 ..];

    const port = std.fmt.parseInt(u16, port_str, 10) catch return -11;

    // Resolve hostname via DNS A record
    const dns = lib.net.Dns;
    const addr = dns.resolveA(hostname) orelse return -11;

    // Delegate to meshguard_join
    return meshguard_join(ctx, &addr, port);
}

// ─── Internal: Event loop ───

fn eventLoop(ctx: *MeshguardContext) void {
    var lan_beacon_counter: u32 = 0;
    // Opt-in diagnostics (MESHGUARD_STATS=1): once-per-second counter deltas, so
    // we can see WHICH path is hot (tick spin vs inbound flood vs rate-cap drops
    // vs hole-punch) without per-packet logging. No-op unless the env var is set.
    const stats_enabled = std.c.getenv("MESHGUARD_STATS") != null;
    var last_stats_ns: i128 = 0;
    var s_tick: u32 = 0;
    var s_recv: u32 = 0;
    var s_sent: u32 = 0;
    var s_raw: u32 = 0;
    var s_drop: u32 = 0;
    while (ctx.running.load(.acquire)) {
        const is_suspended = ctx.suspended.load(.acquire);

        if (ctx.swim) |*swim| {
            if (stats_enabled) {
                const now: i128 = @intCast(std.Io.Timestamp.now(zio(), .awake).toNanoseconds());
                if (now - last_stats_ns >= 1_000_000_000) {
                    last_stats_ns = now;
                    std.debug.print("[stats] tick/s={d} recv/s={d} sent/s={d} raw/s={d} dropped/s={d} punches={d}\n", .{
                        swim.tick_count -% s_tick,              swim.pkts_recv -% s_recv,
                        swim.pkts_sent -% s_sent,               swim.raw_recv -% s_raw,
                        swim.sends_dropped_ratelimit -% s_drop, swim.holepuncher.activeCount(),
                    });
                    s_tick = swim.tick_count;
                    s_recv = swim.pkts_recv;
                    s_sent = swim.pkts_sent;
                    s_raw = swim.raw_recv;
                    s_drop = swim.sends_dropped_ratelimit;
                }
            }
            if (is_suspended) {
                // SUSPENDED: receive-only mode
                // - Poll socket for incoming packets (messages, SOS, handshakes)
                // - Process pending ping timeouts (prevent accumulation)
                // - Do NOT send PINGs or LAN beacons (saves battery)
                // - Sleep longer between ticks (1s vs ~200ms)
                swim.tickReceiveOnly() catch {};
                std.Io.sleep(zio(), std.Io.Duration.fromNanoseconds(800_000_000), .awake) catch {};
            } else {
                // ACTIVE: full gossip + discovery
                applyPendingOrgCert(ctx, swim);
                ctx.last_recv_ns.store(swim.last_recv_ns.load(.acquire), .release);
                const keepalive = ctx.keepalive_ms.load(.acquire);
                if (keepalive != 0) swim.config.gossip_interval_ms = keepalive;
                swim.tick() catch {};
                maintainPinnedRelayAuthentication(ctx);

                // Honor a pending resume() (requested from the host thread): do the
                // immediate re-announce HERE, on the loop thread that owns SWIM/LAN
                // state, so it can't race tick().
                if (ctx.resume_requested.swap(false, .acq_rel)) {
                    swim.pingAllAlive();
                    if (ctx.lan_discovery) |*lan| lan.sendBeacon();
                }
            }

            // LAN discovery: only in active mode
            if (!is_suspended) {
                if (ctx.lan_discovery) |*lan| {
                    _ = lan.recvBeacons();
                    lan_beacon_counter += 1;
                    if (lan_beacon_counter >= 10) {
                        lan.sendBeacon();
                        lan_beacon_counter = 0;
                    }
                }
            }
        } else {
            // No SWIM instance — sleep briefly
            std.Io.sleep(zio(), std.Io.Duration.fromNanoseconds(100_000_000), .awake) catch {};
        }
    }
}

/// The pinned relay's WireGuard key, if the relay vouched for it: signed with
/// its identity (binding or certificate) or derived from it. A key that only
/// third-party gossip claimed could belong to anyone impersonating the relay.
fn trustedRelayWgKey(pin: [32]u8, peer: Membership.Peer) ?[32]u8 {
    const wg_key = peer.wg_pubkey orelse return null;
    if (peer.wg_key_source != .gossip) return wg_key;
    if (lib.identity.Binding.isDerived(pin, wg_key)) return wg_key;
    return null;
}

/// A pinned public relay needs a fresh authenticated source endpoint after
/// restart/network change. A bounded control handshake uses the existing WG
/// protocol; it carries no app data and never counts as a direct app send.
fn maintainPinnedRelayAuthentication(ctx: *MeshguardContext) void {
    const pin = ctx.app_relay_key orelse return;
    const now: i128 = @intCast(std.Io.Timestamp.now(zio(), .awake).toNanoseconds());
    const proof_ms: i128 = switch (ctx.relay_proof_ms.load(.acquire)) {
        0 => DEFAULT_RELAY_PROOF_MS,
        else => |ms| ms,
    };
    if (ctx.last_relay_auth_ns != 0 and now - ctx.last_relay_auth_ns < proof_ms * std.time.ns_per_ms) return;
    const peer = blk: {
        ctx.membership.lock.lockSharedUncancelable(zio());
        defer ctx.membership.lock.unlockShared(zio());
        break :blk ctx.membership.peers.get(pin) orelse return;
    };
    if (peer.state != .alive) return;
    const wg_key = trustedRelayWgKey(pin, peer) orelse return;
    const ep = peer.gossip_endpoint orelse peer.public_endpoint orelse return;
    ctx.last_relay_auth_ns = now;
    ctx.wg_lock.lockUncancelable(zio());
    defer ctx.wg_lock.unlock(zio());
    if (ctx.wg_device) |*dev| {
        const slot = dev.addPeerWithEndpoint(pin, wg_key, ep, peer.mesh_ip, peer.mesh_ip6) catch return;
        const initiation = dev.initiateHandshake(slot) catch return;
        if (ctx.socket) |socket| _ = socket.sendToEndpoint(std.mem.asBytes(&initiation), ep) catch return;
    }
}

/// Callback when a LAN peer is discovered via multicast beacon.
fn onLanPeerDiscovered(raw_ctx: *anyopaque, pubkey: [32]u8, addr: [4]u8, gossip_port: u16) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    if (ctx.swim) |*swim| {
        // Feed the LAN peer into SWIM — same as if we received a PING from them
        swim.registerOrUpdatePeer(pubkey, addr, gossip_port);
    }
}

// ─── Internal: SWIM event callbacks ───

fn onPeerJoinCallback(raw_ctx: *anyopaque, peer: *const Membership.Peer) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    if (ctx.on_peer_event_cb) |cb| {
        cb(1, &peer.pubkey); // 1 = joined
    }
}

fn onPeerDeadCallback(raw_ctx: *anyopaque, pubkey: [32]u8) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    if (ctx.on_peer_event_cb) |cb| {
        cb(2, &pubkey); // 2 = left/dead
    }
}

// ─── Internal: App-level message handling ───

/// Decrypt and enqueue an incoming app message.
/// Called from the SWIM event loop when we receive a 0x50-type packet for us.
pub fn handleAppMessage(ctx: *MeshguardContext, data: []const u8) void {
    // Format: [0x50] [32B dest_pubkey] [32B sender_pubkey] [12B nonce] [N ciphertext] [16B tag]
    if (data.len < 1 + 32 + 32 + 12 + 16) return;
    if (data[0] != 0x50) return;

    // dest at [1..33] (already verified by SWIM)
    const sender_pubkey = data[33..65];
    const nonce: [12]u8 = data[65..77].*;
    const payload_len = data.len - 77 - 16;
    if (payload_len > 1024) return;

    var peer_key: [32]u8 = undefined;
    @memcpy(&peer_key, sender_pubkey);
    // A registered contact's key wins; in contacts-only mode nobody else is
    // even decrypted.
    const peer_x25519 = contactKey(ctx, peer_key) orelse blk: {
        if (ctx.contacts_only.load(.acquire)) return;
        const peer = ctx.membership.peers.get(peer_key) orelse return;
        break :blk peer.wg_pubkey orelse return;
    };
    var plaintext: [1024]u8 = undefined;
    _ = AppPacket.open(ctx.ed25519_public, ctx.x25519_private, peer_x25519, data, &plaintext) catch return;

    for (ctx.app_seen) |seen| {
        if (seen.valid and std.mem.eql(u8, &seen.sender, sender_pubkey) and std.mem.eql(u8, &seen.nonce, &nonce)) {
            _ = ctx.app_duplicate_dropped.fetchAdd(1, .release);
            return;
        }
    }

    // Enqueue to inbox (Finding #8: capacity check + atomic valid)
    const read_idx = ctx.inbox_read.load(.acquire);
    const write_idx = ctx.inbox_write.load(.acquire);
    if (write_idx -% read_idx >= 64) return; // Full — drop message

    ctx.app_seen[ctx.app_seen_next] = .{ .valid = true, .sender = sender_pubkey[0..32].*, .nonce = nonce };
    ctx.app_seen_next = (ctx.app_seen_next + 1) % ctx.app_seen.len;

    const slot = write_idx % 64;
    ctx.inbox[slot].sender_pubkey = peer_key;
    ctx.inbox[slot].len = @intCast(payload_len);
    @memcpy(ctx.inbox[slot].data[0..payload_len], plaintext[0..payload_len]);
    @atomicStore(bool, &ctx.inbox[slot].valid, true, .release);
    _ = ctx.inbox_write.fetchAdd(1, .release);

    // Fire callback if set
    if (ctx.on_message_cb) |cb| {
        cb(plaintext[0..payload_len].ptr, payload_len, sender_pubkey.ptr);
    }
}

/// Callback adapter: SWIM → FFI app message delivery
fn onAppMessageCallback(raw_ctx: *anyopaque, data: []const u8) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    handleAppMessage(ctx, data);
}

// ─── Internal: WireGuard tunnel packet handling ───

/// Callback adapter: SWIM → FFI WG packet dispatch
/// S2: report whether we hold a live userspace WG tunnel to `wg_pubkey`, so SWIM's
/// incarnation restart detection can use it as an origin-authentication signal (a
/// spoofer cannot forge a live WG session). False when no device exists yet.
fn hasActiveTunnelCallback(raw_ctx: *anyopaque, wg_pubkey: [32]u8) bool {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    if (ctx.wg_device) |*dev| return dev.hasActiveTunnel(wg_pubkey);
    return false;
}

/// S2 heal: re-initiate a WG handshake to a restarted peer whose stale session we
/// still hold — only when we are the tie-break initiator, so we don't race a
/// simultaneous init. A refresh, not a teardown; device-rate-limited. No-op if the
/// peer isn't registered in our device.
fn reinitiateHandshakeCallback(raw_ctx: *anyopaque, peer: *const Membership.Peer) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    if (ctx.wg_device) |*dev| {
        const wg_key = peer.wg_pubkey orelse return;
        if (std.mem.order(u8, &dev.static_public, &wg_key) != .lt) return; // only the initiator
        const ep: messages.Endpoint = if (peer.gossip_endpoint) |e| e else if (peer.public_endpoint) |pe| pe else return;
        if (dev.reinitiate(wg_key)) |init_msg| {
            _ = sendWgCiphertextToPeer(ctx, peer.pubkey, std.mem.asBytes(&init_msg), ep, null);
        } else |_| {}
    }
}

fn relayEndpointForPeer(ctx: *MeshguardContext, target_pubkey: [32]u8) ?messages.Endpoint {
    if (ctx.swim != null) {
        const relay = lib.nat.Relay.selectRelayForPair(&ctx.membership.peers, ctx.ed25519_public, target_pubkey) orelse return null;
        return relay.gossip_endpoint orelse relay.public_endpoint;
    }
    return null;
}

fn sendRelayFrame(ctx: *MeshguardContext, target_pubkey: [32]u8, data: []const u8, relay_endpoint: messages.Endpoint) bool {
    var relay_buf: [lib.nat.Relay.MAX_RELAY_DATAGRAM]u8 = undefined;
    const relay_len = lib.nat.Relay.encodeRelayData(&relay_buf, ctx.ed25519_public, target_pubkey, data) catch return false;
    if (ctx.socket) |*sock| {
        _ = sock.sendToEndpoint(relay_buf[0..relay_len], relay_endpoint) catch return false;
        return true;
    }
    return false;
}

fn sendWgCiphertextToPeer(
    ctx: *MeshguardContext,
    target_pubkey: [32]u8,
    data: []const u8,
    direct_endpoint: ?messages.Endpoint,
    preferred_relay: ?messages.Endpoint,
) bool {
    if (preferred_relay) |relay_ep| return sendRelayFrame(ctx, target_pubkey, data, relay_ep);

    var target_nat: messages.NatType = .unknown;
    var relay_ep: ?messages.Endpoint = null;
    if (ctx.swim) |*swim| {
        ctx.membership.lock.lockSharedUncancelable(zio());
        if (ctx.membership.peers.get(target_pubkey)) |peer| target_nat = peer.nat_type;
        relay_ep = relayEndpointForPeer(ctx, target_pubkey);
        ctx.membership.lock.unlockShared(zio());

        const relay_available = relay_ep != null;
        if (direct_endpoint) |ep| {
            const path = lib.nat.Relay.choosePath(swim.our_nat_type, target_nat, true, relay_available);
            if (path == .direct or path == .holepunch or !relay_available) {
                if (ctx.socket) |*sock| {
                    _ = sock.sendToEndpoint(data, ep) catch return false;
                    return true;
                }
                return false;
            }
        }
    } else if (direct_endpoint) |ep| {
        if (ctx.socket) |*sock| {
            _ = sock.sendToEndpoint(data, ep) catch return false;
            return true;
        }
        return false;
    }

    if (relay_ep) |ep| return sendRelayFrame(ctx, target_pubkey, data, ep);
    return false;
}

fn onWgPacketCallback(raw_ctx: *anyopaque, data: []const u8, sender_addr: [4]u8, sender_port: u16) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    handleWgPacket(ctx, data, sender_addr, sender_port);
}

fn onRelayWgPacketCallback(raw_ctx: *anyopaque, data: []const u8, sender_pubkey: [32]u8, relay_endpoint: messages.Endpoint) void {
    const ctx: *MeshguardContext = @ptrCast(@alignCast(raw_ctx));
    handleRelayWgPacket(ctx, data, sender_pubkey, relay_endpoint);
}

/// Process incoming WireGuard packets (Type 1/2/4) for tunnel support.
fn handleWgPacket(ctx: *MeshguardContext, data: []const u8, sender_addr: [4]u8, sender_port: u16) void {
    if (data.len < 4) return;
    if (ctx.wg_device == null) return;

    const pkt_type = Device.PacketType.classify(data);
    switch (pkt_type) {
        .wg_handshake_init => {
            // Incoming handshake initiation — we are the responder
            // Need exclusive lock: modifies peer state, index tables
            ctx.wg_lock.lockUncancelable(zio());
            defer ctx.wg_lock.unlock(zio());

            var dev = &ctx.wg_device.?;
            if (data.len < @sizeOf(noise.HandshakeInitiation)) return;
            const msg: *const noise.HandshakeInitiation = @ptrCast(@alignCast(data.ptr));

            // Finding #7 (v2): Attempt handleInitiation first.
            // Only auto-register if it fails with UnknownPeer.
            // This avoids the double X25519 multiplication on every packet.
            const result = dev.handleInitiation(msg, sender_addr) catch |err| blk: {
                if (err != error.UnknownPeer) return;

                // Auto-register responder peer from membership table
                if (noise.verifyMac1(dev.static_public, msg)) {
                    if (noise.decryptInitiatorStatic(
                        dev.static_private,
                        dev.static_public,
                        msg,
                    )) |preamble| {
                        // Look up in membership by X25519 key
                        var iter = ctx.membership.peers.iterator();
                        while (iter.next()) |entry| {
                            const m_peer = entry.value_ptr;
                            if (m_peer.wg_pubkey) |wg_pk| {
                                if (std.mem.eql(u8, &wg_pk, &preamble.initiator_static)) {
                                    if (m_peer.gossip_endpoint) |ep| {
                                        _ = dev.addPeerWithMeshIp(
                                            m_peer.pubkey,
                                            wg_pk,
                                            ep.addr,
                                            ep.port,
                                            m_peer.mesh_ip,
                                        ) catch {};
                                    }
                                    break;
                                }
                            }
                        }
                    } else |_| {}
                }

                // Retry after auto-registration. Use the "admitted" path so the
                // rate limiter is not charged a second time for this one
                // legitimate handshake (the first attempt already consumed a
                // token before failing with UnknownPeer).
                break :blk dev.handleInitiationAdmitted(msg) catch return;
            };

            // Send handshake response back to the initiator
            const resp_bytes: [*]const u8 = @ptrCast(&result.response);
            const socket = ctx.socket orelse return;
            _ = socket.sendTo(resp_bytes[0..@sizeOf(noise.HandshakeResponse)], sender_addr, sender_port) catch return;

            // Update the peer's endpoint to the sender's address
            if (dev.peers[result.slot]) |*peer| {
                peer.endpoint_addr = sender_addr;
                peer.endpoint_port = sender_port;
            }

            std.debug.print("  🔑 WG handshake init handled (slot {d}), response sent\n", .{result.slot});
        },
        .wg_handshake_resp => {
            // Incoming handshake response — we were the initiator
            // Need exclusive lock: modifies tunnel keys
            ctx.wg_lock.lockUncancelable(zio());
            defer ctx.wg_lock.unlock(zio());

            var dev = &ctx.wg_device.?;
            if (data.len < @sizeOf(noise.HandshakeResponse)) return;
            const msg: *const noise.HandshakeResponse = @ptrCast(@alignCast(data.ptr));

            const slot = dev.handleResponse(msg) catch return;

            // Update the peer's endpoint
            if (dev.peers[slot]) |*peer| {
                peer.endpoint_addr = sender_addr;
                peer.endpoint_port = sender_port;
            }

            std.debug.print("  🔑 WG handshake complete (slot {d}), tunnel ready\n", .{slot});
        },
        .wg_transport => {
            // Incoming transport data — decrypt and enqueue to tunnel inbox
            // Shared lock: decrypt only reads keys, counter is atomic
            ctx.wg_lock.lockSharedUncancelable(zio());
            defer ctx.wg_lock.unlockShared(zio());

            var dev = &ctx.wg_device.?;
            var plaintext: [1500]u8 = undefined;
            const result = dev.decryptTransport(data, &plaintext) catch return;

            // identity_key is captured inside decryptTransport under the device
            // lock, so we never re-read peers[slot] here (avoids the removePeer race).
            const sender_identity: [32]u8 = result.identity_key;

            // Strip the 4-byte length framing header.
            // Wire format: [2B reserved=0] [2B LE length] [payload]
            if (result.len < 4) return;
            if (plaintext[0] != 0 or plaintext[1] != 0) return; // Not our framing
            const payload_len = std.mem.readInt(u16, plaintext[2..4], .little);
            const payload_end = tunnelFramePayloadLen(result.len, payload_len) orelse return; // Corrupt frame
            enqueueTunnelMessage(ctx, sender_identity, plaintext[4..][0..payload_end]);
        },
        else => {}, // Cookie (Type 3) not implemented yet
    }
}

fn handleRelayWgPacket(ctx: *MeshguardContext, data: []const u8, sender_pubkey: [32]u8, relay_endpoint: messages.Endpoint) void {
    if (data.len < 4) return;
    if (ctx.wg_device == null) return;

    const pkt_type = Device.PacketType.classify(data);
    switch (pkt_type) {
        .wg_handshake_init => {
            ctx.wg_lock.lockUncancelable(zio());
            defer ctx.wg_lock.unlock(zio());

            var dev = &ctx.wg_device.?;
            if (data.len < @sizeOf(noise.HandshakeInitiation)) return;
            const msg: *const noise.HandshakeInitiation = @ptrCast(@alignCast(data.ptr));

            const result = dev.handleInitiation(msg, relay_endpoint.addr) catch |err| blk: {
                if (err != error.UnknownPeer) return;

                if (ctx.membership.peers.get(sender_pubkey)) |m_peer| {
                    if (m_peer.wg_pubkey) |wg_pk| {
                        const ep = m_peer.gossip_endpoint orelse m_peer.public_endpoint orelse relay_endpoint;
                        _ = dev.addPeerWithEndpoint(
                            m_peer.pubkey,
                            wg_pk,
                            ep,
                            m_peer.mesh_ip,
                            m_peer.mesh_ip6,
                        ) catch {};
                    }
                }

                break :blk dev.handleInitiationAdmitted(msg) catch return;
            };

            const resp_bytes: [*]const u8 = @ptrCast(&result.response);
            _ = sendRelayFrame(ctx, sender_pubkey, resp_bytes[0..@sizeOf(noise.HandshakeResponse)], relay_endpoint);

            std.debug.print("  🔑 WG handshake init handled via relay (slot {d})\n", .{result.slot});
        },
        .wg_handshake_resp => {
            ctx.wg_lock.lockUncancelable(zio());
            defer ctx.wg_lock.unlock(zio());

            var dev = &ctx.wg_device.?;
            if (data.len < @sizeOf(noise.HandshakeResponse)) return;
            const msg: *const noise.HandshakeResponse = @ptrCast(@alignCast(data.ptr));
            const slot = dev.handleResponse(msg) catch return;

            std.debug.print("  🔑 WG handshake complete via relay (slot {d}), tunnel ready\n", .{slot});
        },
        .wg_transport => {
            ctx.wg_lock.lockSharedUncancelable(zio());
            defer ctx.wg_lock.unlockShared(zio());

            var dev = &ctx.wg_device.?;
            var plaintext: [1500]u8 = undefined;
            const result = dev.decryptTransport(data, &plaintext) catch return;
            const sender_identity: [32]u8 = result.identity_key;

            if (result.len < 4) return;
            if (plaintext[0] != 0 or plaintext[1] != 0) return;
            const payload_len = std.mem.readInt(u16, plaintext[2..4], .little);
            const payload_end = tunnelFramePayloadLen(result.len, payload_len) orelse return;
            enqueueTunnelMessage(ctx, sender_identity, plaintext[4..][0..payload_end]);
        },
        else => {},
    }
}

/// Enqueue a decrypted tunnel message to the tunnel inbox.
/// Finding #3: Capacity check + atomic valid flag to prevent torn reads.
fn enqueueTunnelMessage(ctx: *MeshguardContext, sender_identity: [32]u8, data: []const u8) void {
    if (data.len > 1500) return;

    const read_idx = ctx.tunnel_inbox_read.load(.acquire);
    const write_idx = ctx.tunnel_inbox_write.load(.acquire);
    if (write_idx -% read_idx >= 256) return; // Full — drop packet

    const slot = write_idx % 256;
    ctx.tunnel_inbox[slot].sender_identity = sender_identity;
    ctx.tunnel_inbox[slot].len = @intCast(data.len);
    @memcpy(ctx.tunnel_inbox[slot].data[0..data.len], data);

    // Set valid AFTER data is fully written (release barrier)
    @atomicStore(bool, &ctx.tunnel_inbox[slot].valid, true, .release);
    _ = ctx.tunnel_inbox_write.fetchAdd(1, .release);
}

// ─── Tunnel FFI exports ───

/// Open a WireGuard tunnel to a peer.
///
/// Looks up the peer by Ed25519 pubkey in the membership table,
/// registers them in the WgDevice, and sends a handshake initiation.
///
/// `peer_pubkey`: 32-byte Ed25519 public key of the peer.
///
/// Returns 0 on success, negative on error:
///   -1: null context
///   -2: not running
///   -3: peer not found in membership
///   -4: peer has no WG pubkey
///   -5: peer has no endpoint
///   -6: failed to add peer to WG device
///   -7: handshake initiation failed
///   -8: failed to send handshake packet
export fn meshguard_tunnel_open(
    ctx: ?*MeshguardContext,
    peer_pubkey: [*]const u8,
) i32 {
    const c = ctx orelse return -1;
    if (!c.running.load(.acquire)) return -2;
    if (c.wg_device == null) return -1;

    var target_key: [32]u8 = undefined;
    @memcpy(&target_key, peer_pubkey[0..32]);

    // Look up peer in membership table for endpoint and WG pubkey.
    // SECURITY (H7): copy under a read lock vs SWIM-thread rehash (released
    // before wg_lock below, preserving membership→wg_lock ordering).
    const peer = blk: {
        c.membership.lock.lockSharedUncancelable(zio());
        defer c.membership.lock.unlockShared(zio());
        break :blk c.membership.peers.get(target_key);
    } orelse return -3;
    const peer_x25519 = peer.wg_pubkey orelse return -4;
    const ep = peer.gossip_endpoint orelse return -5;

    // Derive mesh IP for the peer
    const ip_mod = @import("wireguard/ip.zig");
    const pk = Ed25519.PublicKey.fromBytes(target_key) catch return -3;
    const mesh_ip = ip_mod.deriveFromPubkey(pk);

    // Exclusive lock: adding peer + initiating handshake modifies device state
    c.wg_lock.lockUncancelable(zio());
    defer c.wg_lock.unlock(zio());

    var dev = &c.wg_device.?;
    const slot = dev.addPeerWithMeshIp(target_key, peer_x25519, ep.addr, ep.port, mesh_ip) catch return -6;

    // Initiate WG Noise IK handshake
    const init_msg = dev.initiateHandshake(slot) catch return -7;

    // Send handshake initiation packet to peer
    const init_bytes: [*]const u8 = @ptrCast(&init_msg);
    if (!sendWgCiphertextToPeer(c, target_key, init_bytes[0..@sizeOf(noise.HandshakeInitiation)], ep, null)) return -8;

    std.debug.print("  \xf0\x9f\x94\x91 Tunnel handshake sent to {x:0>2}{x:0>2}...\n", .{ target_key[0], target_key[1] });
    return 0;
}

/// Send data through a WireGuard tunnel to a peer.
///
/// Encrypts the data with the peer's tunnel and sends it as a
/// WG Type 4 transport packet over UDP.
///
/// `peer_pubkey`: 32-byte Ed25519 public key of the peer.
/// `data`:        payload to send.
/// `len`:         payload length (max 1400 bytes, MTU limit).
///
/// Returns 0 on success, negative on error.
export fn meshguard_tunnel_send(
    ctx: ?*MeshguardContext,
    peer_pubkey: [*]const u8,
    data: [*]const u8,
    len: u32,
) i32 {
    const c = ctx orelse return -1;
    if (!c.running.load(.acquire)) return -2;
    if (len > 1396) return -3; // MTU limit (1400 - 4 byte framing header)
    if (c.wg_device == null) return -1;

    var target_key: [32]u8 = undefined;
    @memcpy(&target_key, peer_pubkey[0..32]);

    // Shared lock for encrypt (keys are read-only, nonce is atomic)
    // NOTE: Do NOT defer unlock — we manually unlock before I/O for rekey lock upgrade
    c.wg_lock.lockSharedUncancelable(zio());

    var dev = &c.wg_device.?;

    // Find peer by identity key
    const slot = dev.findByIdentity(target_key) orelse {
        c.wg_lock.unlockShared(zio());
        return -4;
    };
    const peer = if (dev.peers[slot]) |*p| p else {
        c.wg_lock.unlockShared(zio());
        return -4;
    };

    // Finding #4 (v2): Framing header with leading zeros.
    // [2B reserved=0] [2B LE payload_length] [payload]
    // Leading 0x00 ensures tunnel.zig sees version==0, bypassing IPv4/IPv6.
    const data_len: usize = @intCast(len);
    var framed_buf: [1400]u8 = undefined;
    framed_buf[0] = 0;
    framed_buf[1] = 0;
    std.mem.writeInt(u16, framed_buf[2..4], @intCast(data_len), .little);
    @memcpy(framed_buf[4..][0..data_len], data[0..data_len]);
    const framed_len = data_len + 4;

    // Encrypt the framed data
    var out_buf: [1500]u8 = undefined;
    const encrypted_len = dev.encryptForPeer(slot, framed_buf[0..framed_len], &out_buf) catch {
        c.wg_lock.unlockShared(zio());
        return -5;
    };

    // Finding #2 (v2): Check rekey flag, but DON'T initiate under shared lock.
    // Save the flag, we'll upgrade to exclusive lock after releasing shared.
    var requires_rekey = false;
    if (peer.active_tunnel) |*tun| {
        if (tun.needs_rekey) {
            tun.needs_rekey = false;
            requires_rekey = true;
        }
    }

    // Read endpoint while we have the lock
    const direct_ep = peer.endpoint();

    // Release shared lock before I/O
    c.wg_lock.unlockShared(zio());

    // Send via UDP to peer's endpoint
    if (c.socket == null) return -6;
    if (!sendWgCiphertextToPeer(c, target_key, out_buf[0..encrypted_len], direct_ep, null)) return -7;

    // Rekeying requires exclusive lock (modifies index_map)
    if (requires_rekey) {
        c.wg_lock.lockUncancelable(zio());
        defer c.wg_lock.unlock(zio());
        if (c.wg_device) |*wd| {
            var rekey_dev = wd;
            if (rekey_dev.initiateHandshake(slot)) |rekey_msg| {
                const rekey_bytes: [*]const u8 = @ptrCast(&rekey_msg);
                _ = sendWgCiphertextToPeer(c, target_key, rekey_bytes[0..@sizeOf(noise.HandshakeInitiation)], direct_ep, null);
            } else |_| {}
        }
    }

    return 0;
}

/// Receive the next decrypted tunnel message.
///
/// `out_data`:   buffer for decrypted payload (must be >= 1500 bytes).
/// `out_len`:    receives the actual payload length.
/// `out_sender`: receives the 32-byte Ed25519 pubkey of the sender.
///
/// Returns 0 if a message was received, 1 if inbox empty, -1 on error.
export fn meshguard_tunnel_recv(
    ctx: ?*MeshguardContext,
    out_data: [*]u8,
    out_len: *u32,
    out_sender: [*]u8,
) i32 {
    const c = ctx orelse return -1;

    const read_idx = c.tunnel_inbox_read.load(.acquire);
    const write_idx = c.tunnel_inbox_write.load(.acquire);
    if (read_idx == write_idx) return 1; // empty

    const slot = read_idx % 256;
    const msg = &c.tunnel_inbox[slot];

    // Atomic load of valid flag (acquire barrier matches producer's release)
    if (!@atomicLoad(bool, &msg.valid, .acquire)) return 1;

    @memcpy(out_data[0..msg.len], msg.data[0..msg.len]);
    out_len.* = msg.len;
    @memcpy(out_sender[0..32], &msg.sender_identity);

    @atomicStore(bool, &msg.valid, false, .release);
    _ = c.tunnel_inbox_read.fetchAdd(1, .release);

    return 0;
}

/// Close a WireGuard tunnel to a peer.
///
/// Removes the peer from the WgDevice, clearing all tunnel state.
///
/// `peer_pubkey`: 32-byte Ed25519 public key of the peer.
export fn meshguard_tunnel_close(
    ctx: ?*MeshguardContext,
    peer_pubkey: [*]const u8,
) void {
    const c = ctx orelse return;
    if (c.wg_device == null) return;

    var target_key: [32]u8 = undefined;
    @memcpy(&target_key, peer_pubkey[0..32]);

    // Exclusive lock: removing peer modifies device state
    c.wg_lock.lockUncancelable(zio());
    defer c.wg_lock.unlock(zio());

    var dev = &c.wg_device.?;

    // Find peer by identity key to get their WG pubkey
    if (dev.findByIdentity(target_key)) |slot| {
        if (dev.peers[slot]) |peer| {
            dev.removePeer(peer.wg_pubkey);
            std.debug.print("  \xf0\x9f\x94\x91 Tunnel closed with {x:0>2}{x:0>2}...\n", .{ target_key[0], target_key[1] });
        }
    }
}

test "destroyContext releases FFI-owned membership allocations" {
    const allocator = std.testing.allocator;
    const ctx = try allocator.create(MeshguardContext);
    initContextStorage(ctx, allocator);

    const peer_name = try allocator.dupe(u8, "ffi-peer");
    try ctx.membership.upsert(.{
        .pubkey = @as([32]u8, @splat(0x42)),
        .name = peer_name,
        .state = .alive,
        .gossip_endpoint = null,
        .wg_pubkey = null,
        .mesh_ip = .{ 10, 99, 0, 42 },
        .wg_port = 51830,
        .lamport = 1,
        .last_seen_ns = 0,
        .suspected_at_ns = null,
        .last_rtt_ns = null,
        .handshake_complete = false,
    });

    destroyContext(ctx);
}

test "tunnel frame payload length guard widens before adding header" {
    try std.testing.expectEqual(@as(?usize, 0), tunnelFramePayloadLen(4, 0));
    try std.testing.expectEqual(@as(?usize, 1496), tunnelFramePayloadLen(1500, 1496));
    try std.testing.expectEqual(@as(?usize, null), tunnelFramePayloadLen(4, 65535));
    try std.testing.expectEqual(@as(?usize, null), tunnelFramePayloadLen(1500, 65535));
}

fn routeTestPeer(key: u8) Membership.Peer {
    return .{ .pubkey = @as([32]u8, @splat(key)), .name = "", .state = .alive, .gossip_endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 51000 + @as(u16, key)), .wg_pubkey = @as([32]u8, @splat(key)), .mesh_ip = .{ 10, 99, 0, key }, .wg_port = 0, .lamport = 1, .last_seen_ns = 1, .suspected_at_ns = null, .last_rtt_ns = null, .handshake_complete = false };
}

test "forced app relay route never falls back to direct" {
    const peer = routeTestPeer(1);
    const absent = appRoute(peer, null, true);
    try std.testing.expect(absent.direct == null and absent.relay == null);
    const relay = routeTestPeer(2);
    const forced = appRoute(peer, relay, true);
    try std.testing.expect(forced.direct == null);
    try std.testing.expectEqual(relay.gossip_endpoint.?, forced.relay.?);
    const automatic = appRoute(peer, relay, false);
    try std.testing.expect(automatic.direct != null and automatic.relay != null);
}

test "forced app relay requires an identity before join" {
    var ctx: MeshguardContext = undefined;
    initContextStorage(&ctx, std.testing.allocator);
    defer ctx.membership.deinit();
    try std.testing.expectEqual(@as(i32, -3), meshguard_set_app_relay(&ctx, null, true));
    var pin = @as([32]u8, @splat(2));
    try std.testing.expectEqual(@as(i32, 0), meshguard_set_app_relay(&ctx, &pin, true));
    ctx.running.store(true, .release);
    try std.testing.expectEqual(@as(i32, -2), meshguard_set_app_relay(&ctx, null, false));
}

test "authenticated direct and relay copies enqueue only once" {
    var seed_a = @as([32]u8, @splat(1));
    var seed_b = @as([32]u8, @splat(2));
    const sender = meshguard_init(&seed_a, 0) orelse return error.InitFailed;
    defer meshguard_destroy(sender);
    const receiver = meshguard_init(&seed_b, 0) orelse return error.InitFailed;
    defer meshguard_destroy(receiver);
    var peer = routeTestPeer(1);
    peer.pubkey = sender.ed25519_public;
    peer.wg_pubkey = sender.x25519_public;
    try receiver.membership.upsert(peer);
    const text = "native relay copy test";
    var packet: [93 + text.len]u8 = undefined;
    packet[0] = 0x50;
    @memcpy(packet[1..33], &receiver.ed25519_public);
    @memcpy(packet[33..65], &sender.ed25519_public);
    const nonce = @as([12]u8, @splat(7));
    @memcpy(packet[65..77], &nonce);
    const shared = try X25519.scalarmult(sender.x25519_private, receiver.x25519_public);
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(packet[77..][0..text.len], &tag, text, &sender.ed25519_public, nonce, crypto.kdf2(shared, "meshguard-app-v1").key);
    @memcpy(packet[77 + text.len ..], &tag);
    var corrupt = packet;
    corrupt[corrupt.len - 1] ^= 1;
    handleAppMessage(receiver, &corrupt);
    try std.testing.expectEqual(@as(u32, 0), receiver.inbox_write.load(.acquire));
    handleAppMessage(receiver, &packet);
    handleAppMessage(receiver, &packet);
    try std.testing.expectEqual(@as(u32, 1), receiver.inbox_write.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), receiver.app_duplicate_dropped.load(.acquire));
    try std.testing.expectEqualStrings(text, receiver.inbox[0].data[0..text.len]);
}

fn smallStackLifecycle() !void {
    var seed = @as([32]u8, @splat(0x37));
    for (0..3) |_| {
        const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
        defer meshguard_destroy(ctx);
        if (ctx.wg_device == null or ctx.wg_device.?.peer_count != 0)
            return error.InvalidDevice;
        if (ctx.wg_device.?.next_index == 0) return error.InvalidIndex;
        for (ctx.wg_device.?.ip_to_slot) |slot| {
            if (slot != 0xff) return error.InvalidRoute;
        }
    }
    const random_ctx = meshguard_init(null, 0) orelse return error.InitFailed;
    meshguard_destroy(random_ctx);
}

test "FFI lifecycle fits a small mobile host thread stack" {
    // Unoptimized std.crypto arithmetic needs more stack than the ReleaseFast
    // mobile artifacts. Both limits remain below the old initializer's frame.
    const stack_size: usize = if (builtin.mode == .debug) 1024 * 1024 else 256 * 1024;
    const thread = try std.Thread.spawn(.{ .stack_size = stack_size }, smallStackLifecycle, .{});
    thread.join();
}

test "pinned relay WireGuard key is used only when signed or derived" {
    const relay = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(5)));
    const pin = relay.public_key.toBytes();
    var peer = routeTestPeer(3);

    peer.wg_pubkey = @as([32]u8, @splat(0x66));
    peer.wg_key_source = .gossip;
    try std.testing.expect(trustedRelayWgKey(pin, peer) == null);

    peer.wg_key_source = .binding;
    try std.testing.expectEqualSlices(u8, &peer.wg_pubkey.?, &trustedRelayWgKey(pin, peer).?);

    const derived = try X25519.publicKeyFromEd25519(relay.public_key);
    peer.wg_pubkey = derived;
    peer.wg_key_source = .gossip;
    try std.testing.expectEqualSlices(u8, &derived, &trustedRelayWgKey(pin, peer).?);
}

test "certificates are checked against this context before they are installed" {
    var seed = @as([32]u8, @splat(6));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    const Org = lib.identity.Org;
    const org = Org.generateOrgKeyPair();
    const now: i64 = @intCast(std.Io.Timestamp.now(zio(), .real).toSeconds());
    var wire: [messages.ORG_CERT_WIRE_SIZE]u8 = undefined;

    const good = try Org.issueCertificateV2(org, ctx.ed25519_public, ctx.x25519_public, "", now + 3600);
    good.serialize(&wire);
    try std.testing.expectEqual(@as(i32, 0), meshguard_set_org_cert(ctx, &wire, wire.len));
    try std.testing.expect(ctx.org_cert != null and ctx.org_cert_dirty.load(.acquire));

    const other_wg = try Org.issueCertificateV2(org, ctx.ed25519_public, @as([32]u8, @splat(9)), "", now + 3600);
    other_wg.serialize(&wire);
    try std.testing.expectEqual(@as(i32, -4), meshguard_set_org_cert(ctx, &wire, wire.len));

    const other_node = try Org.issueCertificateV2(org, @as([32]u8, @splat(8)), ctx.x25519_public, "", now + 3600);
    other_node.serialize(&wire);
    try std.testing.expectEqual(@as(i32, -4), meshguard_set_org_cert(ctx, &wire, wire.len));

    const expired = try Org.issueCertificateV2(org, ctx.ed25519_public, ctx.x25519_public, "", now - 3600);
    expired.serialize(&wire);
    try std.testing.expectEqual(@as(i32, -4), meshguard_set_org_cert(ctx, &wire, wire.len));

    good.serialize(&wire);
    wire[200] ^= 1;
    try std.testing.expectEqual(@as(i32, -4), meshguard_set_org_cert(ctx, &wire, wire.len));
    try std.testing.expectEqual(@as(i32, -3), meshguard_set_org_cert(ctx, &wire, 100));

    try std.testing.expectEqual(@as(i32, 0), meshguard_clear_org_cert(ctx));
    try std.testing.expect(ctx.org_cert == null);
}

test "a certificate set before join is advertised once the context runs" {
    var seed = @as([32]u8, @splat(7));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    const Org = lib.identity.Org;
    const org = Org.generateOrgKeyPair();
    const now: i64 = @intCast(std.Io.Timestamp.now(zio(), .real).toSeconds());
    var wire: [messages.ORG_CERT_WIRE_SIZE]u8 = undefined;
    const cert = try Org.issueCertificateV2(org, ctx.ed25519_public, ctx.x25519_public, "", now + 3600);
    cert.serialize(&wire);
    try std.testing.expectEqual(@as(i32, 0), meshguard_set_org_cert(ctx, &wire, wire.len));

    const loopback = [_]u8{ 127, 0, 0, 1 };
    try std.testing.expectEqual(@as(i32, 0), meshguard_join(ctx, &loopback, 9));
    defer meshguard_leave(ctx);
    try std.testing.expectEqualSlices(u8, &wire, &ctx.swim.?.our_org_cert.?);
    try std.testing.expectEqualSlices(u8, &ctx.wg_binding.signature, &ctx.swim.?.our_wg_binding.?.signature);
}

test "contexts advertise a binding for their own WireGuard key" {
    var seed = @as([32]u8, @splat(4));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    try std.testing.expectEqualSlices(u8, &ctx.x25519_public, &ctx.wg_binding.wg_pubkey);
    try std.testing.expect(lib.identity.Binding.verify(ctx.ed25519_public, ctx.wg_binding));
}

test "contacts are validated, counted and removed" {
    var seed = @as([32]u8, @splat(0x21));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    const other = try AppPacket.Identity.fromSeed(@as([32]u8, @splat(0x22)));

    try std.testing.expectEqual(@as(i32, 0), meshguard_add_contact(ctx, &other.public_key, &other.wg_public));
    try std.testing.expectEqual(@as(i32, 0), meshguard_add_contact(ctx, &other.public_key, &other.wg_public));
    try std.testing.expectEqual(@as(u32, 1), meshguard_contact_count(ctx));
    const zero = @as([32]u8, @splat(0));
    try std.testing.expectEqual(@as(i32, -3), meshguard_add_contact(ctx, &other.public_key, &zero));
    var not_a_point = @as([32]u8, @splat(0xff));
    not_a_point[31] = 0x7f;
    try std.testing.expectEqual(@as(i32, -3), meshguard_add_contact(ctx, &not_a_point, &other.wg_public));

    try std.testing.expectEqual(@as(i32, 0), meshguard_remove_contact(ctx, &other.public_key));
    try std.testing.expectEqual(@as(i32, 1), meshguard_remove_contact(ctx, &other.public_key));
    _ = meshguard_add_contact(ctx, &other.public_key, &other.wg_public);
    meshguard_clear_contacts(ctx);
    try std.testing.expectEqual(@as(u32, 0), meshguard_contact_count(ctx));
}

fn sealedFrom(sender: AppPacket.Identity, ctx: *const MeshguardContext, text: []const u8, out: []u8) ![]const u8 {
    var nonce: [12]u8 = undefined;
    zio().random(&nonce);
    const n = try AppPacket.seal(sender.public_key, sender.wg_private, ctx.ed25519_public, ctx.x25519_public, nonce, text, out);
    return out[0..n];
}

test "frames from a contact open with its registered key, and contacts-only drops strangers" {
    var seed = @as([32]u8, @splat(0x23));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    const friend = try AppPacket.Identity.fromSeed(@as([32]u8, @splat(0x24)));
    const stranger = try AppPacket.Identity.fromSeed(@as([32]u8, @splat(0x25)));
    var buf: [AppPacket.max_packet]u8 = undefined;

    // Not in membership and not a contact: nothing to open it with.
    handleAppMessage(ctx, try sealedFrom(friend, ctx, "hello", &buf));
    try std.testing.expectEqual(@as(u32, 0), ctx.inbox_write.load(.acquire));

    try std.testing.expectEqual(@as(i32, 0), meshguard_add_contact(ctx, &friend.public_key, &friend.wg_public));
    handleAppMessage(ctx, try sealedFrom(friend, ctx, "hello", &buf));
    try std.testing.expectEqual(@as(u32, 1), ctx.inbox_write.load(.acquire));

    // A stranger known to membership is accepted unless contacts-only is on.
    var known = routeTestPeer(0x25);
    known.pubkey = stranger.public_key;
    known.wg_pubkey = stranger.wg_public;
    try ctx.membership.upsert(known);
    meshguard_set_contacts_only(ctx, true);
    handleAppMessage(ctx, try sealedFrom(stranger, ctx, "hi", &buf));
    try std.testing.expectEqual(@as(u32, 1), ctx.inbox_write.load(.acquire));
    meshguard_set_contacts_only(ctx, false);
    handleAppMessage(ctx, try sealedFrom(stranger, ctx, "hi", &buf));
    try std.testing.expectEqual(@as(u32, 2), ctx.inbox_write.load(.acquire));
}

const StatusProbe = struct {
    var calls: u32 = 0;
    var last_code: u8 = 0;
    fn record(_: [*]const u8, _: [*]const u8, code: u8) callconv(.c) void {
        calls += 1;
        last_code = code;
    }
};

test "delivery statuses count only from the pinned relay and for frames we sent" {
    var seed = @as([32]u8, @splat(0x26));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    var relay = routeTestPeer(0x31);
    try ctx.membership.upsert(relay);
    ctx.app_relay_key = relay.pubkey;
    meshguard_set_on_delivery_status(ctx, StatusProbe.record);
    StatusProbe.calls = 0;

    const dest = @as([32]u8, @splat(0x44));
    const nonce = @as([12]u8, @splat(0x55));
    var bytes: [AppStatus.SIZE]u8 = undefined;
    AppStatus.encode(&bytes, .{ .destination = dest, .nonce = nonce, .code = .handshake_again });
    const relay_ep = relay.gossip_endpoint.?;

    // Not a frame we sent.
    onAppStatusCallback(ctx, &bytes, relay_ep);
    try std.testing.expectEqual(@as(u32, 0), StatusProbe.calls);

    rememberSentFrame(ctx, dest, nonce);
    // From anywhere but the pinned relay.
    onAppStatusCallback(ctx, &bytes, messages.Endpoint.initV4(.{ 203, 0, 113, 9 }, 51821));
    try std.testing.expectEqual(@as(u32, 0), StatusProbe.calls);

    var got_dest: [32]u8 = undefined;
    var got_nonce: [12]u8 = undefined;
    var got_code: u8 = 0;
    // Refused statuses are not queued either.
    try std.testing.expectEqual(@as(i32, 1), meshguard_recv_delivery_status(ctx, &got_dest, &got_nonce, &got_code));

    ctx.last_relay_auth_ns = 12345;
    onAppStatusCallback(ctx, &bytes, relay_ep);
    try std.testing.expectEqual(@as(u32, 1), StatusProbe.calls);
    try std.testing.expectEqual(@as(u8, 4), StatusProbe.last_code);
    try std.testing.expectEqual(@as(i128, 0), ctx.last_relay_auth_ns); // re-prove at once

    // Each frame is matched once.
    onAppStatusCallback(ctx, &bytes, relay_ep);
    try std.testing.expectEqual(@as(u32, 1), StatusProbe.calls);

    // Polling hosts get the same status once.
    try std.testing.expectEqual(@as(i32, 0), meshguard_recv_delivery_status(ctx, &got_dest, &got_nonce, &got_code));
    try std.testing.expectEqualSlices(u8, &dest, &got_dest);
    try std.testing.expectEqualSlices(u8, &nonce, &got_nonce);
    try std.testing.expectEqual(@as(u8, 4), got_code);
    try std.testing.expectEqual(@as(i32, 1), meshguard_recv_delivery_status(ctx, &got_dest, &got_nonce, &got_code));
    try std.testing.expectEqual(@as(i32, -1), meshguard_recv_delivery_status(null, &got_dest, &got_nonce, &got_code));
    relay.state = .alive;
}

test "the delivery status queue holds 64 and drops newer statuses while full" {
    var seed = @as([32]u8, @splat(0x27));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    const relay = routeTestPeer(0x32);
    try ctx.membership.upsert(relay);
    ctx.app_relay_key = relay.pubkey;
    const relay_ep = relay.gossip_endpoint.?;

    const dest = @as([32]u8, @splat(0x46));
    var bytes: [AppStatus.SIZE]u8 = undefined;
    for (0..70) |i| {
        var nonce = @as([12]u8, @splat(0));
        nonce[0] = @intCast(i);
        rememberSentFrame(ctx, dest, nonce);
        AppStatus.encode(&bytes, .{ .destination = dest, .nonce = nonce, .code = .offline });
        onAppStatusCallback(ctx, &bytes, relay_ep);
    }
    var got_dest: [32]u8 = undefined;
    var got_nonce: [12]u8 = undefined;
    var got_code: u8 = 0;
    for (0..64) |i| {
        try std.testing.expectEqual(@as(i32, 0), meshguard_recv_delivery_status(ctx, &got_dest, &got_nonce, &got_code));
        try std.testing.expectEqual(@as(u8, @intCast(i)), got_nonce[0]);
        try std.testing.expectEqual(@as(u8, 1), got_code);
    }
    try std.testing.expectEqual(@as(i32, 1), meshguard_recv_delivery_status(ctx, &got_dest, &got_nonce, &got_code));
}

test "leaving forgets the network but keeps identity and contacts" {
    var seed = @as([32]u8, @splat(0x28));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    const friend = try AppPacket.Identity.fromSeed(@as([32]u8, @splat(0x29)));
    try std.testing.expectEqual(@as(i32, 0), meshguard_add_contact(ctx, &friend.public_key, &friend.wg_public));
    const loopback = [_]u8{ 127, 0, 0, 1 };

    try std.testing.expectEqual(@as(i32, 0), meshguard_join(ctx, &loopback, 9));
    try ctx.membership.upsert(routeTestPeer(0x41));
    ctx.last_relay_auth_ns = 77;
    meshguard_leave(ctx);
    try std.testing.expectEqual(@as(usize, 0), ctx.membership.count());
    try std.testing.expectEqual(@as(i128, 0), ctx.last_relay_auth_ns);
    try std.testing.expectEqual(@as(u32, 1), meshguard_contact_count(ctx));

    // Switching to another relay joins again (and twice in a row is fine).
    var relay = @as([32]u8, @splat(0x42));
    try std.testing.expectEqual(@as(i32, 0), meshguard_switch_relay(ctx, &relay, true, &loopback, 10));
    try std.testing.expect(ctx.running.load(.acquire));
    try std.testing.expectEqualSlices(u8, &relay, &ctx.app_relay_key.?);
    try std.testing.expectEqual(@as(i32, 0), meshguard_switch_relay(ctx, &relay, true, &loopback, 11));
    meshguard_leave(ctx);
}

test "repeated join and leave cycles stay consistent under concurrent sends" {
    var seed = @as([32]u8, @splat(0x2a));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    const loopback = [_]u8{ 127, 0, 0, 1 };
    var stop = std.atomic.Value(bool).init(false);
    const Sender = struct {
        fn run(c: *MeshguardContext, done: *std.atomic.Value(bool)) void {
            const target = @as([32]u8, @splat(0x55));
            const payload = "x";
            while (!done.load(.acquire)) {
                _ = meshguard_send(c, &target, payload, 1);
                _ = meshguard_last_recv_time(c);
                _ = meshguard_peer_count(c);
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Sender.run, .{ ctx, &stop });
    for (0..50) |i| {
        try std.testing.expectEqual(@as(i32, 0), meshguard_join(ctx, &loopback, @intCast(9 + i % 3)));
        meshguard_leave(ctx);
    }
    stop.store(true, .release);
    thread.join();
}

test "keepalive and relay proof intervals are bounded" {
    var seed = @as([32]u8, @splat(0x27));
    const ctx = meshguard_init(&seed, 0) orelse return error.InitFailed;
    defer meshguard_destroy(ctx);
    try std.testing.expectEqual(@as(i32, 0), meshguard_set_keepalive_interval(ctx, 25_000));
    try std.testing.expectEqual(@as(i32, -3), meshguard_set_keepalive_interval(ctx, 10));
    try std.testing.expectEqual(@as(i32, 0), meshguard_set_relay_proof_interval(ctx, 120_000));
    try std.testing.expectEqual(@as(i32, -3), meshguard_set_relay_proof_interval(ctx, 100));
    try std.testing.expectEqual(@as(u32, 25_000), ctx.keepalive_ms.load(.acquire));
}
