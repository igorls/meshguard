//! meshguard FFI — C-ABI surface for embedding in mobile apps.
//!
//! This module exposes a minimal C-compatible API for:
//!   - Lifecycle: init, join mesh via seed, leave, destroy
//!   - Messaging: send/receive encrypted app-level messages
//!   - Events: peer join/leave callbacks
//!
//! Designed for JNI consumption from Android (Kotlin/Java).
//! Does NOT include the WireGuard TUN dataplane — application-level
//! encrypted messaging only.

const std = @import("std");
const lib = @import("lib.zig");

const Membership = lib.discovery.Membership;
const SwimProtocol = lib.discovery.Swim.SwimProtocol;
const EventHandler = lib.discovery.Swim.EventHandler;
const SwimConfig = lib.discovery.Swim.SwimConfig;
const LanDiscovery = lib.discovery.Lan.LanDiscovery;
const Udp = lib.net.Udp;
const noise = lib.wireguard.Noise;
const crypto = lib.wireguard.Crypto;
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

    // Networking
    membership: Membership.MembershipTable,
    swim: ?SwimProtocol,
    socket: ?Udp.UdpSocket,
    lan_discovery: ?LanDiscovery,
    event_loop_thread: ?std.Thread,
    running: std.atomic.Value(bool),

    // Callbacks (set by host app)
    on_message_cb: ?*const fn ([*]const u8, usize, [*]const u8) callconv(.c) void,
    on_peer_event_cb: ?*const fn (u8, [*]const u8) callconv(.c) void,

    // App-level message inbox (ring buffer)
    inbox: [64]AppMessage,
    inbox_write: std.atomic.Value(u32),
    inbox_read: std.atomic.Value(u32),

    // Allocator for this context's heap needs
    allocator: std.heap.GeneralPurposeAllocator(.{}),
};

/// Application-level encrypted message in the inbox.
const AppMessage = struct {
    sender_pubkey: [32]u8,
    data: [1024]u8,
    len: u16,
    valid: bool,
};

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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const ctx = allocator.create(MeshguardContext) catch return null;
    ctx.* = .{
        .ed25519_seed = undefined,
        .ed25519_public = undefined,
        .x25519_private = undefined,
        .x25519_public = undefined,
        .membership = Membership.MembershipTable.init(allocator, 15000),
        .swim = null,
        .socket = null,
        .lan_discovery = null,
        .event_loop_thread = null,
        .running = std.atomic.Value(bool).init(false),
        .on_message_cb = null,
        .on_peer_event_cb = null,
        .inbox = std.mem.zeroes([64]AppMessage),
        .inbox_write = std.atomic.Value(u32).init(0),
        .inbox_read = std.atomic.Value(u32).init(0),
        .allocator = gpa,
    };

    // Identity: use provided seed or generate
    if (identity_seed) |seed| {
        @memcpy(&ctx.ed25519_seed, seed[0..32]);
        // Derive a deterministic public key by hashing the seed (Ed25519 convention)
        var hash: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(seed[0..32], &hash, .{});
        @memcpy(&ctx.ed25519_public, hash[0..32]);
    } else {
        // Generate a fresh keypair
        const kp = Ed25519.KeyPair.generate();
        const pub_bytes = kp.public_key.toBytes();
        const sec_bytes = kp.secret_key.toBytes();
        @memcpy(&ctx.ed25519_seed, sec_bytes[0..32]);
        @memcpy(&ctx.ed25519_public, &pub_bytes);
    }

    // Derive X25519 keys for Noise handshakes
    // Use first 32 bytes of Ed25519 seed, clamped for Curve25519
    var x_priv = ctx.ed25519_seed;
    x_priv[0] &= 248;
    x_priv[31] &= 127;
    x_priv[31] |= 64;
    ctx.x25519_private = x_priv;
    ctx.x25519_public = X25519.recoverPublicKey(x_priv) catch {
        allocator.destroy(ctx);
        return null;
    };

    // Bind UDP socket — use ephemeral port (0) on mobile for reliability
    ctx.socket = Udp.UdpSocket.bind(listen_port) catch {
        allocator.destroy(ctx);
        return null;
    };

    return ctx;
}

/// Destroy a meshguard instance, stopping all networking.
export fn meshguard_destroy(ctx: ?*MeshguardContext) void {
    const c = ctx orelse return;
    meshguard_leave(c);

    if (c.socket) |*s| {
        s.close();
    }

    var alloc = c.allocator;
    alloc.allocator().destroy(c);
    _ = alloc.deinit();
}

/// Get our Ed25519 public key (32 bytes).
export fn meshguard_get_pubkey(ctx: ?*MeshguardContext, out: [*]u8) void {
    const c = ctx orelse return;
    @memcpy(out[0..32], &c.ed25519_public);
}

/// Get our Ed25519 public key as base64 (44 bytes + null terminator).
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

    // Seed the mesh — use the SEED's port for the seed endpoint
    var seed_addr: [4]u8 = undefined;
    @memcpy(&seed_addr, seed_ip[0..4]);
    const seeds = [_]messages.Endpoint{.{ .addr = seed_addr, .port = target_seed_port }};
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

    // Trust is open by default (enforce_trust = false)
    // For production, add authorized keys before join

    // Initialize LAN discovery (multicast beacon with Peer Circle app ID)
    c.lan_discovery = LanDiscovery.init(
        c.ed25519_public,
        our_port,
        lib.discovery.Lan.APP_ID_PEER_CIRCLE,
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
    const c = ctx orelse return -1;
    if (!c.running.load(.acquire)) return -2;
    if (len > 1024) return -3;

    // Find peer in membership table
    var target_key: [32]u8 = undefined;
    @memcpy(&target_key, peer_pubkey[0..32]);

    const peer = c.membership.peers.get(target_key) orelse return -4; // unknown peer
    const ep = peer.gossip_endpoint orelse return -5; // no endpoint

    // Build encrypted message:
    //   [1B type=0x50] [32B dest_pubkey] [32B sender_pubkey] [12B nonce] [N ciphertext] [16B tag]
    var msg_buf: [1 + 32 + 32 + 12 + 1024 + 16]u8 = undefined;
    msg_buf[0] = 0x50; // App message type
    @memcpy(msg_buf[1..33], &target_key); // destination pubkey
    @memcpy(msg_buf[33..65], &c.ed25519_public); // sender pubkey

    // Nonce: random 12 bytes
    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    @memcpy(msg_buf[65..77], &nonce);

    // Derive shared key via X25519 + HKDF
    const peer_x25519 = peer.wg_pubkey orelse return -6; // no WG pubkey
    const shared = X25519.scalarmult(c.x25519_private, peer_x25519) catch return -7;
    const key_result = crypto.kdf2(shared, "meshguard-app-v1");
    const enc_key = key_result.key;

    // Encrypt
    const msg_len: usize = @intCast(len);
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(
        msg_buf[77..][0..msg_len],
        &tag,
        data[0..msg_len],
        &c.ed25519_public, // AD = sender pubkey
        nonce,
        enc_key,
    );
    @memcpy(msg_buf[77 + msg_len ..][0..16], &tag);

    const total_len: usize = 77 + msg_len + 16;
    const socket = c.socket orelse return -8;
    _ = socket.sendTo(msg_buf[0..total_len], ep.addr, ep.port) catch return -9;

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
    if (!msg.valid) return 1;

    @memcpy(out_data[0..msg.len], msg.data[0..msg.len]);
    out_len.* = msg.len;
    @memcpy(out_sender[0..32], &msg.sender_pubkey);

    msg.valid = false;
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

// ─── Query ───

/// Get the number of alive peers.
export fn meshguard_peer_count(ctx: ?*MeshguardContext) u32 {
    const c = ctx orelse return 0;
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
/// `out_info`:    72-byte buffer for peer info:
///   [0..4]   = IPv4 address (gossip endpoint)
///   [4..6]   = gossip port (big-endian)
///   [6..10]  = mesh IP
///   [10..11] = state (0=alive, 1=suspected, 2=dead, 3=left)
///   [11..12] = has_wg_pubkey (0/1)
///   [12..44] = wg_pubkey (if has_wg_pubkey)
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

    const peer = c.membership.peers.get(key) orelse return -1;

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

    return 0;
}

// ─── Internal: Event loop ───

fn eventLoop(ctx: *MeshguardContext) void {
    var lan_beacon_counter: u32 = 0;
    while (ctx.running.load(.acquire)) {
        if (ctx.swim) |*swim| {
            swim.tick() catch {};

            // LAN discovery: send beacons every ~3 seconds (every 10 ticks at ~300ms/tick)
            if (ctx.lan_discovery) |*lan| {
                _ = lan.recvBeacons();
                lan_beacon_counter += 1;
                if (lan_beacon_counter >= 10) {
                    lan.sendBeacon();
                    lan_beacon_counter = 0;
                }
            }
        } else {
            // No SWIM instance — sleep briefly
            std.Thread.sleep(100_000_000); // 100ms
        }
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

    const ciphertext = data[77..][0..payload_len];
    const tag: [16]u8 = data[77 + payload_len ..][0..16].*;

    // Derive shared key
    var peer_key: [32]u8 = undefined;
    @memcpy(&peer_key, sender_pubkey);
    const peer = ctx.membership.peers.get(peer_key) orelse return;
    const peer_x25519 = peer.wg_pubkey orelse return;

    const shared = X25519.scalarmult(ctx.x25519_private, peer_x25519) catch return;
    const key_result = crypto.kdf2(shared, "meshguard-app-v1");
    const enc_key = key_result.key;

    // Decrypt
    var plaintext: [1024]u8 = undefined;
    ChaCha20Poly1305.decrypt(
        plaintext[0..payload_len],
        ciphertext,
        tag,
        sender_pubkey,
        nonce,
        enc_key,
    ) catch return; // Auth failed — silently drop

    // Enqueue to inbox
    const write_idx = ctx.inbox_write.load(.acquire);
    const slot = write_idx % 64;
    ctx.inbox[slot] = .{
        .sender_pubkey = peer_key,
        .data = undefined,
        .len = @intCast(payload_len),
        .valid = true,
    };
    @memcpy(ctx.inbox[slot].data[0..payload_len], plaintext[0..payload_len]);
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
