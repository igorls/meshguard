///! WireGuard device — manages per-peer tunnels and the TUN interface.
///!
///! This is the userspace equivalent of the kernel's wg_device.
///! It holds all peer tunnels, routes packets between TUN and UDP,
///! and manages handshake initiation and rekeying.
const std = @import("std");
const noise = @import("noise.zig");
const tunnel = @import("tunnel.zig");
const messages = @import("../protocol/messages.zig");

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowNs() i128 {
    return @intCast(std.Io.Timestamp.now(zio(), .awake).toNanoseconds());
}

pub const MAX_PEERS: usize = 64;

/// Hash table bucket count for index → peer mapping.
/// Must be power of 2. Sized for ~3x the max number of active indices
/// (each peer can have 2-3 active indices: current + previous).
const INDEX_TABLE_SIZE: usize = 256;

/// Classifies incoming UDP packet by its first byte.
pub const PacketType = enum {
    wg_handshake_init, // Type 1
    wg_handshake_resp, // Type 2
    wg_cookie, // Type 3
    wg_transport, // Type 4
    swim, // SWIM gossip or holepunch
    stun, // STUN binding response
    unknown,

    pub fn classify(data: []const u8) PacketType {
        if (data.len < 4) return .unknown;

        // WireGuard messages: first byte is type, next 3 are zeros
        const msg_type = std.mem.readInt(u32, data[0..4], .little);

        // Optimization: Extract dominant data-plane case to explicit if branch to avoid jump table
        if (msg_type == 4) return .wg_transport;

        return switch (msg_type) {
            1 => .wg_handshake_init,
            2 => .wg_handshake_resp,
            3 => .wg_cookie,
            4 => unreachable,
            else => blk: {
                // STUN: check for magic cookie at bytes 4-7
                if (data.len >= 8) {
                    const magic = std.mem.readInt(u32, data[4..8], .big);
                    if (magic == 0x2112A442) break :blk .stun;
                }
                // Everything else is SWIM gossip
                break :blk .swim;
            },
        };
    }
};

/// Per-peer WG state.
pub const WgPeer = struct {
    /// Ed25519 identity pubkey (for membership lookup)
    identity_key: [32]u8,
    /// X25519 WG static public key
    wg_pubkey: [32]u8,
    /// Mesh IP address (10.99.x.y)
    mesh_ip: [4]u8 = .{0} ** 4,
    /// Mesh IPv6 address (fd99:6d67::/64)
    mesh_ip6: [16]u8 = .{0} ** 16,
    /// Noise handshake state
    handshake: noise.Handshake,
    /// Active tunnel (after successful handshake)
    active_tunnel: ?tunnel.Tunnel = null,
    /// Our sender index for this peer
    sender_index: u32 = 0,
    /// Peer's endpoint
    endpoint_addr: [4]u8 = .{0} ** 4,
    endpoint_addr6: ?[16]u8 = null,
    endpoint_port: u16 = 0,
    /// Last handshake attempt time (for rate limiting)
    last_handshake_ns: i128 = 0,
    /// Number of handshake attempts
    handshake_attempts: u32 = 0,
    /// Per-peer Tx ring for parallel pipeline ordering (only used when --encrypt-workers > 0)
    tx_ring: @import("../net/pipeline.zig").PeerTxRing = .{},

    pub fn deinit(self: *WgPeer) void {
        self.handshake.deinit();
        if (self.active_tunnel) |*t| {
            t.deinit();
            self.active_tunnel = null;
        }
    }

    pub fn endpoint(self: *const WgPeer) ?messages.Endpoint {
        if (self.endpoint_port == 0) return null;
        if (self.endpoint_addr6) |addr6| return messages.Endpoint.initV6(addr6, self.endpoint_port);
        if (std.mem.allEqual(u8, &self.endpoint_addr, 0)) return null;
        return messages.Endpoint.initV4(self.endpoint_addr, self.endpoint_port);
    }
};

/// Fixed-size open-addressed hash table for u32 → usize mapping.
/// Uses linear probing with tombstone-free deletion (robin hood style).
/// No allocator needed — all inline in the struct.
const IndexTable = struct {
    const EMPTY: u32 = 0; // 0 is never a valid sender_index (we start at 1)

    keys: [INDEX_TABLE_SIZE]u32 = .{EMPTY} ** INDEX_TABLE_SIZE,
    values: [INDEX_TABLE_SIZE]usize = .{0} ** INDEX_TABLE_SIZE,

    fn hash(index: u32) usize {
        // Fibonacci hashing: multiply by golden ratio, extract TOP bits.
        // Using % extracts bottom bits which defeats the multiplication.
        return @as(usize, (index *% 0x9E3779B9) >> 24);
    }

    pub fn put(self: *IndexTable, index: u32, slot: usize) void {
        if (index == EMPTY) return; // Can't store the sentinel
        var pos = hash(index);
        var i: usize = 0;
        while (i < INDEX_TABLE_SIZE) : (i += 1) {
            if (self.keys[pos] == EMPTY or self.keys[pos] == index) {
                self.keys[pos] = index;
                self.values[pos] = slot;
                return;
            }
            pos = (pos + 1) & (INDEX_TABLE_SIZE - 1);
        }
        // Table full — shouldn't happen with our sizing (256 >> 64*3)
    }

    pub fn get(self: *const IndexTable, index: u32) ?usize {
        if (index == EMPTY) return null;
        var pos = hash(index);
        var i: usize = 0;
        while (i < INDEX_TABLE_SIZE) : (i += 1) {
            if (self.keys[pos] == index) return self.values[pos];
            if (self.keys[pos] == EMPTY) return null;
            pos = (pos + 1) & (INDEX_TABLE_SIZE - 1);
        }
        return null;
    }

    pub fn remove(self: *IndexTable, index: u32) void {
        if (index == EMPTY) return;
        var pos = hash(index);
        var i: usize = 0;
        while (i < INDEX_TABLE_SIZE) : (i += 1) {
            if (self.keys[pos] == index) {
                // Shift subsequent entries to maintain probe chain
                var empty_pos = pos;
                var j = (pos + 1) & (INDEX_TABLE_SIZE - 1);
                while (self.keys[j] != EMPTY) {
                    const ideal = hash(self.keys[j]);
                    // Check if key at j should be moved to empty_pos
                    // (it's closer to its ideal position)
                    if ((j -% ideal) & (INDEX_TABLE_SIZE - 1) >=
                        (j -% empty_pos) & (INDEX_TABLE_SIZE - 1))
                    {
                        self.keys[empty_pos] = self.keys[j];
                        self.values[empty_pos] = self.values[j];
                        empty_pos = j;
                    }
                    j = (j + 1) & (INDEX_TABLE_SIZE - 1);
                }
                self.keys[empty_pos] = EMPTY;
                return;
            }
            if (self.keys[pos] == EMPTY) return;
            pos = (pos + 1) & (INDEX_TABLE_SIZE - 1);
        }
    }
};

/// Static-key lookup table for O(1) handshake initiation routing.
/// Maps X25519 public key → peer slot index.
const StaticKeyTable = struct {
    /// Store first 8 bytes of pubkey as hash key for fast comparison
    keys: [MAX_PEERS][32]u8 = undefined,
    slots: [MAX_PEERS]usize = undefined,
    count: usize = 0,

    pub fn put(self: *StaticKeyTable, pubkey: [32]u8, slot: usize) void {
        // Update existing entry if present
        for (0..self.count) |i| {
            if (std.mem.eql(u8, &self.keys[i], &pubkey)) {
                self.slots[i] = slot;
                return;
            }
        }
        if (self.count < MAX_PEERS) {
            self.keys[self.count] = pubkey;
            self.slots[self.count] = slot;
            self.count += 1;
        }
    }

    pub fn get(self: *const StaticKeyTable, pubkey: [32]u8) ?usize {
        for (0..self.count) |i| {
            if (std.mem.eql(u8, &self.keys[i], &pubkey)) return self.slots[i];
        }
        return null;
    }

    pub fn remove(self: *StaticKeyTable, pubkey: [32]u8) void {
        for (0..self.count) |i| {
            if (std.mem.eql(u8, &self.keys[i], &pubkey)) {
                // Swap with last
                if (self.count > 1 and i < self.count - 1) {
                    self.keys[i] = self.keys[self.count - 1];
                    self.slots[i] = self.slots[self.count - 1];
                }
                self.count -= 1;
                return;
            }
        }
    }
};

/// Extract the host ID (u16) from a mesh IP address.
/// Mesh prefix is 10.99.0.0/16, so octets [2] and [3] form the host key.
fn meshIpHostId(ip: [4]u8) u16 {
    return (@as(u16, ip[2]) << 8) | @as(u16, ip[3]);
}

/// SECURITY (H4): token-bucket rate limiter for inbound WireGuard handshake
/// initiations. Each accepted init forces an X25519 on the (single) control
/// thread; the MAC1 key is public, so without this a forged-init flood starves
/// SWIM + the data plane. A small per-source table provides fairness; a global
/// bucket bounds total work even under source-address spoofing (the spoofing
/// case is fully addressed only by the planned cookie/MAC2 follow-up).
const HandshakeLimiter = struct {
    const SLOTS: usize = 512; // distinct source IPs tracked (hashed, evict-on-collision)
    const PER_SRC_BURST: u32 = 8;
    const PER_SRC_REFILL_NS: i128 = 250 * std.time.ns_per_ms; // 1 token / 250ms ≈ 4/s
    const GLOBAL_BURST: u32 = 256;
    const GLOBAL_REFILL_NS: i128 = 10 * std.time.ns_per_ms; // 1 token / 10ms = 100/s

    const Bucket = struct {
        ip: [4]u8 = .{ 0, 0, 0, 0 },
        tokens: u32 = PER_SRC_BURST,
        last_ns: i128 = 0,
    };

    mutex: std.Io.Mutex = .init,
    buckets: [SLOTS]Bucket = .{Bucket{}} ** SLOTS,
    global_tokens: u32 = GLOBAL_BURST,
    global_last_ns: i128 = 0,

    fn refill(tokens: u32, max: u32, last_ns: *i128, now_ns: i128, interval_ns: i128) u32 {
        if (now_ns <= last_ns.*) return tokens;
        const gained: u64 = @intCast(@divTrunc(now_ns - last_ns.*, interval_ns));
        if (gained == 0) return tokens;
        last_ns.* += @as(i128, @intCast(gained)) * interval_ns;
        const t: u64 = @as(u64, tokens) + gained;
        return if (t > max) max else @intCast(t);
    }

    /// Returns true if a handshake from `ip` may proceed (consuming a token).
    fn allow(self: *HandshakeLimiter, ip: [4]u8, now_ns: i128) bool {
        self.mutex.lockUncancelable(zio());
        defer self.mutex.unlock(zio());

        // Global backstop first: bounds total X25519/sec even under spoofing.
        self.global_tokens = refill(self.global_tokens, GLOBAL_BURST, &self.global_last_ns, now_ns, GLOBAL_REFILL_NS);
        if (self.global_tokens == 0) return false;

        // Per-source bucket (hash → slot, reset on collision with a different IP).
        const h = (((@as(usize, ip[0]) *% 131 +% @as(usize, ip[1])) *% 131 +% @as(usize, ip[2])) *% 131 +% @as(usize, ip[3]));
        const b = &self.buckets[h % SLOTS];
        if (!std.mem.eql(u8, &b.ip, &ip)) {
            b.* = .{ .ip = ip, .tokens = PER_SRC_BURST, .last_ns = now_ns };
        } else {
            b.tokens = refill(b.tokens, PER_SRC_BURST, &b.last_ns, now_ns, PER_SRC_REFILL_NS);
        }
        if (b.tokens == 0) return false;

        b.tokens -= 1;
        self.global_tokens -= 1;
        return true;
    }
};

/// Result of processing an inbound handshake initiation (we are responder).
pub const InitiationResult = struct {
    response: noise.HandshakeResponse,
    slot: usize,
};

/// Userspace WireGuard device.
pub const WgDevice = struct {
    /// Our X25519 keypair
    static_private: [32]u8,
    static_public: [32]u8,

    /// Per-peer state
    peers: [MAX_PEERS]?WgPeer = .{null} ** MAX_PEERS,
    peer_count: usize = 0,

    /// Sender index → peer slot mapping (for fast lookup on incoming transport)
    /// Full u32 range support via open-addressed hash table
    index_map: IndexTable = .{},

    /// Static pubkey → peer slot mapping (for O(1) handshake initiation routing)
    /// Replaces O(N) iteration in handleInitiation
    static_map: StaticKeyTable = .{},

    /// Mesh IP → peer slot mapping (O(1) routing for data plane).
    /// Mesh prefix is 10.99.0.0/16, so the last 2 octets form a u16 host ID.
    /// Uses u8 with 0xFF sentinel (MAX_PEERS=64 fits in u8). 65536 bytes = 64KB.
    ip_to_slot: [65536]u8 = .{0xFF} ** 65536,

    /// Next sender index to assign (random-ish via wrapping increment)
    next_index: u32 = 0,

    /// SECURITY (H6): guards the peer table against concurrent access. Data-plane
    /// worker threads take the SHARED lock to encrypt/decrypt; the control thread
    /// (peer death → removePeer) and handshake handlers take the EXCLUSIVE lock.
    /// Without this, removePeer secureZeros key material and nils a slot while a
    /// worker is mid-encrypt, yielding torn reads / use-after-zero ciphertext on
    /// the wire (silent under ReleaseFast). The lock is the OUTERMOST lock on the
    /// data path (acquired before tx_ring push/send locks) so there is no
    /// ordering inversion.
    lock: std.Io.RwLock = .init,

    /// SECURITY (H4): per-source + global rate limit on inbound handshake
    /// initiations, checked before the expensive X25519. The MAC1 anti-DoS key is
    /// our public key, broadcast in cleartext gossip, so MAC1 alone cannot gate a
    /// forged-init flood. (A full WireGuard cookie/MAC2 reply — which also defends
    /// against source-spoofed floods — is a planned follow-up.)
    hs_limiter: HandshakeLimiter = .{},

    pub fn init(static_private: [32]u8, static_public: [32]u8) WgDevice {
        // Start with a random sender index for unpredictability
        var seed: [4]u8 = undefined;
        zio().random(&seed);
        const start_index = std.mem.readInt(u32, &seed, .little) | 1; // ensure non-zero

        return .{
            .static_private = static_private,
            .static_public = static_public,
            .next_index = start_index,
        };
    }

    /// Allocate a new random-ish sender index.
    fn allocIndex(self: *WgDevice) u32 {
        const idx = self.next_index;
        self.next_index +%= 1;
        if (self.next_index == 0) self.next_index = 1; // Never use 0 (sentinel)
        return idx;
    }

    /// Add or update a peer by their WG public key.
    /// Returns the peer slot index.
    pub fn addPeer(self: *WgDevice, identity_key: [32]u8, wg_pubkey: [32]u8, addr: [4]u8, port: u16) !usize {
        return self.addPeerWithMeshIp(identity_key, wg_pubkey, addr, port, .{ 0, 0, 0, 0 });
    }

    /// Add or update a peer with mesh IP for O(1) data-plane routing.
    pub fn addPeerWithMeshIp(self: *WgDevice, identity_key: [32]u8, wg_pubkey: [32]u8, addr: [4]u8, port: u16, mesh_ip: [4]u8) !usize {
        return self.addPeerWithEndpoint(identity_key, wg_pubkey, messages.Endpoint.initV4(addr, port), mesh_ip, .{0} ** 16);
    }

    /// Add or update a peer with IPv4/IPv6 endpoint and mesh addresses.
    pub fn addPeerWithEndpoint(self: *WgDevice, identity_key: [32]u8, wg_pubkey: [32]u8, endpoint: messages.Endpoint, mesh_ip: [4]u8, mesh_ip6: [16]u8) !usize {
        self.lock.lockUncancelable(zio()); // H6: exclusive — mutates the peer table
        defer self.lock.unlock(zio());
        // Check if peer already exists
        if (self.static_map.get(wg_pubkey)) |existing| {
            if (self.peers[existing]) |*peer| {
                peer.endpoint_addr = endpoint.addr;
                peer.endpoint_addr6 = endpoint.addr6;
                peer.endpoint_port = endpoint.port;
                // Update mesh IP routing if provided
                if (mesh_ip[0] != 0 or mesh_ip[1] != 0) {
                    // Clear old mapping if mesh_ip changed
                    if (peer.mesh_ip[0] != 0 or peer.mesh_ip[1] != 0) {
                        const old_host = meshIpHostId(peer.mesh_ip);
                        self.ip_to_slot[old_host] = 0xFF;
                    }
                    peer.mesh_ip = mesh_ip;
                    peer.mesh_ip6 = mesh_ip6;
                    self.ip_to_slot[meshIpHostId(mesh_ip)] = @intCast(existing);
                }
                return existing;
            }
        }

        // Find empty slot
        for (&self.peers, 0..) |*slot, i| {
            if (slot.* == null) {
                const handshake = noise.Handshake.init(
                    self.static_private,
                    self.static_public,
                    wg_pubkey,
                ) catch return error.WeakPublicKey;
                const sender_idx = self.allocIndex();
                slot.* = .{
                    .identity_key = identity_key,
                    .wg_pubkey = wg_pubkey,
                    .mesh_ip = mesh_ip,
                    .mesh_ip6 = mesh_ip6,
                    .handshake = handshake,
                    .endpoint_addr = endpoint.addr,
                    .endpoint_addr6 = endpoint.addr6,
                    .endpoint_port = endpoint.port,
                    .sender_index = sender_idx,
                };
                self.peer_count += 1;
                self.static_map.put(wg_pubkey, i);
                // Register mesh IP routing
                if (mesh_ip[0] != 0 or mesh_ip[1] != 0) {
                    self.ip_to_slot[meshIpHostId(mesh_ip)] = @intCast(i);
                }
                return i;
            }
        }
        return error.TooManyPeers;
    }

    /// True if we hold an established transport session (a completed handshake)
    /// for this peer. Lets the periodic handshake retransmit skip peers whose
    /// tunnel is already up, so only stalled/rejoining peers are re-initiated.
    /// Force a fresh handshake initiation to an already-registered peer, bypassing
    /// the "already established" short-circuit — used by the S2 restart-heal path to
    /// refresh a stale-but-unexpired session without tearing it down. initiateHandshake
    /// applies its own 5s rate limit and returns error.HandshakeRateLimited when hot.
    pub fn reinitiate(self: *WgDevice, wg_pubkey: [32]u8) !noise.HandshakeInitiation {
        const slot = self.static_map.get(wg_pubkey) orelse return error.PeerNotFound;
        return self.initiateHandshake(slot);
    }

    pub fn hasActiveTunnel(self: *WgDevice, wg_pubkey: [32]u8) bool {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        if (self.static_map.get(wg_pubkey)) |slot| {
            if (self.peers[slot]) |*peer| {
                // Honor session expiry: a non-null but expired (>= REJECT_AFTER_TIME)
                // tunnel can no longer encrypt or decrypt, so it must NOT count as
                // active — otherwise the periodic handshake retransmit and re-init
                // gates skip it and the dead session is never re-established.
                if (peer.active_tunnel) |*t| return t.isValid();
                return false;
            }
        }
        return false;
    }

    /// Remove a peer by WG public key.
    pub fn removePeer(self: *WgDevice, wg_pubkey: [32]u8) void {
        self.lock.lockUncancelable(zio()); // H6: exclusive — zeroes keys + nils the slot
        defer self.lock.unlock(zio());
        if (self.static_map.get(wg_pubkey)) |slot| {
            if (self.peers[slot]) |*peer| {
                self.index_map.remove(peer.sender_index);
                // Clear mesh IP routing
                if (peer.mesh_ip[0] != 0 or peer.mesh_ip[1] != 0) {
                    self.ip_to_slot[meshIpHostId(peer.mesh_ip)] = 0xFF;
                }
                self.static_map.remove(wg_pubkey);
                // Securely zero out key material before removal
                peer.deinit();
                self.peers[slot] = null;
                self.peer_count -|= 1;
            }
        }
    }

    /// Initiate a handshake with a peer.
    pub fn initiateHandshake(self: *WgDevice, slot: usize) !noise.HandshakeInitiation {
        self.lock.lockUncancelable(zio()); // H6: exclusive — mutates index_map + peer
        defer self.lock.unlock(zio());
        const peer = if (self.peers[slot]) |*p| p else return error.PeerNotFound;
        const now = nowNs();

        // Rate limit: 1 handshake per 5 seconds
        if (now - peer.last_handshake_ns < 5 * std.time.ns_per_s) {
            return error.HandshakeRateLimited;
        }

        // Remove old index mapping, allocate new one
        self.index_map.remove(peer.sender_index);
        peer.sender_index = self.allocIndex();
        self.index_map.put(peer.sender_index, slot);

        const msg = try peer.handshake.createInitiation(peer.sender_index);
        peer.last_handshake_ns = now;
        peer.handshake_attempts += 1;
        return msg;
    }

    /// Handle an incoming handshake initiation (we are responder).
    /// O(1) lookup via static key table instead of O(N) peer iteration.
    pub fn handleInitiation(self: *WgDevice, msg: *const noise.HandshakeInitiation, src_ip: [4]u8) !InitiationResult {
        // Step 0: Verify MAC1 BEFORE expensive DH (cheap, no lock).
        // MAC1 is keyed with our public key, so we can check without knowing the sender.
        if (!noise.verifyMac1(self.static_public, msg)) {
            return error.InvalidMac;
        }

        // Step 0.5 (H4): rate-limit per source BEFORE the X25519 below. The MAC1
        // key is public, so a flood of MAC1-valid inits would otherwise burn one
        // X25519 each on this thread. Checked under the limiter's own lock so a
        // flood does not even contend the device lock.
        if (!self.hs_limiter.allow(src_ip, nowNs())) {
            return error.HandshakeRateLimited;
        }

        return self.handleInitiationAdmitted(msg);
    }

    /// Process a handshake initiation that has ALREADY passed admission control
    /// (MAC1 + rate limit). Used by the FFI auto-register path to retry after
    /// registering the peer, WITHOUT charging the rate limiter a second time for
    /// the same legitimate handshake (the first attempt already consumed a token
    /// before failing with UnknownPeer).
    pub fn handleInitiationAdmitted(self: *WgDevice, msg: *const noise.HandshakeInitiation) !InitiationResult {
        // The expensive crypto + peer-table mutation below run under the
        // exclusive device lock (H6).
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());

        // Step 1: Perform the Noise IK preamble (e, es, decrypt static).
        // Returns NoisePreamble with intermediate state to avoid double DH.
        const preamble = try noise.decryptInitiatorStatic(
            self.static_private,
            self.static_public,
            msg,
        );

        // Step 2: O(1) lookup by decrypted static key
        const slot = self.static_map.get(preamble.initiator_static) orelse return error.UnknownPeer;
        const peer = if (self.peers[slot]) |*p| p else return error.PeerNotFound;

        // Step 3: Continue from preamble state (no redundant X25519)
        try peer.handshake.consumeInitiationFast(msg, preamble);

        // If we already have an outstanding locally-initiated handshake, keep
        // its sender index mapped so the matching response can still complete.
        // Otherwise, a simultaneous initiation race causes both peers to drop
        // the other's handshake response as UnknownIndex and data traffic never
        // establishes despite both sides having responded.
        if (peer.handshake.state != .created_initiation) {
            self.index_map.remove(peer.sender_index);
            peer.sender_index = self.allocIndex();
            self.index_map.put(peer.sender_index, slot);
        }

        const response = try peer.handshake.createResponse(peer.sender_index);

        // Derive transport keys
        const keys = try peer.handshake.deriveTransportKeys();
        peer.active_tunnel = tunnel.Tunnel{ .keys = keys };

        // NOTE: We do NOT insert remote sender_index into our index_map.
        // The index_map only contains indices WE generated. Remote indices
        // could be attacker-controlled and cause tunnel hijacking.

        return .{ .response = response, .slot = slot };
    }

    /// Handle an incoming handshake response (we are initiator).
    pub fn handleResponse(self: *WgDevice, msg: *const noise.HandshakeResponse) !usize {
        self.lock.lockUncancelable(zio()); // H6: exclusive — sets active_tunnel
        defer self.lock.unlock(zio());
        // Look up by receiver_index (which is our sender_index)
        const recv_idx = std.mem.littleToNative(u32, msg.receiver_index);
        const peer_slot = self.index_map.get(recv_idx) orelse return error.UnknownIndex;
        const peer = if (self.peers[peer_slot]) |*p| p else return error.PeerNotFound;

        try peer.handshake.consumeResponse(msg);

        // Derive transport keys
        const keys = try peer.handshake.deriveTransportKeys();
        peer.active_tunnel = tunnel.Tunnel{ .keys = keys };
        peer.handshake_attempts = 0;

        // NOTE: We do NOT insert remote sender_index into our index_map.
        // Only locally-generated indices belong in the map.

        return peer_slot;
    }

    /// Encrypt an IP packet for a specific peer.
    pub fn encryptForPeer(self: *WgDevice, slot: usize, plaintext: []const u8, out: []u8) !usize {
        self.lock.lockSharedUncancelable(zio()); // H6: shared — excludes removePeer
        defer self.lock.unlockShared(zio());
        const peer = if (self.peers[slot]) |*p| p else return error.PeerNotFound;
        const tun = if (peer.active_tunnel) |*t| t else return error.NoTunnel;
        return tun.encrypt(plaintext, out);
    }

    /// Decrypt an incoming transport packet.
    /// Returns: (peer_slot, decrypted_length, peer identity_key). The identity_key
    /// is captured under the lock so callers never have to re-read peers[slot]
    /// afterwards (which would race removePeer — see H6).
    pub fn decryptTransport(self: *WgDevice, packet: []const u8, out: []u8) !struct { slot: usize, len: usize, identity_key: [32]u8 } {
        if (packet.len < 16) return error.PacketTooShort;

        self.lock.lockSharedUncancelable(zio()); // H6: shared — excludes removePeer
        defer self.lock.unlockShared(zio());

        // Look up peer by receiver_index (which is the index they assigned us)
        const recv_idx = std.mem.readInt(u32, packet[4..8], .little);
        const peer_slot = self.index_map.get(recv_idx) orelse return error.UnknownIndex;
        const peer = if (self.peers[peer_slot]) |*p| p else return error.PeerNotFound;
        const tun = if (peer.active_tunnel) |*t| t else return error.NoTunnel;
        const identity_key = peer.identity_key;

        const len = try tun.decrypt(packet, out);

        // SECURITY (H1): RX cryptokey routing. A decrypted transport packet must
        // carry an inner SOURCE address that belongs to the peer it arrived from.
        // The kernel WireGuard path enforces this via AllowedIPs; the userspace
        // plane previously did not, letting any admitted peer spoof any mesh
        // source IP (cross-tenant impersonation, ARP/conntrack poisoning, bypass
        // of source-based service policy). Drop on mismatch.
        if (!innerSourceAllowed(peer.mesh_ip, peer.mesh_ip6, out[0..len])) {
            return error.SourceSpoofed;
        }
        return .{ .slot = peer_slot, .len = len, .identity_key = identity_key };
    }

    /// Find a peer slot by identity key.
    pub fn findByIdentity(self: *const WgDevice, identity_key: [32]u8) ?usize {
        for (self.peers, 0..) |slot, i| {
            if (slot) |peer| {
                if (std.mem.eql(u8, &peer.identity_key, &identity_key)) return i;
            }
        }
        return null;
    }

    /// Find a peer slot by WG public key (O(1) via static_map).
    pub fn findByWgPubkey(self: *const WgDevice, wg_pubkey: [32]u8) ?usize {
        return self.static_map.get(wg_pubkey);
    }

    /// O(1) mesh IP routing lookup for data plane.
    /// Extracts host ID from destination IP and does flat-array lookup.
    pub fn lookupByMeshIp(self: *const WgDevice, dst_ip: [4]u8) ?usize {
        const slot = self.ip_to_slot[meshIpHostId(dst_ip)];
        if (slot == 0xFF) return null;
        return @as(usize, slot);
    }

    pub fn lookupByMeshIp6(self: *const WgDevice, dst_ip: [16]u8) ?usize {
        for (self.peers, 0..) |slot, i| {
            if (slot) |peer| {
                if (std.mem.eql(u8, &peer.mesh_ip6, &dst_ip)) return i;
            }
        }
        return null;
    }
};

/// SECURITY (H1): for a decrypted inner IPv4/IPv6 packet, returns true iff its
/// SOURCE address belongs to the peer it arrived from (RX cryptokey routing).
///
/// Only IPv4 (version nibble 4) and IPv6 (6) packets are constrained — those are
/// the ones routed onto the host IP stack, where a spoofed source matters. Empty
/// keepalives and NON-IP plaintext pass through: the FFI tunnel API frames app
/// payloads (leading-zero length header → version nibble 0) and delivers them to
/// an inbox, not the IP stack, so the source-IP rule does not apply. A zero peer
/// mesh IP means "unconstrained" (interop/test peers added without a derived
/// address); production peers always carry a derived 10.99/16 address.
fn innerSourceAllowed(peer_mesh_ip: [4]u8, peer_mesh_ip6: [16]u8, plaintext: []const u8) bool {
    if (plaintext.len == 0) return true; // WireGuard keepalive
    const version = plaintext[0] >> 4;
    switch (version) {
        4 => {
            if (plaintext.len < 20) return false; // too short to hold an IPv4 header
            const unset = (peer_mesh_ip[0] | peer_mesh_ip[1] | peer_mesh_ip[2] | peer_mesh_ip[3]) == 0;
            if (unset) return true;
            return std.mem.eql(u8, plaintext[12..16], &peer_mesh_ip);
        },
        6 => {
            if (plaintext.len < 40) return false; // too short to hold an IPv6 header
            const zero6 = [_]u8{0} ** 16;
            if (std.mem.eql(u8, &peer_mesh_ip6, &zero6)) return true;
            return std.mem.eql(u8, plaintext[8..24], &peer_mesh_ip6);
        },
        else => return true, // non-IP framed payload (FFI tunnel inbox) — not IP-routed
    }
}

// ─── Tests ───

test "WgDevice add/remove peer" {
    const X25519 = std.crypto.dh.X25519;
    var secret: [32]u8 = undefined;
    zio().random(&secret);
    const pubkey = try X25519.recoverPublicKey(secret);

    var dev = WgDevice.init(secret, pubkey);

    var peer_secret: [32]u8 = undefined;
    zio().random(&peer_secret);
    const peer_pub = try X25519.recoverPublicKey(peer_secret);

    const slot = try dev.addPeer(.{0} ** 32, peer_pub, .{ 10, 0, 0, 1 }, 51821);
    try std.testing.expectEqual(dev.peer_count, 1);
    try std.testing.expect(dev.peers[slot] != null);

    // Verify O(1) lookup works
    try std.testing.expectEqual(dev.findByWgPubkey(peer_pub), slot);

    dev.removePeer(peer_pub);
    try std.testing.expectEqual(dev.peer_count, 0);
    try std.testing.expectEqual(dev.findByWgPubkey(peer_pub), null);
}

test "handshake rate limiter throttles a single-source flood (H4 regression)" {
    var lim = HandshakeLimiter{};
    const ip = [4]u8{ 203, 0, 113, 7 };
    const t0: i128 = 1_000_000_000;

    // A burst from one source is capped at PER_SRC_BURST; extras are denied.
    var allowed: u32 = 0;
    var i: usize = 0;
    while (i < HandshakeLimiter.PER_SRC_BURST + 5) : (i += 1) {
        if (lim.allow(ip, t0)) allowed += 1;
    }
    try std.testing.expectEqual(HandshakeLimiter.PER_SRC_BURST, allowed);

    // Tokens refill over time — a later attempt succeeds again.
    try std.testing.expect(lim.allow(ip, t0 + HandshakeLimiter.PER_SRC_REFILL_NS + 1));

    // A different source has its own independent budget.
    try std.testing.expect(lim.allow(.{ 198, 51, 100, 9 }, t0));
}

test "innerSourceAllowed enforces RX cryptokey routing (H1 regression)" {
    const peer_ip = [4]u8{ 10, 99, 1, 2 };
    const zero6 = [_]u8{0} ** 16;

    // Valid IPv4 packet whose source is the peer's own mesh IP → allowed.
    var pkt: [20]u8 = .{0} ** 20;
    pkt[0] = 0x45; // IPv4, IHL=5
    @memcpy(pkt[12..16], &peer_ip);
    try std.testing.expect(innerSourceAllowed(peer_ip, zero6, &pkt));

    // Spoofed inner source → rejected.
    var spoof: [20]u8 = .{0} ** 20;
    spoof[0] = 0x45;
    spoof[12] = 10;
    spoof[13] = 99;
    spoof[14] = 9;
    spoof[15] = 9;
    try std.testing.expect(!innerSourceAllowed(peer_ip, zero6, &spoof));

    // Empty keepalive → allowed.
    try std.testing.expect(innerSourceAllowed(peer_ip, zero6, &[_]u8{}));

    // Runt packet claiming IPv4 but too short → rejected (and no OOB read).
    try std.testing.expect(!innerSourceAllowed(peer_ip, zero6, &[_]u8{ 0x45, 0, 0 }));

    // Non-IP framed payload (e.g. FFI tunnel inbox, leading-zero header) → allowed:
    // the source-IP rule only applies to IP-routed packets.
    try std.testing.expect(innerSourceAllowed(peer_ip, zero6, &[_]u8{0x00} ** 20));

    // Unconstrained peer (zero mesh IP, e.g. interop) → not enforced.
    try std.testing.expect(innerSourceAllowed(.{ 0, 0, 0, 0 }, zero6, &spoof));

    // IPv6: matching source allowed, tampered source rejected.
    const peer6 = [16]u8{ 0xfd, 0x99, 0x6d, 0x67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var p6: [40]u8 = .{0} ** 40;
    p6[0] = 0x60; // IPv6
    @memcpy(p6[8..24], &peer6);
    try std.testing.expect(innerSourceAllowed(.{ 0, 0, 0, 0 }, peer6, &p6));
    p6[23] = 0x02; // tamper the source address
    try std.testing.expect(!innerSourceAllowed(.{ 0, 0, 0, 0 }, peer6, &p6));
}

test "IndexTable put/get/remove" {
    var table: IndexTable = .{};
    table.put(42, 5);
    try std.testing.expectEqual(table.get(42), 5);

    table.put(0xDEADBEEF, 10);
    try std.testing.expectEqual(table.get(0xDEADBEEF), 10);

    // Full u32 range
    table.put(0xFFFFFFFF, 99);
    try std.testing.expectEqual(table.get(0xFFFFFFFF), 99);

    table.remove(42);
    try std.testing.expectEqual(table.get(42), null);
    try std.testing.expectEqual(table.get(0xDEADBEEF), 10); // Still there
}

test "PacketType classification" {
    // WG Handshake Init (type 1)
    var init_pkt: [148]u8 = .{0} ** 148;
    std.mem.writeInt(u32, init_pkt[0..4], 1, .little);
    try std.testing.expectEqual(PacketType.classify(&init_pkt), .wg_handshake_init);

    // WG Transport Data (type 4)
    var data_pkt: [32]u8 = .{0} ** 32;
    std.mem.writeInt(u32, data_pkt[0..4], 4, .little);
    try std.testing.expectEqual(PacketType.classify(&data_pkt), .wg_transport);

    // STUN with magic cookie
    var stun_pkt: [20]u8 = .{0} ** 20;
    std.mem.writeInt(u32, stun_pkt[4..8], 0x2112A442, .big);
    try std.testing.expectEqual(PacketType.classify(&stun_pkt), .stun);

    // SWIM (anything else with non-WG first 4 bytes)
    var swim_pkt = [_]u8{ 0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(PacketType.classify(&swim_pkt), .swim);
}
