///! WireGuard device — manages per-peer tunnels and the TUN interface.
///!
///! This is the userspace equivalent of the kernel's wg_device.
///! It holds all peer tunnels, routes packets between TUN and UDP,
///! and manages handshake initiation and rekeying.
const std = @import("std");
const noise = @import("noise.zig");
const tunnel = @import("tunnel.zig");

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
        return switch (msg_type) {
            1 => .wg_handshake_init,
            2 => .wg_handshake_resp,
            3 => .wg_cookie,
            4 => .wg_transport,
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
    /// Noise handshake state
    handshake: noise.Handshake,
    /// Active tunnel (after successful handshake)
    active_tunnel: ?tunnel.Tunnel = null,
    /// Our sender index for this peer
    sender_index: u32 = 0,
    /// Peer's endpoint
    endpoint_addr: [4]u8 = .{0} ** 4,
    endpoint_port: u16 = 0,
    /// Last handshake attempt time (for rate limiting)
    last_handshake_ns: i128 = 0,
    /// Number of handshake attempts
    handshake_attempts: u32 = 0,
    /// Per-peer Tx ring for parallel pipeline ordering (only used when --encrypt-workers > 0)
    tx_ring: @import("../net/pipeline.zig").PeerTxRing = .{},
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

    pub fn init(static_private: [32]u8, static_public: [32]u8) WgDevice {
        // Start with a random sender index for unpredictability
        var seed: [4]u8 = undefined;
        std.crypto.random.bytes(&seed);
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
        // Check if peer already exists
        if (self.static_map.get(wg_pubkey)) |existing| {
            if (self.peers[existing]) |*peer| {
                peer.endpoint_addr = addr;
                peer.endpoint_port = port;
                // Update mesh IP routing if provided
                if (mesh_ip[0] != 0 or mesh_ip[1] != 0) {
                    // Clear old mapping if mesh_ip changed
                    if (peer.mesh_ip[0] != 0 or peer.mesh_ip[1] != 0) {
                        const old_host = meshIpHostId(peer.mesh_ip);
                        self.ip_to_slot[old_host] = 0xFF;
                    }
                    peer.mesh_ip = mesh_ip;
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
                    .handshake = handshake,
                    .endpoint_addr = addr,
                    .endpoint_port = port,
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

    /// Remove a peer by WG public key.
    pub fn removePeer(self: *WgDevice, wg_pubkey: [32]u8) void {
        if (self.static_map.get(wg_pubkey)) |slot| {
            if (self.peers[slot]) |*peer| {
                self.index_map.remove(peer.sender_index);
                // Clear mesh IP routing
                if (peer.mesh_ip[0] != 0 or peer.mesh_ip[1] != 0) {
                    self.ip_to_slot[meshIpHostId(peer.mesh_ip)] = 0xFF;
                }
                self.static_map.remove(wg_pubkey);
                // Securely zero out key material before removal
                peer.handshake.deinit();
                self.peers[slot] = null;
                self.peer_count -|= 1;
            }
        }
    }

    /// Initiate a handshake with a peer.
    pub fn initiateHandshake(self: *WgDevice, slot: usize) !noise.HandshakeInitiation {
        const peer = &(self.peers[slot] orelse return error.PeerNotFound);
        const now = std.time.nanoTimestamp();

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
    pub fn handleInitiation(self: *WgDevice, msg: *const noise.HandshakeInitiation) !struct { response: noise.HandshakeResponse, slot: usize } {
        // Step 0: Verify MAC1 BEFORE expensive DH (anti-DoS gate)
        // MAC1 is keyed with our public key, so we can check without knowing the sender.
        if (!noise.verifyMac1(self.static_public, msg)) {
            return error.InvalidMac;
        }

        // Step 1: Perform the Noise IK preamble (e, es, decrypt static).
        // Returns NoisePreamble with intermediate state to avoid double DH.
        const preamble = try noise.decryptInitiatorStatic(
            self.static_private,
            self.static_public,
            msg,
        );

        // Step 2: O(1) lookup by decrypted static key
        const slot = self.static_map.get(preamble.initiator_static) orelse return error.UnknownPeer;
        const peer = &(self.peers[slot] orelse return error.PeerNotFound);

        // Step 3: Continue from preamble state (no redundant X25519)
        try peer.handshake.consumeInitiationFast(msg, preamble);

        // Allocate our sender index for this handshake
        self.index_map.remove(peer.sender_index);
        peer.sender_index = self.allocIndex();
        self.index_map.put(peer.sender_index, slot);

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
        // Look up by receiver_index (which is our sender_index)
        const recv_idx = std.mem.littleToNative(u32, msg.receiver_index);
        const peer_slot = self.index_map.get(recv_idx) orelse return error.UnknownIndex;
        const peer = &(self.peers[peer_slot] orelse return error.PeerNotFound);

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
        const peer = &(self.peers[slot] orelse return error.PeerNotFound);
        const tun = &(peer.active_tunnel orelse return error.NoTunnel);
        return tun.encrypt(plaintext, out);
    }

    /// Decrypt an incoming transport packet.
    /// Returns: (peer_slot, decrypted_length)
    pub fn decryptTransport(self: *WgDevice, packet: []const u8, out: []u8) !struct { slot: usize, len: usize } {
        if (packet.len < 16) return error.PacketTooShort;

        // Look up peer by receiver_index (which is the index they assigned us)
        const recv_idx = std.mem.readInt(u32, packet[4..8], .little);
        const peer_slot = self.index_map.get(recv_idx) orelse return error.UnknownIndex;
        const peer = &(self.peers[peer_slot] orelse return error.PeerNotFound);
        const tun = &(peer.active_tunnel orelse return error.NoTunnel);

        const len = try tun.decrypt(packet, out);
        return .{ .slot = peer_slot, .len = len };
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
};

// ─── Tests ───

test "WgDevice add/remove peer" {
    const X25519 = std.crypto.dh.X25519;
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    const pubkey = try X25519.recoverPublicKey(secret);

    var dev = WgDevice.init(secret, pubkey);

    var peer_secret: [32]u8 = undefined;
    std.crypto.random.bytes(&peer_secret);
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
