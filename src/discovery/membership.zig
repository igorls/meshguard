//! SWIM membership table and peer state machine.
//!
//! Tracks all known peers and their lifecycle:
//!   ALIVE → SUSPECTED → DEAD → (removed)
//!
//! State transitions:
//!   - ALIVE: peer responds to pings normally
//!   - SUSPECTED: peer failed to respond, being investigated
//!   - DEAD: peer confirmed unreachable, WireGuard peer removed

const std = @import("std");
const messages = @import("../protocol/messages.zig");

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowNs() i128 {
    return @intCast(std.Io.Timestamp.now(zio(), .awake).toNanoseconds());
}

pub const PeerState = enum {
    alive,
    suspected,
    dead,
    left, // graceful departure
};

pub const Peer = struct {
    /// Ed25519 public key — the peer's identity
    pubkey: [32]u8,
    /// Human-readable name (if known)
    name: []const u8,
    /// Current state in the SWIM lifecycle
    state: PeerState,
    /// Network endpoint for gossip communication
    gossip_endpoint: ?messages.Endpoint,
    /// WireGuard public key (exchanged during handshake)
    wg_pubkey: ?[32]u8,
    /// Deterministic mesh IP
    mesh_ip: [4]u8,
    /// Deterministic mesh IPv6 address
    mesh_ip6: [16]u8 = .{0} ** 16,
    /// WireGuard listen port
    wg_port: u16,
    /// Lamport timestamp of last state change
    lamport: u64,
    /// Wall-clock time of last successful ping (nanoseconds)
    last_seen_ns: i128,
    /// When the node was marked as suspected (nanoseconds), null if not suspected
    suspected_at_ns: ?i128,
    /// Round-trip time of last successful ping (nanoseconds)
    last_rtt_ns: ?u64,
    /// Whether handshake has been completed
    handshake_complete: bool,
    /// Peer's advertised incarnation (startup epoch). When a ping/ack arrives
    /// with a higher incarnation than this, the peer has restarted and must be
    /// re-integrated. 0 = not yet known.
    incarnation: u64 = 0,
    /// STUN-discovered public endpoint (NAT traversal)
    public_endpoint: ?messages.Endpoint = null,
    /// NAT type classification
    nat_type: messages.NatType = .unknown,
    /// Whether this peer can act as a relay
    is_relay_capable: bool = false,
    // ── Org trust fields ──
    /// Org public key (if peer authenticated via org cert)
    org_pubkey: ?[32]u8 = null,
    /// Node name from certificate (e.g. "node-1")
    org_node_name: [32]u8 = std.mem.zeroes([32]u8),
    /// Certificate expiry (0 = never, null = no cert)
    cert_expires_at: ?i64 = null,
};

/// Hard cap on tracked peers. Without this, unauthenticated SWIM gossip (open
/// trust by default) lets a remote attacker inject unbounded fake members until
/// OOM (plus quadratic per-tick CPU). 4096 bounds memory to ~1 MB while staying
/// well above any realistic mesh size; new peers past the cap reclaim a
/// dead/left/suspected slot or are dropped.
pub const MAX_MEMBERS: usize = 4096;

pub const MembershipTable = struct {
    allocator: std.mem.Allocator,
    peers: std.AutoHashMap([32]u8, Peer),
    /// Local node's Lamport clock
    lamport: u64,
    /// Suspicion timeout in nanoseconds
    suspicion_timeout_ns: i128,
    /// SECURITY (H7): guards `peers` against the single writer (the SWIM/event-loop
    /// thread, via the mutating methods below) racing concurrent readers on other
    /// threads (FFI host calls, data-plane workers). A `peers.put` rehash frees the
    /// old buckets; an unsynchronized reader would then hit freed memory. Mutating
    /// methods take the write lock; external readers must take the read lock via
    /// `lock.lockShared()`. The SWIM thread's own direct reads need no lock (it is
    /// the only writer). Methods release the lock before any handler callback fires,
    /// so this lock is never held together with the WgDevice lock (no inversion).
    lock: std.Io.RwLock = .init,

    pub fn init(allocator: std.mem.Allocator, suspicion_timeout_ms: u32) MembershipTable {
        return .{
            .allocator = allocator,
            .peers = std.AutoHashMap([32]u8, Peer).init(allocator),
            .lamport = 0,
            .suspicion_timeout_ns = @as(i128, suspicion_timeout_ms) * 1_000_000,
        };
    }

    pub fn deinit(self: *MembershipTable) void {
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.name.len > 0) {
                self.allocator.free(entry.value_ptr.name);
            }
        }
        self.peers.deinit();
    }

    /// Add or update a peer in the membership table.
    pub fn upsert(self: *MembershipTable, peer: Peer) !void {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        const existing = self.peers.get(peer.pubkey);
        if (existing) |e| {
            // Only update if the incoming info is newer (higher Lamport timestamp)
            if (peer.lamport <= e.lamport) return;
            // Free the previous name allocation we're about to overwrite, unless
            // the caller is reusing the same buffer (avoids a leak and a later
            // double-free; names are owned by self.allocator like remove/deinit).
            if (e.name.len > 0 and e.name.ptr != peer.name.ptr) {
                self.allocator.free(e.name);
            }
            try self.peers.put(peer.pubkey, peer);
            return;
        }
        // New peer: enforce the capacity bound. Try to reclaim a non-alive slot
        // before rejecting, so honest churn keeps working while a flood of fake
        // members cannot grow the table without limit.
        if (self.peers.count() >= MAX_MEMBERS and !self.evictOneReclaimable()) {
            return error.MembershipFull;
        }
        try self.peers.put(peer.pubkey, peer);
    }

    /// Evict one dead/left/suspected peer to make room under MAX_MEMBERS.
    /// Returns true if a peer was removed. Never evicts an alive peer.
    /// Caller must hold the write lock (called from upsert).
    fn evictOneReclaimable(self: *MembershipTable) bool {
        var victim: ?[32]u8 = null;
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state == .dead or entry.value_ptr.state == .left) {
                victim = entry.key_ptr.*;
                break;
            }
        }
        if (victim == null) {
            var it2 = self.peers.iterator();
            while (it2.next()) |entry| {
                if (entry.value_ptr.state == .suspected) {
                    victim = entry.key_ptr.*;
                    break;
                }
            }
        }
        if (victim) |v| {
            self.removeLocked(v);
            return true;
        }
        return false;
    }

    /// Mark a peer as suspected (failed to respond to ping).
    pub fn suspect(self: *MembershipTable, pubkey: [32]u8) void {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        if (self.peers.getPtr(pubkey)) |peer| {
            if (peer.state == .alive) {
                self.lamport +|= 1;
                peer.state = .suspected;
                peer.suspected_at_ns = nowNs();
                peer.lamport = self.lamport;
            }
        }
    }

    /// Mark a peer as alive (responded to ping).
    pub fn markAlive(self: *MembershipTable, pubkey: [32]u8, rtt_ns: ?u64) void {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        if (self.peers.getPtr(pubkey)) |peer| {
            self.lamport += 1;
            peer.state = .alive;
            peer.last_seen_ns = nowNs();
            peer.suspected_at_ns = null;
            peer.last_rtt_ns = rtt_ns;
            peer.lamport = self.lamport;
        }
    }

    /// Mark a peer as dead (confirmed unreachable).
    pub fn markDead(self: *MembershipTable, pubkey: [32]u8) void {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        self.markDeadLocked(pubkey);
    }

    /// markDead body without locking — caller must hold the write lock.
    fn markDeadLocked(self: *MembershipTable, pubkey: [32]u8) void {
        if (self.peers.getPtr(pubkey)) |peer| {
            self.lamport += 1;
            peer.state = .dead;
            peer.lamport = self.lamport;
        }
    }

    /// Remove a dead peer from the table entirely.
    pub fn remove(self: *MembershipTable, pubkey: [32]u8) void {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        self.removeLocked(pubkey);
    }

    /// remove body without locking — caller must hold the write lock.
    fn removeLocked(self: *MembershipTable, pubkey: [32]u8) void {
        if (self.peers.fetchRemove(pubkey)) |kv| {
            if (kv.value.name.len > 0) {
                self.allocator.free(kv.value.name);
            }
        }
    }

    /// Get all alive peers.
    pub fn alivePeers(self: *MembershipTable, allocator: std.mem.Allocator) ![][32]u8 {
        var result = std.ArrayList([32]u8).init(allocator);
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state == .alive) {
                try result.append(entry.key_ptr.*);
            }
        }
        return result.toOwnedSlice();
    }

    /// Pick a random alive peer for SWIM probing.
    pub fn randomAlivePeer(self: *MembershipTable) ?*Peer {
        var alive_count: usize = 0;
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state == .alive) {
                alive_count += 1;
            }
        }

        if (alive_count == 0) return null;

        // Use a simple PRNG seeded from timestamp
        var prng = std.Random.DefaultPrng.init(@intCast(nowNs()));
        const random = prng.random();
        const target = random.intRangeAtMost(usize, 0, alive_count - 1);

        var idx: usize = 0;
        var iter2 = self.peers.iterator();
        while (iter2.next()) |entry| {
            if (entry.value_ptr.state == .alive) {
                if (idx == target) return entry.value_ptr;
                idx += 1;
            }
        }

        return null;
    }

    /// Check suspected peers and promote to dead if their suspicion timeout
    /// expired. The expired pubkeys are written into the caller-provided `out`
    /// buffer and the count is returned.
    ///
    /// SECURITY (use-after-return): this used to return a slice into its own
    /// stack frame, which the caller's per-element work (print/onPeerDead/
    /// enqueueGossip) then overwrote. The buffer is now owned by the caller so
    /// it stays live across that loop.
    pub fn expireSuspected(self: *MembershipTable, out: [][32]u8) usize {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        const now = nowNs();
        var n: usize = 0;

        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state == .suspected) {
                if (entry.value_ptr.suspected_at_ns) |suspected_at| {
                    if (now - suspected_at > self.suspicion_timeout_ns) {
                        if (n < out.len) {
                            out[n] = entry.key_ptr.*;
                            n += 1;
                        }
                    }
                }
            }
        }

        for (out[0..n]) |pubkey| {
            self.markDeadLocked(pubkey);
        }

        return n;
    }

    /// Number of peers in a given state.
    pub fn countByState(self: *MembershipTable, state: PeerState) usize {
        var n: usize = 0;
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state == state) n += 1;
        }
        return n;
    }

    /// Total number of peers.
    pub fn count(self: *MembershipTable) usize {
        return self.peers.count();
    }
};

// ─── Tests ───

test "basic membership lifecycle" {
    const allocator = std.testing.allocator;
    var table = MembershipTable.init(allocator, 5000);
    defer table.deinit();

    const pubkey = [_]u8{0x42} ** 32;
    try table.upsert(.{
        .pubkey = pubkey,
        .name = "",
        .state = .alive,
        .gossip_endpoint = null,
        .wg_pubkey = null,
        .mesh_ip = .{ 10, 99, 1, 2 },
        .wg_port = 51820,
        .lamport = 1,
        .last_seen_ns = nowNs(),
        .suspected_at_ns = null,
        .last_rtt_ns = null,
        .handshake_complete = false,
    });

    try std.testing.expectEqual(table.count(), 1);
    try std.testing.expectEqual(table.countByState(.alive), 1);

    table.suspect(pubkey);
    try std.testing.expectEqual(table.countByState(.suspected), 1);

    table.markAlive(pubkey, 12_000_000);
    try std.testing.expectEqual(table.countByState(.alive), 1);

    table.markDead(pubkey);
    try std.testing.expectEqual(table.countByState(.dead), 1);

    table.remove(pubkey);
    try std.testing.expectEqual(table.count(), 0);
}

test "lamport ordering" {
    const allocator = std.testing.allocator;
    var table = MembershipTable.init(allocator, 5000);
    defer table.deinit();

    const pubkey = [_]u8{0xAA} ** 32;

    // Insert with lamport=5
    try table.upsert(.{
        .pubkey = pubkey,
        .name = "",
        .state = .alive,
        .gossip_endpoint = null,
        .wg_pubkey = null,
        .mesh_ip = .{ 10, 99, 1, 1 },
        .wg_port = 51820,
        .lamport = 5,
        .last_seen_ns = 0,
        .suspected_at_ns = null,
        .last_rtt_ns = null,
        .handshake_complete = false,
    });

    // Try to update with older lamport=3 — should be ignored
    try table.upsert(.{
        .pubkey = pubkey,
        .name = "",
        .state = .dead,
        .gossip_endpoint = null,
        .wg_pubkey = null,
        .mesh_ip = .{ 10, 99, 1, 1 },
        .wg_port = 51820,
        .lamport = 3,
        .last_seen_ns = 0,
        .suspected_at_ns = null,
        .last_rtt_ns = null,
        .handshake_complete = false,
    });

    // State should still be alive (lamport 3 < 5)
    const peer = table.peers.get(pubkey).?;
    try std.testing.expectEqual(peer.state, .alive);
}

fn testPeer(pk: [32]u8, state: PeerState, suspected_at: ?i128) Peer {
    return .{
        .pubkey = pk,
        .name = "",
        .state = state,
        .gossip_endpoint = null,
        .wg_pubkey = null,
        .mesh_ip = .{ 0, 0, 0, 0 },
        .wg_port = 0,
        .lamport = 1,
        .last_seen_ns = 0,
        .suspected_at_ns = suspected_at,
        .last_rtt_ns = null,
        .handshake_complete = false,
    };
}

test "membership table caps growth and reclaims non-alive slots (H3 regression)" {
    const allocator = std.testing.allocator;
    var table = MembershipTable.init(allocator, 5000);
    defer table.deinit();

    var i: usize = 0;
    while (i < MAX_MEMBERS) : (i += 1) {
        var pk = [_]u8{0} ** 32;
        std.mem.writeInt(u32, pk[0..4], @intCast(i), .little);
        try table.upsert(testPeer(pk, .alive, null));
    }
    try std.testing.expectEqual(MAX_MEMBERS, table.count());

    // A new peer past the cap with no reclaimable slot must be rejected.
    const overflow_pk = [_]u8{0xFF} ** 32;
    try std.testing.expectError(error.MembershipFull, table.upsert(testPeer(overflow_pk, .alive, null)));

    // Kill an existing peer, then the new peer is admitted by reclaiming it.
    const victim = [_]u8{0} ** 32; // i==0
    table.markDead(victim);
    try table.upsert(testPeer(overflow_pk, .alive, null));
    try std.testing.expectEqual(MAX_MEMBERS, table.count());
    try std.testing.expect(table.peers.get(overflow_pk) != null);
}

test "expireSuspected writes to caller-owned buffer (H8 regression)" {
    const allocator = std.testing.allocator;
    var table = MembershipTable.init(allocator, 1000); // 1s timeout
    defer table.deinit();

    const keys = [_][32]u8{ [_]u8{1} ** 32, [_]u8{2} ** 32, [_]u8{3} ** 32 };
    for (keys) |k| {
        try table.upsert(testPeer(k, .suspected, 1)); // suspected_at = 1ns → long expired
    }

    var buf: [8][32]u8 = undefined;
    const n = table.expireSuspected(&buf);
    try std.testing.expectEqual(@as(usize, 3), n);
    // Every returned key must be a real, now-dead peer. Pre-fix, the 2nd/3rd
    // entries were garbage read from a reclaimed stack frame.
    for (buf[0..n]) |k| {
        const p = table.peers.get(k) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(PeerState.dead, p.state);
    }
}
