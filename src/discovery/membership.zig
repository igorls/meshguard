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
    /// STUN-discovered public endpoint (NAT traversal)
    public_endpoint: ?messages.Endpoint = null,
    /// NAT type classification
    nat_type: messages.NatType = .unknown,
    /// Whether this peer can act as a relay
    is_relay_capable: bool = false,
};

pub const MembershipTable = struct {
    allocator: std.mem.Allocator,
    peers: std.AutoHashMap([32]u8, Peer),
    /// Local node's Lamport clock
    lamport: u64,
    /// Suspicion timeout in nanoseconds
    suspicion_timeout_ns: i128,

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
        const existing = self.peers.get(peer.pubkey);
        if (existing) |e| {
            // Only update if the incoming info is newer (higher Lamport timestamp)
            if (peer.lamport <= e.lamport) return;
        }
        try self.peers.put(peer.pubkey, peer);
    }

    /// Mark a peer as suspected (failed to respond to ping).
    pub fn suspect(self: *MembershipTable, pubkey: [32]u8) void {
        if (self.peers.getPtr(pubkey)) |peer| {
            if (peer.state == .alive) {
                self.lamport += 1;
                peer.state = .suspected;
                peer.suspected_at_ns = std.time.nanoTimestamp();
                peer.lamport = self.lamport;
            }
        }
    }

    /// Mark a peer as alive (responded to ping).
    pub fn markAlive(self: *MembershipTable, pubkey: [32]u8, rtt_ns: ?u64) void {
        if (self.peers.getPtr(pubkey)) |peer| {
            self.lamport += 1;
            peer.state = .alive;
            peer.last_seen_ns = std.time.nanoTimestamp();
            peer.suspected_at_ns = null;
            peer.last_rtt_ns = rtt_ns;
            peer.lamport = self.lamport;
        }
    }

    /// Mark a peer as dead (confirmed unreachable).
    pub fn markDead(self: *MembershipTable, pubkey: [32]u8) void {
        if (self.peers.getPtr(pubkey)) |peer| {
            self.lamport += 1;
            peer.state = .dead;
            peer.lamport = self.lamport;
        }
    }

    /// Remove a dead peer from the table entirely.
    pub fn remove(self: *MembershipTable, pubkey: [32]u8) void {
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
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.nanoTimestamp()));
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

    /// Check suspected peers and promote to dead if timeout expired.
    pub fn expireSuspected(self: *MembershipTable) [][32]u8 {
        const now = std.time.nanoTimestamp();
        // Collect keys of peers to mark as dead (can't modify map while iterating)
        var to_kill_buf: [256][32]u8 = undefined;
        var to_kill_count: usize = 0;

        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state == .suspected) {
                if (entry.value_ptr.suspected_at_ns) |suspected_at| {
                    if (now - suspected_at > self.suspicion_timeout_ns) {
                        if (to_kill_count < to_kill_buf.len) {
                            to_kill_buf[to_kill_count] = entry.key_ptr.*;
                            to_kill_count += 1;
                        }
                    }
                }
            }
        }

        for (to_kill_buf[0..to_kill_count]) |pubkey| {
            self.markDead(pubkey);
        }

        return to_kill_buf[0..to_kill_count];
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
        .last_seen_ns = std.time.nanoTimestamp(),
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
