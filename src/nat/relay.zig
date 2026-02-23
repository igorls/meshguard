//! Mesh relay logic for peers behind symmetric NAT.
//!
//! When hole punching fails (both peers behind symmetric NAT), a public-IP
//! mesh member can relay WireGuard traffic. Since WG provides E2E encryption,
//! the relay only sees ciphertext.
//!
//! Architecture:
//!   Node A (NATed) ←WG→ Relay (public) ←WG→ Node B (NATed)
//!
//! The relay is just another WG peer — no special protocol needed. Both NATed
//! peers add the relay as their WG peer. The relay adds both NATed peers.
//! WG handles routing based on AllowedIPs.

const std = @import("std");
const messages = @import("../protocol/messages.zig");
const Membership = @import("../discovery/membership.zig");

/// Relay node info.
pub const RelayInfo = struct {
    /// Whether this node can serve as a relay
    is_relay_capable: bool,
    /// Number of active relay connections
    active_relay_count: u16,
    /// Max relay connections allowed
    max_relay_peers: u16,
};

/// Maximum relay connections per node (default).
pub const DEFAULT_MAX_RELAY_PEERS: u16 = 10;

/// Check if this node can serve as a relay.
pub fn selfRelayInfo(nat_type: messages.NatType, active_count: u16, max_peers: u16) RelayInfo {
    return .{
        .is_relay_capable = nat_type == .public and active_count < max_peers,
        .active_relay_count = active_count,
        .max_relay_peers = max_peers,
    };
}

/// Select the best relay candidate from known peers.
/// Prefers peers that are:
///   1. Public (no NAT)
///   2. Relay-capable (not at capacity)
///   3. Lowest RTT (closest)
pub fn selectRelay(
    peers: *std.AutoHashMap([32]u8, Membership.Peer),
    exclude: ?[32]u8,
) ?*const Membership.Peer {
    var best: ?*const Membership.Peer = null;
    var best_rtt: u64 = std.math.maxInt(u64);

    var iter = peers.iterator();
    while (iter.next()) |entry| {
        const peer = entry.value_ptr;

        // Skip excluded peer (usually ourselves)
        if (exclude) |ex| {
            if (std.mem.eql(u8, &peer.pubkey, &ex)) continue;
        }

        // Must be alive and relay-capable
        if (peer.state != .alive) continue;
        if (!peer.is_relay_capable) continue;
        if (peer.nat_type != .public) continue;

        // Prefer lowest RTT
        if (peer.last_rtt_ns) |rtt| {
            if (rtt < best_rtt) {
                best_rtt = rtt;
                best = peer;
            }
        } else if (best == null) {
            // No RTT data, but it's the only candidate
            best = peer;
        }
    }

    return best;
}

// ─── Tests ───

test "selfRelayInfo public node" {
    const info = selfRelayInfo(.public, 3, 10);
    try std.testing.expect(info.is_relay_capable);
    try std.testing.expectEqual(info.active_relay_count, 3);
}

test "selfRelayInfo NATed node" {
    const info = selfRelayInfo(.cone, 0, 10);
    try std.testing.expect(!info.is_relay_capable);
}

test "selfRelayInfo at capacity" {
    const info = selfRelayInfo(.public, 10, 10);
    try std.testing.expect(!info.is_relay_capable);
}
