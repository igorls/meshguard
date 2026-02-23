//! UDP hole punching coordinator.
//!
//! Implements a rendezvous-mediated hole punching protocol:
//!   1. Initiator sends HolepunchRequest to target via a mutual peer (rendezvous)
//!   2. Target responds with HolepunchResponse
//!   3. Both peers simultaneously send UDP probes to each other's public endpoint
//!   4. Once a probe succeeds, the WG peer endpoint is updated
//!
//! This only works for cone NAT (endpoint-independent mapping).
//! For symmetric NAT, fall back to relay (see relay.zig).

const std = @import("std");
const messages = @import("../protocol/messages.zig");
const Udp = @import("../net/udp.zig");

/// Result of a hole punching attempt.
pub const HolepunchResult = enum {
    /// Hole punch succeeded — direct UDP path established
    success,
    /// Failed: one or both peers behind symmetric NAT
    failed_symmetric_nat,
    /// Timed out waiting for probe response
    timeout,
    /// No mutual public peer available as rendezvous
    no_rendezvous,
};

/// State of an in-progress hole punch.
pub const HolepunchState = struct {
    /// Who initiated this hole punch
    initiator_pubkey: [32]u8,
    /// Target peer
    target_pubkey: [32]u8,
    /// Our public endpoint for this punch
    our_public_endpoint: messages.Endpoint,
    /// Target's public endpoint (filled in when response arrives)
    target_public_endpoint: ?messages.Endpoint,
    /// Random token to verify the exchange
    token: [16]u8,
    /// When the punch was initiated (nanoseconds)
    started_at_ns: i128,
    /// Number of probes sent
    probes_sent: u8,
    /// Whether we've received the target's response
    response_received: bool,
};

/// Maximum concurrent hole punch attempts.
const MAX_CONCURRENT_PUNCHES = 4;

/// Hole punch timeout in nanoseconds (5 seconds).
const PUNCH_TIMEOUT_NS: i128 = 5_000_000_000;

/// Probe interval in nanoseconds (200ms between probes).
const PROBE_INTERVAL_NS: i128 = 200_000_000;

/// Maximum probes per attempt.
const MAX_PROBES: u8 = 25; // 5 seconds / 200ms

/// STUN probe: a small magic packet sent to create NAT mappings.
/// The receiver recognizes this as a hole punch probe and ignores it
/// (it's not a valid SWIM message and won't be processed by the gossip handler).
const PROBE_MAGIC: [4]u8 = .{ 0x4D, 0x47, 0x48, 0x50 }; // "MGHP" = MeshGuard HolePunch

/// Hole punch coordinator — manages concurrent punch attempts.
pub const Holepuncher = struct {
    /// Active hole punch attempts.
    active: [MAX_CONCURRENT_PUNCHES]?HolepunchState = .{ null, null, null, null },

    /// Initiate a hole punch with a remote peer.
    /// Returns the HolepunchRequest to be sent via a rendezvous peer.
    pub fn initiate(
        self: *Holepuncher,
        our_pubkey: [32]u8,
        target_pubkey: [32]u8,
        our_public_endpoint: messages.Endpoint,
    ) ?messages.HolepunchRequest {
        // Find a free slot
        const slot = for (&self.active, 0..) |*s, i| {
            if (s.* == null) break i;
        } else return null; // all slots busy

        var token: [16]u8 = undefined;
        std.crypto.random.bytes(&token);

        self.active[slot] = .{
            .initiator_pubkey = our_pubkey,
            .target_pubkey = target_pubkey,
            .our_public_endpoint = our_public_endpoint,
            .target_public_endpoint = null,
            .token = token,
            .started_at_ns = std.time.nanoTimestamp(),
            .probes_sent = 0,
            .response_received = false,
        };

        return .{
            .sender_pubkey = our_pubkey,
            .target_pubkey = target_pubkey,
            .public_endpoint = our_public_endpoint,
            .token = token,
        };
    }

    /// Process a holepunch response from the target peer.
    /// Returns the target's public endpoint if we can start probing.
    pub fn handleResponse(
        self: *Holepuncher,
        response: messages.HolepunchResponse,
    ) ?messages.Endpoint {
        for (&self.active) |*slot| {
            if (slot.*) |*state| {
                if (std.mem.eql(u8, &state.token, &response.token_echo)) {
                    state.target_public_endpoint = response.public_endpoint;
                    state.response_received = true;
                    return response.public_endpoint;
                }
            }
        }
        return null; // no matching punch attempt
    }

    /// Build a HolepunchResponse for an incoming request.
    pub fn buildResponse(
        our_pubkey: [32]u8,
        our_public_endpoint: messages.Endpoint,
        request: messages.HolepunchRequest,
    ) messages.HolepunchResponse {
        return .{
            .sender_pubkey = our_pubkey,
            .public_endpoint = our_public_endpoint,
            .token_echo = request.token,
        };
    }

    /// Send UDP probes for active punch attempts that are ready.
    /// Returns a list of pubkeys for successful punches.
    pub fn sendProbes(
        self: *Holepuncher,
        socket: *Udp.UdpSocket,
    ) [MAX_CONCURRENT_PUNCHES]?[32]u8 {
        const now = std.time.nanoTimestamp();
        const successes: [MAX_CONCURRENT_PUNCHES]?[32]u8 = .{ null, null, null, null };

        for (&self.active, 0..) |*slot, i| {
            if (slot.*) |*state| {
                // Check timeout
                if (now - state.started_at_ns > PUNCH_TIMEOUT_NS) {
                    slot.* = null; // timed out
                    continue;
                }

                // Only probe if we have the target's public endpoint
                if (state.target_public_endpoint) |target_ep| {
                    if (state.probes_sent < MAX_PROBES) {
                        // Send probe packet
                        _ = socket.sendTo(&PROBE_MAGIC, target_ep.addr, target_ep.port) catch {};
                        state.probes_sent += 1;
                    }

                    // Check if we've received a probe FROM the target
                    // (checked externally via markSuccess)
                    _ = i;
                }
            }
        }

        return successes;
    }

    /// Mark a punch as successful (probe received from target).
    pub fn markSuccess(self: *Holepuncher, from_pubkey: [32]u8) ?messages.Endpoint {
        for (&self.active) |*slot| {
            if (slot.*) |state| {
                if (std.mem.eql(u8, &state.target_pubkey, &from_pubkey)) {
                    const ep = state.target_public_endpoint;
                    slot.* = null; // done
                    return ep;
                }
            }
        }
        return null;
    }

    /// Check if a received packet is a hole punch probe.
    pub fn isProbe(data: []const u8) bool {
        return data.len == PROBE_MAGIC.len and std.mem.eql(u8, data, &PROBE_MAGIC);
    }

    /// Count active punch attempts.
    pub fn activeCount(self: *const Holepuncher) usize {
        var n: usize = 0;
        for (self.active) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }

    /// Clean up timed-out attempts.
    pub fn expireTimeouts(self: *Holepuncher) void {
        const now = std.time.nanoTimestamp();
        for (&self.active) |*slot| {
            if (slot.*) |state| {
                if (now - state.started_at_ns > PUNCH_TIMEOUT_NS) {
                    slot.* = null;
                }
            }
        }
    }
};

// ─── Tests ───

test "initiate and respond" {
    var puncher = Holepuncher{};

    const our_pubkey = [_]u8{0xAA} ** 32;
    const target_pubkey = [_]u8{0xBB} ** 32;
    const our_ep = messages.Endpoint{ .addr = .{ 1, 2, 3, 4 }, .port = 51820 };

    // Initiate a punch
    const request = puncher.initiate(our_pubkey, target_pubkey, our_ep);
    try std.testing.expect(request != null);
    try std.testing.expectEqual(puncher.activeCount(), 1);

    // Build and handle response
    const target_ep = messages.Endpoint{ .addr = .{ 5, 6, 7, 8 }, .port = 51820 };
    const response = Holepuncher.buildResponse([_]u8{0xBB} ** 32, target_ep, request.?);
    const result_ep = puncher.handleResponse(response);
    try std.testing.expect(result_ep != null);
    try std.testing.expectEqual(result_ep.?.addr[0], 5);
}

test "probe magic detection" {
    try std.testing.expect(Holepuncher.isProbe(&PROBE_MAGIC));
    try std.testing.expect(!Holepuncher.isProbe(&.{ 0x01, 0x02, 0x03, 0x04 }));
    try std.testing.expect(!Holepuncher.isProbe(&.{0x01}));
}

test "max concurrent punches" {
    var puncher = Holepuncher{};
    const our_ep = messages.Endpoint{ .addr = .{ 1, 2, 3, 4 }, .port = 51820 };

    // Fill all slots
    for (0..MAX_CONCURRENT_PUNCHES) |i| {
        var target = [_]u8{0} ** 32;
        target[0] = @intCast(i);
        try std.testing.expect(puncher.initiate([_]u8{0xAA} ** 32, target, our_ep) != null);
    }

    // Next one should fail
    try std.testing.expect(puncher.initiate([_]u8{0xAA} ** 32, [_]u8{0xFF} ** 32, our_ep) == null);
    try std.testing.expectEqual(puncher.activeCount(), MAX_CONCURRENT_PUNCHES);
}
