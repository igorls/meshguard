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

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowNs() i128 {
    return @intCast(std.Io.Timestamp.now(zio(), .awake).toNanoseconds());
}

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
const PROBE_SIZE: usize = PROBE_MAGIC.len + 16;

pub const Probe = struct {
    token: [16]u8,
};

pub const PunchSuccess = struct {
    peer_pubkey: [32]u8,
    endpoint: messages.Endpoint,
};

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
        zio().random(&token);

        self.active[slot] = .{
            .initiator_pubkey = our_pubkey,
            .target_pubkey = target_pubkey,
            .our_public_endpoint = our_public_endpoint,
            .target_public_endpoint = null,
            .token = token,
            .started_at_ns = nowNs(),
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
                if (std.mem.eql(u8, &state.token, &response.token_echo) and
                    std.mem.eql(u8, &state.target_pubkey, &response.sender_pubkey))
                {
                    state.target_public_endpoint = response.public_endpoint;
                    state.response_received = true;
                    return response.public_endpoint;
                }
            }
        }
        return null; // no matching punch attempt
    }

    /// Accept an incoming request as the target peer and start a session keyed to
    /// the initiator identity and token. This mirrors initiate(), but preserves
    /// the initiator's token so later probes can be bound to the same session.
    pub fn acceptRequest(
        self: *Holepuncher,
        our_pubkey: [32]u8,
        request: messages.HolepunchRequest,
        our_public_endpoint: messages.Endpoint,
    ) bool {
        for (&self.active) |*slot| {
            if (slot.*) |*state| {
                if (std.mem.eql(u8, &state.initiator_pubkey, &our_pubkey) and
                    std.mem.eql(u8, &state.target_pubkey, &request.sender_pubkey))
                {
                    state.our_public_endpoint = our_public_endpoint;
                    state.target_public_endpoint = request.public_endpoint;
                    state.token = request.token;
                    state.started_at_ns = nowNs();
                    state.probes_sent = 0;
                    state.response_received = true;
                    return true;
                }
            }
        }

        const slot = for (&self.active, 0..) |*s, i| {
            if (s.* == null) break i;
        } else return false;

        self.active[slot] = .{
            .initiator_pubkey = our_pubkey,
            .target_pubkey = request.sender_pubkey,
            .our_public_endpoint = our_public_endpoint,
            .target_public_endpoint = request.public_endpoint,
            .token = request.token,
            .started_at_ns = nowNs(),
            .probes_sent = 0,
            .response_received = true,
        };
        return true;
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
        const now = nowNs();
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
                        var probe_buf: [PROBE_SIZE]u8 = undefined;
                        encodeProbe(state.token, &probe_buf);
                        _ = socket.sendToEndpoint(&probe_buf, target_ep) catch {};
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

    pub fn markProbeSuccess(self: *Holepuncher, probe: Probe, sender_endpoint: messages.Endpoint) ?PunchSuccess {
        for (&self.active) |*slot| {
            if (slot.*) |state| {
                if (!std.mem.eql(u8, &state.token, &probe.token)) continue;
                const target_ep = state.target_public_endpoint orelse continue;
                if (!messages.Endpoint.eql(target_ep, sender_endpoint)) continue;
                const success = PunchSuccess{
                    .peer_pubkey = state.target_pubkey,
                    .endpoint = target_ep,
                };
                slot.* = null;
                return success;
            }
        }
        return null;
    }

    pub fn encodeProbe(token: [16]u8, out: *[PROBE_SIZE]u8) void {
        @memcpy(out[0..PROBE_MAGIC.len], &PROBE_MAGIC);
        @memcpy(out[PROBE_MAGIC.len..][0..16], &token);
    }

    pub fn decodeProbe(data: []const u8) ?Probe {
        if (data.len != PROBE_SIZE) return null;
        if (!std.mem.eql(u8, data[0..PROBE_MAGIC.len], &PROBE_MAGIC)) return null;
        var token: [16]u8 = undefined;
        @memcpy(&token, data[PROBE_MAGIC.len..][0..16]);
        return .{ .token = token };
    }

    /// Check if a received packet is a hole punch probe.
    pub fn isProbe(data: []const u8) bool {
        return decodeProbe(data) != null;
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
        const now = nowNs();
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
    var probe_buf: [PROBE_SIZE]u8 = undefined;
    Holepuncher.encodeProbe([_]u8{0x42} ** 16, &probe_buf);

    try std.testing.expect(Holepuncher.isProbe(&probe_buf));
    try std.testing.expectEqualSlices(u8, &([_]u8{0x42} ** 16), &Holepuncher.decodeProbe(&probe_buf).?.token);
    try std.testing.expect(!Holepuncher.isProbe(&PROBE_MAGIC));
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

test "holepunch response is bound to token and peer identity" {
    var puncher = Holepuncher{};
    const our_pubkey = [_]u8{0xAA} ** 32;
    const target_pubkey = [_]u8{0xBB} ** 32;
    const wrong_pubkey = [_]u8{0xCC} ** 32;
    const our_ep = messages.Endpoint.initV4(.{ 1, 2, 3, 4 }, 51821);
    const target_ep = messages.Endpoint.initV4(.{ 5, 6, 7, 8 }, 51821);

    const req = puncher.initiate(our_pubkey, target_pubkey, our_ep).?;
    try std.testing.expect(puncher.handleResponse(.{
        .sender_pubkey = wrong_pubkey,
        .public_endpoint = target_ep,
        .token_echo = req.token,
    }) == null);
    try std.testing.expect(puncher.handleResponse(.{
        .sender_pubkey = target_pubkey,
        .public_endpoint = target_ep,
        .token_echo = [_]u8{0x11} ** 16,
    }) == null);
    try std.testing.expect(puncher.handleResponse(.{
        .sender_pubkey = target_pubkey,
        .public_endpoint = target_ep,
        .token_echo = req.token,
    }) != null);
}

test "target accepts request with initiator session token" {
    var puncher = Holepuncher{};
    const our_pubkey = [_]u8{0xBB} ** 32;
    const initiator_pubkey = [_]u8{0xAA} ** 32;
    const our_ep = messages.Endpoint.initV4(.{ 5, 6, 7, 8 }, 51821);
    const initiator_ep = messages.Endpoint.initV4(.{ 1, 2, 3, 4 }, 51821);
    const token = [_]u8{0x99} ** 16;

    try std.testing.expect(puncher.acceptRequest(our_pubkey, .{
        .sender_pubkey = initiator_pubkey,
        .target_pubkey = our_pubkey,
        .public_endpoint = initiator_ep,
        .token = token,
    }, our_ep));
    try std.testing.expectEqual(@as(usize, 1), puncher.activeCount());

    const success = puncher.markProbeSuccess(.{ .token = token }, initiator_ep).?;
    try std.testing.expectEqualSlices(u8, &initiator_pubkey, &success.peer_pubkey);
    try std.testing.expect(messages.Endpoint.eql(initiator_ep, success.endpoint));
    try std.testing.expectEqual(@as(usize, 0), puncher.activeCount());
}
