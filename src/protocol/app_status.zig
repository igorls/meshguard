//! Relay delivery status (`0x51`).
//!
//! When a relay does not forward a sealed `0x50` frame it can tell the sender
//! why, so the sender re-proves its endpoint, backs off, or reports the
//! contact as unreachable instead of waiting for a reply that never comes.
//!
//!   [0x51][32B destination][12B nonce echo][1B code][1B reserved]   47 bytes
//!
//! The status goes only to the frame's source address, echoes the frame's
//! nonce so a client can match it to a frame it sent (an off-path forger must
//! guess 96 bits), and is never larger than a frame, so it cannot amplify.
//! Relays rate-limit statuses per source address, and operators can turn them
//! off (`--no-delivery-status`): they reveal whether a destination is reachable.

const std = @import("std");

pub const TYPE: u8 = 0x51;
pub const SIZE: usize = 47;

pub const Code = enum(u8) {
    /// The destination is not reachable on this relay.
    offline = 1,
    /// The destination is not admitted here.
    destination_not_admitted = 2,
    /// The sender exceeded its forwarding budget.
    rate_limited = 3,
    /// The sender's endpoint is not proven for its key: send a handshake.
    handshake_again = 4,
    /// The sender is not admitted (for example its pass expired).
    not_admitted = 5,
    /// The relay is over its forwarding budget.
    overloaded = 6,
    _,
};

pub const Status = struct {
    destination: [32]u8,
    nonce: [12]u8,
    code: Code,
};

pub fn encode(out: *[SIZE]u8, status: Status) void {
    out[0] = TYPE;
    @memcpy(out[1..33], &status.destination);
    @memcpy(out[33..45], &status.nonce);
    out[45] = @intFromEnum(status.code);
    out[46] = 0;
}

pub fn decode(data: []const u8) ?Status {
    if (data.len != SIZE or data[0] != TYPE) return null;
    return .{ .destination = data[1..33].*, .nonce = data[33..45].*, .code = @enumFromInt(data[45]) };
}

/// The status for a sealed frame `[0x50][dest][sender][nonce]...`.
pub fn forFrame(frame: []const u8, code: Code) ?Status {
    if (frame.len < 77 or frame[0] != 0x50) return null;
    return .{ .destination = frame[1..33].*, .nonce = frame[65..77].*, .code = code };
}

test "a status round-trips and is smaller than any sealed frame" {
    var frame = [_]u8{0} ** 93;
    frame[0] = 0x50;
    @memset(frame[1..33], 0xDD);
    @memset(frame[65..77], 0x77);
    const status = forFrame(&frame, .handshake_again).?;
    var out: [SIZE]u8 = undefined;
    encode(&out, status);
    try std.testing.expect(SIZE < frame.len);
    const back = decode(&out).?;
    try std.testing.expectEqualSlices(u8, &status.destination, &back.destination);
    try std.testing.expectEqualSlices(u8, &status.nonce, &back.nonce);
    try std.testing.expectEqual(Code.handshake_again, back.code);
    try std.testing.expect(decode(out[0..46]) == null);
    try std.testing.expect(forFrame(frame[0..76], .offline) == null);
}
