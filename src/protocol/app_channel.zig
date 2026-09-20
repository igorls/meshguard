//! Isolated application-channel framing inside decrypted 0x50 plaintext.
//!
//! Wire format (UTF-8, no NUL terminator):
//!
//!     MGAPP1 <channel> <payload>
//!
//! `MGAPP1` plus the following space is a reserved prefix. Unframed / non-MGAPP1
//! plaintext continues to use the legacy SEND/RECV/MSGS queue.
//!
//! Channel rules:
//!   - length 1–64
//!   - charset `[a-z0-9._-]`
//!
//! Size budget:
//!   The 0x50 plaintext is capped at 1024 bytes (`MAX_PLAINTEXT`).
//!   Framing overhead is `len("MGAPP1 ")` + channel + one space.
//!   `MAX_APP_PAYLOAD` (952) is the conservative universal maximum that fits
//!   even with a 64-byte channel. A shorter channel (e.g. `meshrooms-v1`) has
//!   more room; APPINFO still reports 952 so clients do not over-claim.
//!
//! Malformed or oversize MGAPP1 frames are rejected. They are never truncated
//! and never placed on the legacy queue.

const std = @import("std");

pub const PREFIX = "MGAPP1 ";
pub const MIN_CHANNEL_LEN: usize = 1;
pub const MAX_CHANNEL_LEN: usize = 64;
pub const MAX_PLAINTEXT: usize = 1024;
pub const FRAME_OVERHEAD_WITHOUT_CHANNEL: usize = PREFIX.len + 1; // prefix + payload separator
pub const MAX_APP_PAYLOAD: usize = MAX_PLAINTEXT - FRAME_OVERHEAD_WITHOUT_CHANNEL - MAX_CHANNEL_LEN;
pub const MESHROOMS_CHANNEL = "meshrooms-v1";
pub const PROTOCOL_VERSION: u8 = 1;

pub const Frame = struct {
    channel: []const u8,
    payload: []const u8,
};

pub const ParseError = error{
    Malformed,
    InvalidChannel,
    Oversize,
};

pub const EncodeError = error{
    InvalidChannel,
    Oversize,
};

pub fn isValidChannelChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '.' or c == '_' or c == '-';
}

pub fn isValidChannel(name: []const u8) bool {
    if (name.len < MIN_CHANNEL_LEN or name.len > MAX_CHANNEL_LEN) return false;
    for (name) |c| {
        if (!isValidChannelChar(c)) return false;
    }
    return true;
}

pub fn looksLikeAppFrame(data: []const u8) bool {
    return data.len >= PREFIX.len and std.mem.eql(u8, data[0..PREFIX.len], PREFIX);
}

pub fn maxPayloadForChannelLen(channel_len: usize) usize {
    if (channel_len < MIN_CHANNEL_LEN or channel_len > MAX_CHANNEL_LEN) return 0;
    return MAX_PLAINTEXT - FRAME_OVERHEAD_WITHOUT_CHANNEL - channel_len;
}

pub fn encodedLen(channel: []const u8, payload: []const u8) usize {
    return PREFIX.len + channel.len + 1 + payload.len;
}

pub fn parse(data: []const u8) ParseError!Frame {
    if (!looksLikeAppFrame(data)) return error.Malformed;
    if (data.len > MAX_PLAINTEXT) return error.Oversize;

    const rest = data[PREFIX.len..];
    const space = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.Malformed;
    const channel = rest[0..space];
    const payload = rest[space + 1 ..];
    if (!isValidChannel(channel)) return error.InvalidChannel;
    return .{ .channel = channel, .payload = payload };
}

pub fn encode(channel: []const u8, payload: []const u8, out: []u8) EncodeError![]u8 {
    if (!isValidChannel(channel)) return error.InvalidChannel;
    const need = encodedLen(channel, payload);
    if (need > MAX_PLAINTEXT or out.len < need) return error.Oversize;

    var i: usize = 0;
    @memcpy(out[i..][0..PREFIX.len], PREFIX);
    i += PREFIX.len;
    @memcpy(out[i..][0..channel.len], channel);
    i += channel.len;
    out[i] = ' ';
    i += 1;
    if (payload.len > 0) {
        @memcpy(out[i..][0..payload.len], payload);
        i += payload.len;
    }
    return out[0..i];
}

test "MAX_APP_PAYLOAD accounts for worst-case framing" {
    try std.testing.expectEqual(@as(usize, 7), PREFIX.len);
    try std.testing.expectEqual(@as(usize, 952), MAX_APP_PAYLOAD);
    try std.testing.expectEqual(@as(usize, 1024 - 7 - 64 - 1), MAX_APP_PAYLOAD);
    try std.testing.expectEqual(@as(usize, 1004), maxPayloadForChannelLen(MESHROOMS_CHANNEL.len));
}

test "channel validation accepts meshrooms-v1 and rejects illegal names" {
    try std.testing.expect(isValidChannel(MESHROOMS_CHANNEL));
    try std.testing.expect(isValidChannel("a"));
    try std.testing.expect(isValidChannel("chan_1.foo-bar"));
    try std.testing.expect(!isValidChannel(""));
    try std.testing.expect(!isValidChannel("Bad"));
    try std.testing.expect(!isValidChannel("has space"));
    try std.testing.expect(!isValidChannel("slash/no"));
    try std.testing.expect(!isValidChannel("A"));
    try std.testing.expect(!isValidChannel(&[_]u8{'a'} ** 65));
    try std.testing.expect(isValidChannel(&[_]u8{'a'} ** 64));
}

test "encode/decode round-trip" {
    var buf: [MAX_PLAINTEXT]u8 = undefined;
    const framed = try encode(MESHROOMS_CHANNEL, "hello rooms", &buf);
    try std.testing.expectEqualStrings("MGAPP1 meshrooms-v1 hello rooms", framed);

    const parsed = try parse(framed);
    try std.testing.expectEqualStrings(MESHROOMS_CHANNEL, parsed.channel);
    try std.testing.expectEqualStrings("hello rooms", parsed.payload);
}

test "parse rejects malformed and oversize frames without truncating" {
    try std.testing.expectError(error.Malformed, parse("hello"));
    try std.testing.expectError(error.Malformed, parse("MGAPP1"));
    try std.testing.expectError(error.Malformed, parse("MGAPP1 "));
    try std.testing.expectError(error.Malformed, parse("MGAPP1 meshrooms-v1"));
    try std.testing.expectError(error.InvalidChannel, parse("MGAPP1 BAD payload"));
    try std.testing.expectError(error.InvalidChannel, parse("MGAPP1  payload"));

    var oversize: [MAX_PLAINTEXT + 8]u8 = undefined;
    const prefix = "MGAPP1 meshrooms-v1 ";
    @memcpy(oversize[0..prefix.len], prefix);
    @memset(oversize[prefix.len..], 'x');
    try std.testing.expectError(error.Oversize, parse(&oversize));
}

test "encode rejects oversize payloads instead of truncating" {
    var buf: [MAX_PLAINTEXT]u8 = undefined;
    const max_for_room = maxPayloadForChannelLen(MESHROOMS_CHANNEL.len);
    const ok_payload = [_]u8{'x'} ** 1004;
    try std.testing.expectEqual(max_for_room, ok_payload.len);
    _ = try encode(MESHROOMS_CHANNEL, &ok_payload, &buf);

    const too_big = [_]u8{'x'} ** 1005;
    try std.testing.expectError(error.Oversize, encode(MESHROOMS_CHANNEL, &too_big, &buf));
}

test "unframed plaintext is not an app frame" {
    try std.testing.expect(!looksLikeAppFrame("hello meshguard"));
    try std.testing.expect(!looksLikeAppFrame("MGAPP1"));
    try std.testing.expect(!looksLikeAppFrame("MGAPP2 meshrooms-v1 x"));
    try std.testing.expect(looksLikeAppFrame("MGAPP1 meshrooms-v1 x"));
}
