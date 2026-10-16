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
//!   even with a 64-byte channel. Every channel enforces that same ceiling.
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
pub const EXAMPLE_CHANNEL = "example-v1";
pub const PROTOCOL_VERSION: u8 = 1;

pub const Frame = struct {
    channel: []const u8,
    payload: []const u8,
};

pub const ParseError = error{
    Malformed,
    InvalidChannel,
    InvalidUtf8,
    Oversize,
};

pub const EncodeError = error{
    InvalidChannel,
    EmptyPayload,
    InvalidUtf8,
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
    return MAX_APP_PAYLOAD;
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
    if (payload.len == 0) return error.Malformed;
    if (payload.len > MAX_APP_PAYLOAD) return error.Oversize;
    if (!std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
    return .{ .channel = channel, .payload = payload };
}

pub fn encode(channel: []const u8, payload: []const u8, out: []u8) EncodeError![]u8 {
    if (!isValidChannel(channel)) return error.InvalidChannel;
    if (payload.len == 0) return error.EmptyPayload;
    if (payload.len > MAX_APP_PAYLOAD) return error.Oversize;
    if (!std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
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
    try std.testing.expectEqual(MAX_APP_PAYLOAD, maxPayloadForChannelLen(EXAMPLE_CHANNEL.len));
}

test "channel validation accepts example-v1 and rejects illegal names" {
    try std.testing.expect(isValidChannel(EXAMPLE_CHANNEL));
    try std.testing.expect(isValidChannel("a"));
    try std.testing.expect(isValidChannel("chan_1.foo-bar"));
    try std.testing.expect(!isValidChannel(""));
    try std.testing.expect(!isValidChannel("Bad"));
    try std.testing.expect(!isValidChannel("has space"));
    try std.testing.expect(!isValidChannel("slash/no"));
    try std.testing.expect(!isValidChannel("A"));
    try std.testing.expect(!isValidChannel(&@as([65]u8, @splat('a'))));
    try std.testing.expect(isValidChannel(&@as([64]u8, @splat('a'))));
}

test "encode/decode round-trip" {
    var buf: [MAX_PLAINTEXT]u8 = undefined;
    const framed = try encode(EXAMPLE_CHANNEL, "hello rooms", &buf);
    try std.testing.expectEqualStrings("MGAPP1 example-v1 hello rooms", framed);

    const parsed = try parse(framed);
    try std.testing.expectEqualStrings(EXAMPLE_CHANNEL, parsed.channel);
    try std.testing.expectEqualStrings("hello rooms", parsed.payload);
}

test "parse rejects malformed and oversize frames without truncating" {
    try std.testing.expectError(error.Malformed, parse("hello"));
    try std.testing.expectError(error.Malformed, parse("MGAPP1"));
    try std.testing.expectError(error.Malformed, parse("MGAPP1 "));
    try std.testing.expectError(error.Malformed, parse("MGAPP1 example-v1"));
    try std.testing.expectError(error.InvalidChannel, parse("MGAPP1 BAD payload"));
    try std.testing.expectError(error.InvalidChannel, parse("MGAPP1  payload"));

    var oversize: [MAX_PLAINTEXT + 8]u8 = undefined;
    const prefix = "MGAPP1 example-v1 ";
    @memcpy(oversize[0..prefix.len], prefix);
    @memset(oversize[prefix.len..], 'x');
    try std.testing.expectError(error.Oversize, parse(&oversize));
}

test "encode rejects oversize payloads instead of truncating" {
    var buf: [MAX_PLAINTEXT]u8 = undefined;
    const max_for_room = maxPayloadForChannelLen(EXAMPLE_CHANNEL.len);
    const ok_payload: [MAX_APP_PAYLOAD]u8 = @splat('x');
    try std.testing.expectEqual(max_for_room, ok_payload.len);
    _ = try encode(EXAMPLE_CHANNEL, &ok_payload, &buf);

    const too_big: [MAX_APP_PAYLOAD + 1]u8 = @splat('x');
    try std.testing.expectError(error.Oversize, encode(EXAMPLE_CHANNEL, &too_big, &buf));
}

test "all channel lengths enforce the advertised payload ceiling" {
    var buf: [MAX_PLAINTEXT]u8 = undefined;
    const payload: [MAX_APP_PAYLOAD]u8 = @splat('x');
    for ([_][]const u8{ "a", EXAMPLE_CHANNEL, &@as([MAX_CHANNEL_LEN]u8, @splat('a')) }) |channel| {
        const frame = try encode(channel, &payload, &buf);
        try std.testing.expectEqualStrings(&payload, (try parse(frame)).payload);
        try std.testing.expectError(error.Oversize, encode(channel, &@as([MAX_APP_PAYLOAD + 1]u8, @splat('x')), &buf));
    }
    try std.testing.expectError(error.Oversize, parse("MGAPP1 a " ++ @as([MAX_APP_PAYLOAD + 1]u8, @splat('x'))));
}

test "application payloads must be valid UTF-8" {
    var buf: [MAX_PLAINTEXT]u8 = undefined;
    for ([_][]const u8{ "\xff", "\xc0\xaf", "\xed\xa0\x80", "\xf0\x9f" }) |invalid| {
        try std.testing.expectError(error.InvalidUtf8, encode("a", invalid, &buf));
        const raw = try std.fmt.bufPrint(&buf, "MGAPP1 a {s}", .{invalid});
        try std.testing.expectError(error.InvalidUtf8, parse(raw));
    }
    const valid = comptime blk: {
        var arr: [MAX_APP_PAYLOAD]u8 = undefined;
        var i: usize = 0;
        while (i + 4 <= arr.len) : (i += 4) {
            @memcpy(arr[i .. i + 4], "\xf0\x9f\x9a\x80");
        }
        break :blk arr;
    };
    const frame = try encode("a", &valid, &buf);
    try std.testing.expectEqualStrings(&valid, (try parse(frame)).payload);
}

test "unframed plaintext is not an app frame" {
    try std.testing.expect(!looksLikeAppFrame("hello meshguard"));
    try std.testing.expect(!looksLikeAppFrame("MGAPP1"));
    try std.testing.expect(!looksLikeAppFrame("MGAPP2 example-v1 x"));
    try std.testing.expect(looksLikeAppFrame("MGAPP1 example-v1 x"));
}

test "empty application payloads are rejected on receive" {
    try std.testing.expectError(error.Malformed, parse("MGAPP1 example-v1 "));
    var buf: [MAX_PLAINTEXT]u8 = undefined;
    try std.testing.expectError(error.EmptyPayload, encode(EXAMPLE_CHANNEL, "", &buf));
}
