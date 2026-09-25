//! Bounded application transfers inside decrypted 0x50 plaintext.
//!
//! Application messages (MGAPP1) are single datagrams of at most 952 bytes.
//! Files, logs, and screenshots need more: this module frames a verified bulk
//! transfer as a sequence of datagrams that reuse the same authenticated 0x50
//! envelope, so they follow the same direct, hole-punched, and relayed paths.
//!
//! Binary frame layout (all integers little-endian):
//!
//!     "MGXF1" kind:u8 id:[16]u8 body...
//!
//!   OFFER   created_unix:i64 size:u64 chunk_size:u16 sha256:[32]u8
//!           channel_len:u8 channel meta_len:u16 meta
//!   DATA    index:u32 bytes (chunk_size bytes, the last chunk may be shorter)
//!   ACK     cumulative:u32 bitmap_len:u8 bitmap
//!           (chunks < cumulative are held; bit i of the bitmap is chunk
//!            cumulative + i, so bit 0 is always clear)
//!   DONE    status:u8   (the receiver verified and holds the complete bytes,
//!                        or the reason it will not)
//!   CANCEL  reason:u8
//!
//! "MGXF1" is a reserved 0x50 plaintext prefix, like "MGAPP1 ".

const std = @import("std");
const app_channel = @import("app_channel.zig");

pub const MAGIC = "MGXF1";
pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = MAGIC.len + 1 + 16;
/// 0x50 plaintext ceiling shared with application messages.
pub const MAX_FRAME: usize = app_channel.MAX_PLAINTEXT;
/// Data bytes per DATA frame. Leaves headroom under MAX_FRAME for the header and index.
pub const CHUNK_SIZE: u16 = 960;
/// Offer frames carry ~140 bytes of fields; 768 bytes of metadata keeps them under MAX_FRAME.
pub const MAX_META: usize = 768;
/// Selective acknowledgement covers this many chunks past the cumulative point.
pub const ACK_BITMAP_BYTES: usize = 64;
pub const ACK_WINDOW: u32 = ACK_BITMAP_BYTES * 8;

pub const Kind = enum(u8) { offer = 1, data = 2, ack = 3, done = 4, cancel = 5 };

pub const DoneStatus = enum(u8) {
    verified = 0,
    hash_mismatch = 1,
    rejected = 2,
};

pub const Reason = enum(u8) {
    unknown_transfer = 1,
    no_listener = 2,
    too_large = 3,
    busy = 4,
    expired = 5,
    cancelled = 6,
    invalid = 7,
    _,

    pub fn text(self: Reason) []const u8 {
        return switch (self) {
            .unknown_transfer => "unknown transfer",
            .no_listener => "no receiver is listening on this channel",
            .too_large => "transfer exceeds the receiver limit",
            .busy => "receiver has no transfer capacity",
            .expired => "transfer offer expired",
            .cancelled => "cancelled",
            .invalid => "invalid transfer",
            _ => "rejected",
        };
    }
};

pub const Offer = struct {
    created_unix: i64,
    size: u64,
    chunk_size: u16,
    sha256: [32]u8,
    channel: []const u8,
    meta: []const u8,
};

pub const Ack = struct {
    cumulative: u32,
    bitmap: []const u8,

    pub fn has(self: Ack, index: u32) bool {
        if (index < self.cumulative) return true;
        const offset = index - self.cumulative;
        if (offset >= self.bitmap.len * 8) return false;
        return (self.bitmap[offset / 8] >> @intCast(offset % 8)) & 1 == 1;
    }
};

pub const Body = union(Kind) {
    offer: Offer,
    data: struct { index: u32, bytes: []const u8 },
    ack: Ack,
    done: DoneStatus,
    cancel: Reason,
};

pub const Frame = struct {
    id: [16]u8,
    body: Body,
};

pub const Error = error{ Malformed, InvalidChannel, Oversize };

pub fn looksLikeTransferFrame(data: []const u8) bool {
    return data.len >= MAGIC.len and std.mem.eql(u8, data[0..MAGIC.len], MAGIC);
}

pub fn chunkCount(size: u64, chunk_size: u16) u32 {
    if (size == 0 or chunk_size == 0) return 0;
    return @intCast((size + chunk_size - 1) / chunk_size);
}

fn readInt(comptime T: type, data: []const u8, pos: *usize) Error!T {
    const n = @sizeOf(T);
    if (pos.* + n > data.len) return error.Malformed;
    const value = std.mem.readInt(T, data[pos.*..][0..n], .little);
    pos.* += n;
    return value;
}

fn take(data: []const u8, pos: *usize, n: usize) Error![]const u8 {
    if (pos.* + n > data.len) return error.Malformed;
    const out = data[pos.*..][0..n];
    pos.* += n;
    return out;
}

pub fn parse(data: []const u8) Error!Frame {
    if (!looksLikeTransferFrame(data)) return error.Malformed;
    if (data.len > MAX_FRAME) return error.Oversize;
    if (data.len < HEADER_LEN) return error.Malformed;
    const kind = std.enums.fromInt(Kind, data[MAGIC.len]) orelse return error.Malformed;
    var id: [16]u8 = undefined;
    @memcpy(&id, data[MAGIC.len + 1 ..][0..16]);
    var pos: usize = HEADER_LEN;
    const body: Body = switch (kind) {
        .offer => blk: {
            const created_unix = try readInt(i64, data, &pos);
            const size = try readInt(u64, data, &pos);
            const chunk_size = try readInt(u16, data, &pos);
            const hash = try take(data, &pos, 32);
            const channel_len = try readInt(u8, data, &pos);
            const channel = try take(data, &pos, channel_len);
            const meta_len = try readInt(u16, data, &pos);
            if (meta_len > MAX_META) return error.Oversize;
            const meta = try take(data, &pos, meta_len);
            if (!app_channel.isValidChannel(channel)) return error.InvalidChannel;
            if (size == 0 or chunk_size == 0 or chunk_size > CHUNK_SIZE) return error.Malformed;
            var sha: [32]u8 = undefined;
            @memcpy(&sha, hash);
            break :blk .{ .offer = .{ .created_unix = created_unix, .size = size, .chunk_size = chunk_size, .sha256 = sha, .channel = channel, .meta = meta } };
        },
        .data => blk: {
            const index = try readInt(u32, data, &pos);
            const bytes = data[pos..];
            if (bytes.len == 0 or bytes.len > CHUNK_SIZE) return error.Malformed;
            pos = data.len;
            break :blk .{ .data = .{ .index = index, .bytes = bytes } };
        },
        .ack => blk: {
            const cumulative = try readInt(u32, data, &pos);
            const len = try readInt(u8, data, &pos);
            if (len > ACK_BITMAP_BYTES) return error.Oversize;
            break :blk .{ .ack = .{ .cumulative = cumulative, .bitmap = try take(data, &pos, len) } };
        },
        .done => .{ .done = std.enums.fromInt(DoneStatus, try readInt(u8, data, &pos)) orelse return error.Malformed },
        .cancel => .{ .cancel = @enumFromInt(try readInt(u8, data, &pos)) },
    };
    if (pos != data.len) return error.Malformed;
    return .{ .id = id, .body = body };
}

fn header(out: []u8, kind: Kind, id: [16]u8) Error!usize {
    if (out.len < HEADER_LEN) return error.Oversize;
    @memcpy(out[0..MAGIC.len], MAGIC);
    out[MAGIC.len] = @intFromEnum(kind);
    @memcpy(out[MAGIC.len + 1 ..][0..16], &id);
    return HEADER_LEN;
}

fn put(comptime T: type, out: []u8, pos: *usize, value: T) Error!void {
    const n = @sizeOf(T);
    if (pos.* + n > out.len) return error.Oversize;
    std.mem.writeInt(T, out[pos.*..][0..n], value, .little);
    pos.* += n;
}

fn putBytes(out: []u8, pos: *usize, bytes: []const u8) Error!void {
    if (pos.* + bytes.len > out.len) return error.Oversize;
    @memcpy(out[pos.*..][0..bytes.len], bytes);
    pos.* += bytes.len;
}

pub fn encodeOffer(out: []u8, id: [16]u8, offer: Offer) Error![]u8 {
    if (!app_channel.isValidChannel(offer.channel)) return error.InvalidChannel;
    if (offer.meta.len > MAX_META) return error.Oversize;
    var pos = try header(out, .offer, id);
    try put(i64, out, &pos, offer.created_unix);
    try put(u64, out, &pos, offer.size);
    try put(u16, out, &pos, offer.chunk_size);
    try putBytes(out, &pos, &offer.sha256);
    try put(u8, out, &pos, @intCast(offer.channel.len));
    try putBytes(out, &pos, offer.channel);
    try put(u16, out, &pos, @intCast(offer.meta.len));
    try putBytes(out, &pos, offer.meta);
    return out[0..pos];
}

pub fn encodeData(out: []u8, id: [16]u8, index: u32, bytes: []const u8) Error![]u8 {
    if (bytes.len == 0 or bytes.len > CHUNK_SIZE) return error.Oversize;
    var pos = try header(out, .data, id);
    try put(u32, out, &pos, index);
    try putBytes(out, &pos, bytes);
    return out[0..pos];
}

pub fn encodeAck(out: []u8, id: [16]u8, cumulative: u32, bitmap: []const u8) Error![]u8 {
    if (bitmap.len > ACK_BITMAP_BYTES) return error.Oversize;
    var pos = try header(out, .ack, id);
    try put(u32, out, &pos, cumulative);
    try put(u8, out, &pos, @intCast(bitmap.len));
    try putBytes(out, &pos, bitmap);
    return out[0..pos];
}

pub fn encodeDone(out: []u8, id: [16]u8, status: DoneStatus) Error![]u8 {
    var pos = try header(out, .done, id);
    try put(u8, out, &pos, @intFromEnum(status));
    return out[0..pos];
}

pub fn encodeCancel(out: []u8, id: [16]u8, reason: Reason) Error![]u8 {
    var pos = try header(out, .cancel, id);
    try put(u8, out, &pos, @intFromEnum(reason));
    return out[0..pos];
}

test "a full DATA frame fits the shared 0x50 plaintext budget" {
    var buf: [MAX_FRAME]u8 = undefined;
    const bytes = [_]u8{0xab} ** CHUNK_SIZE;
    const frame = try encodeData(&buf, @splat(7), 42, &bytes);
    try std.testing.expect(frame.len <= MAX_FRAME);
    const parsed = try parse(frame);
    try std.testing.expectEqual(@as(u32, 42), parsed.body.data.index);
    try std.testing.expectEqualSlices(u8, &bytes, parsed.body.data.bytes);
}

test "offer round-trips and validates its channel and sizes" {
    var buf: [MAX_FRAME]u8 = undefined;
    const offer: Offer = .{ .created_unix = 1_790_000_000, .size = 10 * 1024 * 1024, .chunk_size = CHUNK_SIZE, .sha256 = @splat(3), .channel = "meshrooms-files", .meta = "{\"name\":\"bug.png\"}" };
    const parsed = try parse(try encodeOffer(&buf, @splat(1), offer));
    try std.testing.expectEqual(offer.size, parsed.body.offer.size);
    try std.testing.expectEqualStrings(offer.channel, parsed.body.offer.channel);
    try std.testing.expectEqualStrings(offer.meta, parsed.body.offer.meta);
    try std.testing.expectEqual(offer.sha256, parsed.body.offer.sha256);
    try std.testing.expectError(error.InvalidChannel, encodeOffer(&buf, @splat(1), .{ .created_unix = 0, .size = 1, .chunk_size = 1, .sha256 = @splat(0), .channel = "Bad", .meta = "" }));
    var zero = offer;
    zero.size = 0;
    try std.testing.expectError(error.Malformed, parse(try encodeOffer(&buf, @splat(1), zero)));
}

test "ack bitmap marks selective receipt past the cumulative point" {
    var buf: [MAX_FRAME]u8 = undefined;
    const bitmap = [_]u8{ 0b0000_0110, 0b1000_0000 };
    const ack = (try parse(try encodeAck(&buf, @splat(2), 10, &bitmap))).body.ack;
    try std.testing.expect(ack.has(9));
    try std.testing.expect(!ack.has(10));
    try std.testing.expect(ack.has(11) and ack.has(12));
    try std.testing.expect(!ack.has(13));
    try std.testing.expect(ack.has(25));
    try std.testing.expect(!ack.has(10 + 16));
}

test "malformed, truncated, and trailing frames are rejected" {
    var buf: [MAX_FRAME]u8 = undefined;
    try std.testing.expectError(error.Malformed, parse("MGXF1"));
    try std.testing.expectError(error.Malformed, parse("MGAPP1 meshrooms-v1 hi"));
    const done = try encodeDone(&buf, @splat(9), .verified);
    try std.testing.expectError(error.Malformed, parse(done[0 .. done.len - 1]));
    var longer: [HEADER_LEN + 2]u8 = undefined;
    @memcpy(longer[0..done.len], done);
    longer[done.len] = 0;
    try std.testing.expectError(error.Malformed, parse(&longer));
    buf[0..MAGIC.len].* = MAGIC.*;
    buf[MAGIC.len] = 99;
    try std.testing.expectError(error.Malformed, parse(buf[0..HEADER_LEN]));
    try std.testing.expect(!looksLikeTransferFrame("hello"));
}

test "chunk counts round up" {
    try std.testing.expectEqual(@as(u32, 0), chunkCount(0, CHUNK_SIZE));
    try std.testing.expectEqual(@as(u32, 1), chunkCount(1, CHUNK_SIZE));
    try std.testing.expectEqual(@as(u32, 1), chunkCount(CHUNK_SIZE, CHUNK_SIZE));
    try std.testing.expectEqual(@as(u32, 2), chunkCount(CHUNK_SIZE + 1, CHUNK_SIZE));
}

test "an offer with maximum metadata and channel still fits one frame" {
    var buf: [MAX_FRAME]u8 = undefined;
    const meta = [_]u8{'m'} ** MAX_META;
    const channel = [_]u8{'c'} ** app_channel.MAX_CHANNEL_LEN;
    const frame = try encodeOffer(&buf, @splat(1), .{ .created_unix = 1, .size = 1, .chunk_size = CHUNK_SIZE, .sha256 = @splat(0), .channel = &channel, .meta = &meta });
    try std.testing.expect(frame.len <= MAX_FRAME);
    try std.testing.expectEqual(MAX_META, (try parse(frame)).body.offer.meta.len);
}
