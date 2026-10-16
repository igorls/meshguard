//! Browser ABI for the portable core. Host buffers are restricted to scratch.
const std = @import("std");
const packet = @import("app_packet.zig");
const noise = @import("wireguard/noise.zig");
const Slot = struct { identity: packet.Identity = undefined, live: bool = false, generation: u32 = 0, handshake: ?noise.Handshake = null };
var slots: [16]Slot = @splat(Slot{});
var scratch: [8192]u8 align(16) = @splat(0);

// Status: -1 bad handle, -2 bad buffer, -3 size, -4 pool full,
// -5 invalid key/packet, -6 authentication, -7 wrong recipient/sender.
fn buffer(address: u32, length: u32) ?[]u8 {
    const base = @intFromPtr(&scratch);
    const end = @as(u64, address) + length;
    if (address < base or end > base + scratch.len) return null;
    const offset: usize = address - base;
    return scratch[offset..][0..length];
}
fn context(handle: u32) ?*packet.Identity {
    const index = handle & 255;
    if (index == 0 or index > slots.len) return null;
    const slot = &slots[index - 1];
    if (!slot.live or slot.generation != handle >> 8) return null;
    return &slot.identity;
}
fn overlaps(a: u32, alen: u32, b: u32, blen: u32) bool {
    return @as(u64, a) < @as(u64, b) + blen and @as(u64, b) < @as(u64, a) + alen;
}
export fn mg_abi_version() u32 {
    return 1;
}
export fn mg_scratch_ptr() u32 {
    return @intFromPtr(&scratch);
}
export fn mg_scratch_size() u32 {
    return scratch.len;
}
export fn mg_max_payload() u32 {
    return packet.max_payload;
}
export fn mg_identity_create(address: u32, length: u32) i32 {
    if (length != 32) return -3;
    const seed = buffer(address, length) orelse return -2;
    for (&slots, 0..) |*slot, i| {
        if (slot.live or slot.generation >= 0x7fffff) continue;
        slot.identity = packet.Identity.fromSeed(seed[0..32].*) catch return -5;
        slot.generation += 1;
        slot.live = true;
        return @intCast((slot.generation << 8) | (i + 1));
    }
    return -4;
}
export fn mg_identity_destroy(handle: u32) i32 {
    const identity = context(handle) orelse return -1;
    clearHandshake(&slots[(handle & 255) - 1]);
    identity.clear();
    slots[(handle & 255) - 1].live = false;
    std.crypto.secureZero(u8, &scratch);
    return 0;
}

fn clearHandshake(slot: *Slot) void {
    if (slot.handshake) |*handshake| handshake.deinit();
    slot.handshake = null;
}

/// Start the existing WireGuard Noise IK handshake to authenticate a return route.
/// This deliberately does not expose transport keys or implement tunnel data.
export fn mg_noise_initiate(handle: u32, peer_address: u32, ephemeral_address: u32, timestamp_address: u32, sender_index: u32, output_address: u32) i32 {
    const identity = context(handle) orelse return -1;
    const peer = buffer(peer_address, 32) orelse return -2;
    const ephemeral = buffer(ephemeral_address, 32) orelse return -2;
    const timestamp = buffer(timestamp_address, 12) orelse return -2;
    const out = buffer(output_address, @sizeOf(noise.HandshakeInitiation)) orelse return -2;
    if (sender_index == 0) return -5;
    const slot = &slots[(handle & 255) - 1];
    clearHandshake(slot);
    var handshake = noise.Handshake.init(identity.wg_private, identity.wg_public, peer[0..32].*) catch return -5;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&handshake));
    const initiation = handshake.createInitiationWithEntropy(sender_index, ephemeral[0..32].*, timestamp[0..12].*) catch {
        handshake.deinit();
        return -5;
    };
    slot.handshake = handshake;
    @memcpy(out, std.mem.asBytes(&initiation));
    return @sizeOf(noise.HandshakeInitiation);
}

export fn mg_noise_complete(handle: u32, data_address: u32, length: u32) i32 {
    _ = context(handle) orelse return -1;
    const data = buffer(data_address, length) orelse return -2;
    if (length != @sizeOf(noise.HandshakeResponse) or std.mem.readInt(u32, data[0..4], .little) != 2) return -3;
    const slot = &slots[(handle & 255) - 1];
    const handshake = if (slot.handshake) |*value| value else return -5;
    defer clearHandshake(slot);
    var response: noise.HandshakeResponse = undefined;
    @memcpy(std.mem.asBytes(&response), data);
    handshake.consumeResponse(&response) catch return -6;
    return 0;
}
export fn mg_public_key(handle: u32, address: u32) i32 {
    const identity = context(handle) orelse return -1;
    const out = buffer(address, 32) orelse return -2;
    @memcpy(out, &identity.public_key);
    return 0;
}
export fn mg_wg_public_key(handle: u32, address: u32) i32 {
    const identity = context(handle) orelse return -1;
    const out = buffer(address, 32) orelse return -2;
    @memcpy(out, &identity.wg_public);
    return 0;
}
export fn mg_seal(handle: u32, destination_address: u32, wg_address: u32, nonce_address: u32, data_address: u32, length: u32, output_address: u32, capacity: u32) i32 {
    const identity = context(handle) orelse return -1;
    const destination = buffer(destination_address, 32) orelse return -2;
    const wg = buffer(wg_address, 32) orelse return -2;
    const nonce = buffer(nonce_address, 12) orelse return -2;
    const data = buffer(data_address, length) orelse return -2;
    const out = buffer(output_address, capacity) orelse return -2;
    if (length > packet.max_payload or capacity < packet.overhead + length) return -3;
    if (overlaps(data_address, length, output_address, capacity)) return -2;
    const size = packet.seal(identity.public_key, identity.wg_private, destination[0..32].*, wg[0..32].*, nonce[0..12].*, data, out) catch return -5;
    return @intCast(size);
}
export fn mg_open(handle: u32, sender_address: u32, wg_address: u32, data_address: u32, length: u32, output_address: u32, capacity: u32) i32 {
    const identity = context(handle) orelse return -1;
    const sender = buffer(sender_address, 32) orelse return -2;
    const wg = buffer(wg_address, 32) orelse return -2;
    const data = buffer(data_address, length) orelse return -2;
    const out = buffer(output_address, capacity) orelse return -2;
    if (overlaps(data_address, length, output_address, capacity)) return -2;
    if (overlaps(sender_address, 32, output_address, capacity) or overlaps(wg_address, 32, output_address, capacity)) return -2;
    @memset(out, 0);
    if (length < packet.overhead or length > packet.max_packet) return -3;
    if (!std.mem.eql(u8, data[33..65], sender)) return -7;
    const opened = packet.open(identity.public_key, identity.wg_private, wg[0..32].*, data, out) catch |err| return switch (err) {
        error.WrongRecipient => -7,
        error.OutputTooSmall => -3,
        error.AuthenticationFailed => -6,
        else => -5,
    };
    return @intCast(opened.len);
}
export fn mg_sign(handle: u32, data_address: u32, length: u32, output_address: u32) i32 {
    const identity = context(handle) orelse return -1;
    const data = buffer(data_address, length) orelse return -2;
    const out = buffer(output_address, 64) orelse return -2;
    if (overlaps(data_address, length, output_address, 64)) return -2;
    if (length > packet.max_payload) return -3;
    const signature = identity.sign(data) catch return -5;
    @memcpy(out, &signature);
    return 64;
}
export fn mg_verify(public_address: u32, data_address: u32, length: u32, signature_address: u32) i32 {
    const public = buffer(public_address, 32) orelse return -2;
    const data = buffer(data_address, length) orelse return -2;
    const signature = buffer(signature_address, 64) orelse return -2;
    if (length > packet.max_payload) return -3;
    return if (packet.verify(public[0..32].*, data, signature[0..64].*)) 0 else -6;
}
