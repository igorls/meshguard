///! WireGuard transport layer — per-peer tunnel encryption/decryption.
///!
///! Handles Type 4 (Transport Data) packets:
///! - Encrypt outgoing IP packets with the sending key
///! - Decrypt incoming WG packets with the receiving key
///! - Anti-replay sliding window (2048-bit bitmap)
///! - Nonce counter management
///! - Key expiration and rekey scheduling
///!
///! Reference: drivers/net/wireguard/send.c, receive.c
const std = @import("std");
const noise = @import("noise.zig");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const AUTHTAG_LEN: usize = 16;
pub const TRANSPORT_HEADER_LEN: usize = 16; // sizeof(TransportHeader)

// ─── WireGuard protocol limits (from messages.h) ───

pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = std.math.maxInt(u64) - COUNTER_WINDOW_SIZE - 1;
pub const REKEY_AFTER_TIME_NS: i128 = 120 * std.time.ns_per_s; // 120 seconds
pub const REJECT_AFTER_TIME_NS: i128 = 180 * std.time.ns_per_s; // 180 seconds
pub const KEEPALIVE_TIMEOUT_NS: i128 = 10 * std.time.ns_per_s; // 10 seconds

// Anti-replay window
pub const COUNTER_WINDOW_SIZE: u64 = 2048;

/// Per-peer tunnel state.
pub const Tunnel = struct {
    /// Transport keys from completed handshake
    keys: noise.TransportKeys,

    /// Sending nonce counter (monotonically increasing)
    send_counter: u64 = 0,

    /// Anti-replay window for receiving
    replay_window: ReplayWindow = .{},

    /// Last time we sent data (for keepalive scheduling)
    last_send_ns: i128 = 0,
    /// Last time we received data (for keepalive scheduling)
    last_recv_ns: i128 = 0,

    /// Whether this tunnel needs rekeying
    needs_rekey: bool = false,

    /// Encrypt an outgoing IP packet into a WG transport message.
    /// Returns: [header(16) || encrypted_padded_data || tag(16)]
    pub fn encrypt(self: *Tunnel, plaintext: []const u8, out: []u8) !usize {
        if (self.send_counter >= REJECT_AFTER_MESSAGES) return error.KeyExpired;

        const elapsed = std.time.nanoTimestamp() - self.keys.birthdate_ns;
        if (elapsed >= REJECT_AFTER_TIME_NS) return error.KeyExpired;
        if (elapsed >= REKEY_AFTER_TIME_NS or self.send_counter >= REKEY_AFTER_MESSAGES)
            self.needs_rekey = true;

        // Pad plaintext to multiple of 16 bytes (WG spec: prevents traffic analysis)
        const padding_len = (16 - (plaintext.len % 16)) % 16;
        const padded_len = plaintext.len + padding_len;
        const total_len = TRANSPORT_HEADER_LEN + padded_len + AUTHTAG_LEN;
        if (out.len < total_len) return error.BufferTooSmall;

        // Write transport header
        std.mem.writeInt(u32, out[0..4], 4, .little); // Type 4
        std.mem.writeInt(u32, out[4..8], self.keys.receiving_index, .little); // Peer's receiver index
        std.mem.writeInt(u64, out[8..16], self.send_counter, .little); // Counter/nonce

        // Build 12-byte nonce: 4 zero bytes || 8-byte LE counter
        // WG spec: "counter is prepended with four bytes of zeros"
        // Kernel: put_unaligned_le64(nonce, iv + 4)
        var nonce: [12]u8 = .{0} ** 12;
        std.mem.writeInt(u64, nonce[4..12], self.send_counter, .little);

        // Copy plaintext + zero padding into output buffer temporarily
        const ct_start = TRANSPORT_HEADER_LEN;
        @memcpy(out[ct_start..][0..plaintext.len], plaintext);
        if (padding_len > 0) {
            @memset(out[ct_start + plaintext.len ..][0..padding_len], 0);
        }

        // Encrypt in-place: ChaCha20-Poly1305 supports src==dest
        ChaCha20Poly1305.encrypt(
            out[ct_start..][0..padded_len],
            out[ct_start + padded_len ..][0..AUTHTAG_LEN],
            out[ct_start..][0..padded_len],
            &.{}, // No additional data for transport
            nonce,
            self.keys.sending_key,
        );

        self.send_counter += 1;
        self.last_send_ns = std.time.nanoTimestamp();

        return total_len;
    }

    /// Decrypt an incoming WG transport message.
    /// Input: full WG packet including header.
    /// Returns: decrypted plaintext slice length.
    pub fn decrypt(self: *Tunnel, packet: []const u8, out: []u8) !usize {
        if (packet.len < TRANSPORT_HEADER_LEN + AUTHTAG_LEN) return error.PacketTooShort;

        // Parse header
        const msg_type = std.mem.readInt(u32, packet[0..4], .little);
        if (msg_type != 4) return error.InvalidMessageType;

        const counter = std.mem.readInt(u64, packet[8..16], .little);

        // Anti-replay check
        if (!self.replay_window.check(counter)) return error.ReplayedPacket;

        // Check key expiration
        const elapsed = std.time.nanoTimestamp() - self.keys.birthdate_ns;
        if (elapsed >= REJECT_AFTER_TIME_NS) return error.KeyExpired;

        // Build nonce: 4 zero bytes || 8-byte LE counter
        var nonce: [12]u8 = .{0} ** 12;
        std.mem.writeInt(u64, nonce[4..12], counter, .little);

        const ciphertext = packet[TRANSPORT_HEADER_LEN..];
        const plaintext_len = ciphertext.len - AUTHTAG_LEN;
        if (out.len < plaintext_len) return error.BufferTooSmall;

        // Decrypt
        ChaCha20Poly1305.decrypt(
            out[0..plaintext_len],
            ciphertext[0..plaintext_len],
            ciphertext[plaintext_len..][0..AUTHTAG_LEN].*,
            &.{}, // No AD for transport
            nonce,
            self.keys.receiving_key,
        ) catch return error.DecryptionFailed;

        // Update replay window
        self.replay_window.update(counter);
        self.last_recv_ns = std.time.nanoTimestamp();

        // Strip padding: parse IP header to get real packet length
        // Without this, padded bytes written to TUN may be rejected by the kernel
        if (plaintext_len >= 20) {
            const version = out[0] >> 4;
            var real_len: usize = plaintext_len;
            if (version == 4 and plaintext_len >= 20) {
                // IPv4: total length is at bytes 2-3 (big-endian)
                real_len = std.mem.readInt(u16, out[2..4], .big);
            } else if (version == 6 and plaintext_len >= 40) {
                // IPv6: payload length at bytes 4-5 + 40 byte header
                real_len = @as(usize, std.mem.readInt(u16, out[4..6], .big)) + 40;
            }
            return @min(plaintext_len, real_len);
        }

        return plaintext_len;
    }

    /// Check if this tunnel's keys are still valid.
    pub fn isValid(self: *const Tunnel) bool {
        const elapsed = std.time.nanoTimestamp() - self.keys.birthdate_ns;
        return elapsed < REJECT_AFTER_TIME_NS and
            self.send_counter < REJECT_AFTER_MESSAGES;
    }

    /// Check if a keepalive should be sent.
    pub fn needsKeepalive(self: *const Tunnel) bool {
        if (self.last_send_ns == 0) return false;
        const since_send = std.time.nanoTimestamp() - self.last_send_ns;
        return since_send >= KEEPALIVE_TIMEOUT_NS;
    }
};

/// Sliding window anti-replay protection.
/// Reference: noise.h struct noise_replay_counter
pub const ReplayWindow = struct {
    /// Highest counter value seen
    counter: u64 = 0,
    /// Bitmap of seen counters in [counter - WINDOW_SIZE + 1, counter]
    bitmap: [COUNTER_WINDOW_SIZE / 64]u64 = .{0} ** (COUNTER_WINDOW_SIZE / 64),

    /// Check if a counter value is acceptable (not replayed, not too old).
    pub fn check(self: *const ReplayWindow, counter: u64) bool {
        if (counter > self.counter) return true; // New highest — always OK
        if (self.counter - counter >= COUNTER_WINDOW_SIZE) return false; // Too old

        // Check bitmap
        const bit_index = counter % COUNTER_WINDOW_SIZE;
        const word_index = bit_index / 64;
        const bit_offset: u6 = @intCast(bit_index % 64);
        return (self.bitmap[word_index] & (@as(u64, 1) << bit_offset)) == 0;
    }

    /// Update the window after accepting a counter value.
    pub fn update(self: *ReplayWindow, counter: u64) void {
        if (counter > self.counter) {
            // New highest value — shift window
            const diff = counter - self.counter;
            if (diff >= COUNTER_WINDOW_SIZE) {
                // Complete reset
                @memset(&self.bitmap, 0);
            } else {
                // Shift bitmap by diff positions
                self.shiftBitmap(diff);
            }
            self.counter = counter;
        }
        // Set the bit for this counter
        const bit_index = counter % COUNTER_WINDOW_SIZE;
        const word_index = bit_index / 64;
        const bit_offset: u6 = @intCast(bit_index % 64);
        self.bitmap[word_index] |= @as(u64, 1) << bit_offset;
    }

    fn shiftBitmap(self: *ReplayWindow, shift: u64) void {
        // Clear bits that are shifting out of the window
        // For simplicity, when shift is large just zero everything
        if (shift >= COUNTER_WINDOW_SIZE) {
            @memset(&self.bitmap, 0);
            return;
        }
        // For smaller shifts, we clear the bits that correspond to
        // the positions that will be reused
        var i: u64 = 0;
        while (i < shift) : (i += 1) {
            const pos = (self.counter + 1 + i) % COUNTER_WINDOW_SIZE;
            const word = pos / 64;
            const bit: u6 = @intCast(pos % 64);
            self.bitmap[word] &= ~(@as(u64, 1) << bit);
        }
    }
};

// ─── Tests ───

test "transport encrypt/decrypt roundtrip" {
    const keys = noise.TransportKeys{
        .sending_key = .{0x42} ** 32,
        .receiving_key = .{0x99} ** 32,
        .sending_index = 1,
        .receiving_index = 2,
        .is_initiator = true,
        .birthdate_ns = std.time.nanoTimestamp(),
    };

    // Sender has keys as-is, receiver has them swapped
    var sender = Tunnel{ .keys = keys };
    var receiver = Tunnel{
        .keys = .{
            .sending_key = keys.receiving_key,
            .receiving_key = keys.sending_key,
            .sending_index = keys.receiving_index,
            .receiving_index = keys.sending_index,
            .is_initiator = false,
            .birthdate_ns = keys.birthdate_ns,
        },
    };

    const plaintext = "Hello, WireGuard tunnel!";
    var packet_buf: [256]u8 = undefined;
    var decrypt_buf: [256]u8 = undefined;

    // Encrypt
    const packet_len = try sender.encrypt(plaintext, &packet_buf);
    try std.testing.expectEqual(packet_len, TRANSPORT_HEADER_LEN + plaintext.len + AUTHTAG_LEN);

    // Verify header
    try std.testing.expectEqual(std.mem.readInt(u32, packet_buf[0..4], .little), 4); // Type 4

    // Decrypt
    const decrypted_len = try receiver.decrypt(packet_buf[0..packet_len], &decrypt_buf);
    try std.testing.expectEqual(decrypted_len, plaintext.len);
    try std.testing.expectEqualSlices(u8, plaintext, decrypt_buf[0..decrypted_len]);
}

test "anti-replay window" {
    var w = ReplayWindow{};

    // Sequential counters should all be accepted
    try std.testing.expect(w.check(0));
    w.update(0);
    try std.testing.expect(w.check(1));
    w.update(1);
    try std.testing.expect(w.check(2));
    w.update(2);

    // Replay should be rejected
    try std.testing.expect(!w.check(0));
    try std.testing.expect(!w.check(1));
    try std.testing.expect(!w.check(2));

    // Out-of-order within window should work
    try std.testing.expect(w.check(5));
    w.update(5);
    try std.testing.expect(w.check(3)); // Still within window
    w.update(3);
    try std.testing.expect(w.check(4)); // Still within window
    w.update(4);

    // Way ahead should work and invalidate old
    w.update(COUNTER_WINDOW_SIZE + 100);
    try std.testing.expect(!w.check(0)); // Far too old
}

test "transport nonce counter increments" {
    const keys = noise.TransportKeys{
        .sending_key = .{0x42} ** 32,
        .receiving_key = .{0x99} ** 32,
        .sending_index = 1,
        .receiving_index = 2,
        .is_initiator = true,
        .birthdate_ns = std.time.nanoTimestamp(),
    };
    var tunnel = Tunnel{ .keys = keys };
    var buf: [256]u8 = undefined;

    _ = try tunnel.encrypt("test", &buf);
    try std.testing.expectEqual(tunnel.send_counter, 1);
    _ = try tunnel.encrypt("test", &buf);
    try std.testing.expectEqual(tunnel.send_counter, 2);
}
