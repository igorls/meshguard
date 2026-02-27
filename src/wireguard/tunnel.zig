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
const sodium = @import("../crypto/sodium.zig");

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

    /// Sending nonce counter (monotonically increasing, atomic for multi-thread)
    send_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Anti-replay window for receiving (mutex-protected for multi-thread)
    replay_window: ReplayWindow = .{},
    replay_lock: std.Thread.Mutex = .{},

    /// Last time we sent data (for keepalive scheduling)
    last_send_ns: i128 = 0,
    /// Last time we received data (for keepalive scheduling)
    last_recv_ns: i128 = 0,

    /// Whether this tunnel needs rekeying
    needs_rekey: bool = false,

    /// Securely zero out key material.
    pub fn deinit(self: *Tunnel) void {
        std.crypto.secureZero(u8, &self.keys.sending_key);
        std.crypto.secureZero(u8, &self.keys.receiving_key);
    }

    /// Encrypt an outgoing IP packet into a WG transport message.
    /// Returns: [header(16) || encrypted_padded_data || tag(16)]
    pub fn encrypt(self: *Tunnel, plaintext: []const u8, out: []u8) !usize {
        // Atomically fetch-add the counter for thread safety
        const counter = self.send_counter.fetchAdd(1, .monotonic);

        if (counter >= REJECT_AFTER_MESSAGES) return error.KeyExpired;

        const elapsed = std.time.nanoTimestamp() - self.keys.birthdate_ns;
        if (elapsed >= REJECT_AFTER_TIME_NS) return error.KeyExpired;
        if (elapsed >= REKEY_AFTER_TIME_NS or counter >= REKEY_AFTER_MESSAGES)
            self.needs_rekey = true;

        // Pad plaintext to multiple of 16 bytes (WG spec: prevents traffic analysis)
        const padding_len = (16 - (plaintext.len % 16)) % 16;
        const padded_len = plaintext.len + padding_len;
        const total_len = TRANSPORT_HEADER_LEN + padded_len + AUTHTAG_LEN;
        if (out.len < total_len) return error.BufferTooSmall;

        // Write transport header
        std.mem.writeInt(u32, out[0..4], 4, .little); // Type 4
        std.mem.writeInt(u32, out[4..8], self.keys.receiving_index, .little);
        std.mem.writeInt(u64, out[8..16], counter, .little);

        // Build 12-byte nonce: 4 zero bytes || 8-byte LE counter
        var nonce: [12]u8 = .{0} ** 12;
        std.mem.writeInt(u64, nonce[4..12], counter, .little);

        // Copy plaintext + zero padding into output buffer temporarily
        const ct_start = TRANSPORT_HEADER_LEN;
        @memcpy(out[ct_start..][0..plaintext.len], plaintext);
        if (padding_len > 0) {
            @memset(out[ct_start + plaintext.len ..][0..padding_len], 0);
        }

        // Encrypt in-place: libsodium ChaCha20-Poly1305 AVX2 assembly
        sodium.encrypt(
            out[ct_start..][0..padded_len],
            out[ct_start + padded_len ..][0..AUTHTAG_LEN],
            out[ct_start..][0..padded_len],
            &.{}, // No additional data for transport
            nonce,
            self.keys.sending_key,
        );

        self.last_send_ns = std.time.nanoTimestamp();

        return total_len;
    }

    /// Encrypt in-place with a pre-assigned nonce (for parallel pipeline).
    ///
    /// The caller (TUN reader) places the IP payload at buf[16..16+plaintext_len]
    /// and assigns nonces via fetchAdd(batch_count). The crypto worker then calls
    /// this to encrypt in-place and write the WG transport header at buf[0..16].
    ///
    /// Returns total length: header(16) + padded_ciphertext + tag(16).
    pub fn encryptPreassigned(self: *Tunnel, buf: []u8, plaintext_len: usize, nonce_val: u64) ?usize {
        if (nonce_val >= REJECT_AFTER_MESSAGES) return null;

        const elapsed = std.time.nanoTimestamp() - self.keys.birthdate_ns;
        if (elapsed >= REJECT_AFTER_TIME_NS) return null;
        if (elapsed >= REKEY_AFTER_TIME_NS or nonce_val >= REKEY_AFTER_MESSAGES)
            self.needs_rekey = true;

        // Pad plaintext to multiple of 16 bytes
        const padding_len = (16 - (plaintext_len % 16)) % 16;
        const padded_len = plaintext_len + padding_len;
        const total_len = TRANSPORT_HEADER_LEN + padded_len + AUTHTAG_LEN;
        if (buf.len < total_len) return null;

        // Write transport header at buf[0..16]
        std.mem.writeInt(u32, buf[0..4], 4, .little); // Type 4
        std.mem.writeInt(u32, buf[4..8], self.keys.receiving_index, .little);
        std.mem.writeInt(u64, buf[8..16], nonce_val, .little);

        // Zero-pad after plaintext
        if (padding_len > 0) {
            @memset(buf[TRANSPORT_HEADER_LEN + plaintext_len ..][0..padding_len], 0);
        }

        // Build 12-byte nonce
        var nonce: [12]u8 = .{0} ** 12;
        std.mem.writeInt(u64, nonce[4..12], nonce_val, .little);

        // Encrypt in-place (plaintext at buf[16..], ciphertext overwrites same region)
        sodium.encrypt(
            buf[TRANSPORT_HEADER_LEN..][0..padded_len],
            buf[TRANSPORT_HEADER_LEN + padded_len ..][0..AUTHTAG_LEN],
            buf[TRANSPORT_HEADER_LEN..][0..padded_len],
            &.{},
            nonce,
            self.keys.sending_key,
        );

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

        // Anti-replay check (mutex-protected for multi-thread)
        {
            self.replay_lock.lock();
            defer self.replay_lock.unlock();
            if (!self.replay_window.check(counter)) return error.ReplayedPacket;
        }

        // Check key expiration
        const elapsed = std.time.nanoTimestamp() - self.keys.birthdate_ns;
        if (elapsed >= REJECT_AFTER_TIME_NS) return error.KeyExpired;

        // Build nonce: 4 zero bytes || 8-byte LE counter
        var nonce: [12]u8 = .{0} ** 12;
        std.mem.writeInt(u64, nonce[4..12], counter, .little);

        const ciphertext = packet[TRANSPORT_HEADER_LEN..];
        const plaintext_len = ciphertext.len - AUTHTAG_LEN;
        if (out.len < plaintext_len) return error.BufferTooSmall;

        // Decrypt (libsodium AVX2 assembly)
        sodium.decrypt(
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

        // Optimization: For small shifts (common case), use simple loop (fast setup).
        // For large shifts (packet loss), use word-level clearing (avoid O(shift) loop).
        if (shift <= 64) {
            var i: u64 = 0;
            while (i < shift) : (i += 1) {
                const pos = (self.counter + 1 + i) % COUNTER_WINDOW_SIZE;
                const word = pos / 64;
                const bit: u6 = @intCast(pos % 64);
                self.bitmap[word] &= ~(@as(u64, 1) << bit);
            }
            return;
        }

        // Large shift: clear words efficiently
        var current = (self.counter + 1) % COUNTER_WINDOW_SIZE;
        var remaining = shift;

        while (remaining > 0) {
            const word_idx = current / 64;
            const bit_idx = current % 64;
            const bits_in_word = 64 - bit_idx;
            const to_clear = @min(remaining, bits_in_word);

            if (to_clear == 64) {
                // Clear entire word
                self.bitmap[word_idx] = 0;
            } else {
                // Clear range of bits: [bit_idx, bit_idx + to_clear)
                const mask = (@as(u64, 1) << @intCast(to_clear)) - 1;
                self.bitmap[word_idx] &= ~(mask << @intCast(bit_idx));
            }

            remaining -= to_clear;
            current = (current + to_clear) % COUNTER_WINDOW_SIZE;
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
    // Plaintext len is 24 ("Hello, WireGuard tunnel!"). Padded to 32.
    const padded_len = std.mem.alignForward(usize, plaintext.len, 16);
    try std.testing.expectEqual(packet_len, TRANSPORT_HEADER_LEN + padded_len + AUTHTAG_LEN);

    // Verify header
    try std.testing.expectEqual(std.mem.readInt(u32, packet_buf[0..4], .little), 4); // Type 4

    // Decrypt
    const decrypted_len = try receiver.decrypt(packet_buf[0..packet_len], &decrypt_buf);
    // Since plaintext is not a valid IP packet, decrypt() cannot determine true length from header.
    // It returns the full padded length.
    try std.testing.expectEqual(decrypted_len, padded_len);
    try std.testing.expectEqualSlices(u8, plaintext, decrypt_buf[0..plaintext.len]);
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
    try std.testing.expectEqual(tunnel.send_counter.load(.monotonic), 1);
    _ = try tunnel.encrypt("test", &buf);
    try std.testing.expectEqual(tunnel.send_counter.load(.monotonic), 2);
}

test "anti-replay window large shift" {
    var w = ReplayWindow{};

    // Fill window with some values
    // Window size 2048.
    // Set 0, 100, 200.
    w.update(0);
    w.update(100);
    w.update(200);
    try std.testing.expect(!w.check(0));
    try std.testing.expect(!w.check(100));
    try std.testing.expect(!w.check(200));

    // Shift by 1000 (large shift, triggers optimized path)
    // New max = 1200. Shift = 1000.
    // Range cleared: 201 ... 1200.
    // 0, 100, 200 remain (since they are < 201).
    w.update(1200);
    try std.testing.expect(!w.check(0)); // still in window, still seen
    try std.testing.expect(!w.check(100)); // still in window, still seen
    try std.testing.expect(!w.check(200)); // still in window, still seen
    try std.testing.expect(!w.check(1200)); // new max, seen

    // Shift by another 1000. New max = 2200.
    // Clears 1201...2200.
    // 0 is now outside window (2200 - 2048 = 152).
    // 100 is outside window.
    // 200 is inside window (200 >= 153).
    w.update(2200);

    // Check old values (check returns false if too old)
    try std.testing.expect(!w.check(0));
    try std.testing.expect(!w.check(100));

    // 200 should still be marked as seen?
    // Wait, 200 was set. It wasn't cleared by 1200 update.
    // And it wasn't cleared by 2200 update (cleared 1201..2200).
    // So 200 bit is still set.
    // check(200) -> false (seen).
    try std.testing.expect(!w.check(200));

    // Verify a value that was cleared is acceptable
    // 1500 was in the cleared range of the first large shift?
    // First shift: cleared 201..1200.
    // Second shift: cleared 1201..2200.
    // So 1500 was cleared in second shift.
    // It is within window [2200-2048+1, 2200] = [153, 2200].
    // So 1500 is valid range. And bit should be 0.
    try std.testing.expect(w.check(1500));
}

test "transport tunnel deinit zeros keys" {
    const keys = noise.TransportKeys{
        .sending_key = .{0x42} ** 32,
        .receiving_key = .{0x99} ** 32,
        .sending_index = 1,
        .receiving_index = 2,
        .is_initiator = true,
        .birthdate_ns = std.time.nanoTimestamp(),
    };
    var t = Tunnel{ .keys = keys };

    // Verify keys are set
    try std.testing.expectEqual(t.keys.sending_key[0], 0x42);
    try std.testing.expectEqual(t.keys.receiving_key[0], 0x99);

    // Deinit
    t.deinit();

    // Verify keys are zeroed
    var all_zeros = true;
    for (t.keys.sending_key) |b| {
        if (b != 0) all_zeros = false;
    }
    try std.testing.expect(all_zeros);

    all_zeros = true;
    for (t.keys.receiving_key) |b| {
        if (b != 0) all_zeros = false;
    }
    try std.testing.expect(all_zeros);
}
