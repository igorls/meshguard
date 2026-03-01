///! WireGuard Noise IK handshake implementation.
///!
///! Implements the Noise_IKpsk2 handshake pattern:
///!   <- s
///!   -> e, es, s, ss, {t}     (Handshake Initiation, Type 1, 148 bytes)
///!   <- e, ee, se, psk, {}    (Handshake Response, Type 2, 92 bytes)
///!
///! Reference: drivers/net/wireguard/noise.c
const std = @import("std");
const crypto = @import("crypto.zig");
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2s128 = std.crypto.hash.blake2.Blake2s128;
const X25519 = std.crypto.dh.X25519;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

// ─── Constants ───

pub const PUBLIC_KEY_LEN: usize = 32;
pub const TIMESTAMP_LEN: usize = 12; // TAI64N: 8 (seconds) + 4 (nanoseconds)
pub const AUTHTAG_LEN: usize = 16; // Poly1305 tag
pub const COOKIE_LEN: usize = 16;
pub const AEAD_LEN = AUTHTAG_LEN; // Encrypted empty payload = just the tag

/// WireGuard protocol construction string
const CONSTRUCTION: []const u8 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// WireGuard protocol identifier
const IDENTIFIER: []const u8 = "WireGuard v1 zx2c4 Jason@zx2c4.com";

// ─── Wire format (matching kernel messages.h exactly) ───

pub const MessageType = enum(u8) {
    invalid = 0,
    handshake_initiation = 1,
    handshake_response = 2,
    handshake_cookie = 3,
    transport_data = 4,
};

/// Handshake Initiation message (Type 1, 148 bytes total)
pub const HandshakeInitiation = extern struct {
    message_type: u32 align(1), // LE32, type=1 in first byte
    sender_index: u32 align(1), // LE32
    ephemeral: [PUBLIC_KEY_LEN]u8, // Unencrypted ephemeral public key
    encrypted_static: [PUBLIC_KEY_LEN + AUTHTAG_LEN]u8, // AEAD(static pubkey)
    encrypted_timestamp: [TIMESTAMP_LEN + AUTHTAG_LEN]u8, // AEAD(TAI64N timestamp)
    mac1: [COOKIE_LEN]u8,
    mac2: [COOKIE_LEN]u8,
};

/// Handshake Response message (Type 2, 92 bytes total)
pub const HandshakeResponse = extern struct {
    message_type: u32 align(1), // LE32, type=2
    sender_index: u32 align(1), // LE32
    receiver_index: u32 align(1), // LE32
    ephemeral: [PUBLIC_KEY_LEN]u8, // Unencrypted ephemeral public key
    encrypted_nothing: [AEAD_LEN]u8, // AEAD(empty)
    mac1: [COOKIE_LEN]u8,
    mac2: [COOKIE_LEN]u8,
};

/// Transport Data message header (Type 4)
pub const TransportHeader = extern struct {
    message_type: u32 align(1), // LE32, type=4
    receiver_index: u32 align(1), // LE32
    counter: u64 align(1), // LE64, nonce counter
    // followed by encrypted_data[]
};

// ─── Handshake state ───

pub const HandshakeState = enum {
    zeroed,
    created_initiation,
    consumed_initiation,
    created_response,
    consumed_response,
};

/// Per-peer transport keypair derived from a successful handshake.
pub const TransportKeys = struct {
    sending_key: [32]u8,
    receiving_key: [32]u8,
    sending_index: u32, // Our sender_index (for outgoing packets)
    receiving_index: u32, // Peer's sender_index (their receiver_index)
    is_initiator: bool,
    birthdate_ns: i128,
};

/// Noise IK handshake state.
pub const Handshake = struct {
    state: HandshakeState = .zeroed,

    // Our identity
    static_private: [32]u8,
    static_public: [32]u8,

    // Peer's identity
    remote_static: [32]u8,

    // Precomputed DH(static, remote_static) for performance
    precomputed_ss: [32]u8,

    // Pre-shared key (optional, all zeros if not used)
    preshared_key: [32]u8 = std.mem.zeroes([32]u8),

    // Handshake-in-progress state
    ephemeral_private: [32]u8 = undefined,
    remote_ephemeral: [32]u8 = undefined,
    hash: [32]u8 = undefined,
    chaining_key: [32]u8 = undefined,

    // Session indices
    sender_index: u32 = 0,
    remote_index: u32 = 0,

    // Anti-replay: latest timestamp from this peer
    latest_timestamp: [TIMESTAMP_LEN]u8 = std.mem.zeroes([TIMESTAMP_LEN]u8),

    /// Initialize a handshake with our identity and the peer's public key.
    pub fn init(
        static_private: [32]u8,
        static_public: [32]u8,
        remote_static: [32]u8,
    ) !Handshake {
        // Precompute DH(our_static, their_static)
        // Abort if the remote public key is a weak/low-order point (subgroup confinement)
        const precomputed = X25519.scalarmult(static_private, remote_static) catch
            return error.WeakPublicKey;

        // Check for all-zero result (indicates weak key)
        var all_zero = true;
        for (precomputed) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) return error.WeakPublicKey;

        return .{
            .static_private = static_private,
            .static_public = static_public,
            .remote_static = remote_static,
            .precomputed_ss = precomputed,
        };
    }

    /// Securely zero out all sensitive key material.
    pub fn deinit(self: *Handshake) void {
        std.crypto.secureZero(u8, &self.static_private);
        std.crypto.secureZero(u8, &self.precomputed_ss);
        std.crypto.secureZero(u8, &self.preshared_key);
        std.crypto.secureZero(u8, &self.ephemeral_private);
        std.crypto.secureZero(u8, &self.chaining_key);
        std.crypto.secureZero(u8, &self.hash);
        std.crypto.secureZero(u8, &self.remote_ephemeral);
        self.state = .zeroed;
    }

    /// Create a Handshake Initiation message (Type 1).
    /// We are the initiator: -> e, es, s, ss, {t}
    pub fn createInitiation(self: *Handshake, sender_index: u32) !HandshakeInitiation {
        var msg: HandshakeInitiation = undefined;
        msg.message_type = std.mem.nativeToLittle(u32, 1);
        msg.sender_index = std.mem.nativeToLittle(u32, sender_index);
        self.sender_index = sender_index;

        // Initialize chaining_key and hash from construction
        // ck = Blake2s(CONSTRUCTION)
        Blake2s256.hash(CONSTRUCTION, &self.chaining_key, .{});
        // hash = Blake2s(ck || IDENTIFIER)
        var h = Blake2s256.init(.{});
        h.update(&self.chaining_key);
        h.update(IDENTIFIER);
        h.final(&self.hash);
        // hash = Blake2s(hash || remote_static)
        crypto.mixHash(&self.hash, &self.remote_static);

        // e: Generate ephemeral keypair
        self.ephemeral_private = generateSecret();
        const ephemeral_public = try X25519.recoverPublicKey(self.ephemeral_private);
        msg.ephemeral = ephemeral_public;

        // Mix ephemeral into hash and chaining_key
        crypto.mixHash(&self.hash, &ephemeral_public);
        const ck_e = crypto.kdf1(self.chaining_key, &ephemeral_public);
        self.chaining_key = ck_e.ck;

        // es: DH(ephemeral, remote_static) -> mix into CK, derive key
        const dh_es = try X25519.scalarmult(self.ephemeral_private, self.remote_static);
        const ck_es = crypto.kdf2(self.chaining_key, &dh_es);
        self.chaining_key = ck_es.ck;
        var key = ck_es.key;

        // s: Encrypt our static public key with key, AD=hash
        msg.encrypted_static = aead_encrypt_key(&key, &self.hash, &self.static_public);
        crypto.mixHash(&self.hash, &msg.encrypted_static);

        // ss: Mix precomputed DH(static, remote_static)
        const ck_ss = crypto.kdf2(self.chaining_key, &self.precomputed_ss);
        self.chaining_key = ck_ss.ck;
        key = ck_ss.key;

        // {t}: Encrypt TAI64N timestamp
        const timestamp = tai64nNow();
        msg.encrypted_timestamp = aead_encrypt_ts(&key, &self.hash, &timestamp);
        crypto.mixHash(&self.hash, &msg.encrypted_timestamp);

        // MAC1: Keyed-Blake2s(Blake2s("mac1----" || remote_static), msg_before_macs)
        // MAC2: all zeros (no cookie)
        computeMacs(&msg, self.remote_static);

        self.state = .created_initiation;
        return msg;
    }

    /// Consume a received Handshake Initiation (Type 1) as responder.
    /// Returns the decrypted initiator's public key if valid.
    pub fn consumeInitiation(self: *Handshake, msg: *const HandshakeInitiation) !void {
        // Initialize from our perspective (responder)
        // ck = Blake2s(CONSTRUCTION)
        var chaining_key: [32]u8 = undefined;
        Blake2s256.hash(CONSTRUCTION, &chaining_key, .{});
        // hash = Blake2s(ck || IDENTIFIER)
        var h = Blake2s256.init(.{});
        h.update(&chaining_key);
        h.update(IDENTIFIER);
        var hash: [32]u8 = undefined;
        h.final(&hash);
        // hash = Blake2s(hash || our_static_public)
        crypto.mixHash(&hash, &self.static_public);

        // e: Extract initiator's ephemeral
        const e = msg.ephemeral;
        crypto.mixHash(&hash, &e);
        const ck_e = crypto.kdf1(chaining_key, &e);
        chaining_key = ck_e.ck;

        // es: DH(our_static_private, initiator_ephemeral)
        const dh_es = try X25519.scalarmult(self.static_private, e);
        const ck_es = crypto.kdf2(chaining_key, &dh_es);
        chaining_key = ck_es.ck;
        var key = ck_es.key;

        // s: Decrypt initiator's static public key
        const initiator_static = try aead_decrypt(&key, &hash, &msg.encrypted_static);
        crypto.mixHash(&hash, &msg.encrypted_static);

        // Verify the decrypted static matches what we expect
        // SECURITY: Must use constant-time comparison for identity verification
        if (!std.crypto.timing_safe.eql([32]u8, initiator_static, self.remote_static)) {
            return error.UnknownPeer;
        }

        // ss: Mix precomputed DH(static, remote_static)
        const ck_ss = crypto.kdf2(chaining_key, &self.precomputed_ss);
        chaining_key = ck_ss.ck;
        key = ck_ss.key;

        // {t}: Decrypt timestamp
        const timestamp = try aead_decrypt_ts(&key, &hash, &msg.encrypted_timestamp);
        crypto.mixHash(&hash, &msg.encrypted_timestamp);

        // Anti-replay: ensure timestamp is strictly newer
        if (std.mem.order(u8, &timestamp, &self.latest_timestamp) != .gt) {
            return error.ReplayAttack;
        }

        // Success — store state
        self.remote_ephemeral = e;
        self.latest_timestamp = timestamp;
        self.hash = hash;
        self.chaining_key = chaining_key;
        self.remote_index = std.mem.littleToNative(u32, msg.sender_index);
        self.state = .consumed_initiation;
    }

    /// Consume a Handshake Initiation using pre-computed NoisePreamble state.
    /// This avoids re-doing the expensive X25519 scalarmult that was already
    /// performed in decryptInitiatorStatic. Picks up from step 4 (ss, timestamp).
    pub fn consumeInitiationFast(self: *Handshake, msg: *const HandshakeInitiation, preamble: NoisePreamble) !void {
        var chaining_key = preamble.chaining_key;
        var hash = preamble.hash;

        // Verify the decrypted static matches what we expect
        // SECURITY: Must use constant-time comparison for identity verification
        if (!std.crypto.timing_safe.eql([32]u8, preamble.initiator_static, self.remote_static)) {
            return error.UnknownPeer;
        }

        // ss: Mix precomputed DH(static, remote_static)
        const ck_ss = crypto.kdf2(chaining_key, &self.precomputed_ss);
        chaining_key = ck_ss.ck;
        const key = ck_ss.key;

        // {t}: Decrypt timestamp
        const timestamp = try aead_decrypt_ts(&key, &hash, &msg.encrypted_timestamp);
        crypto.mixHash(&hash, &msg.encrypted_timestamp);

        // Anti-replay: ensure timestamp is strictly newer
        if (std.mem.order(u8, &timestamp, &self.latest_timestamp) != .gt) {
            return error.ReplayAttack;
        }

        // Success — store state
        self.remote_ephemeral = preamble.ephemeral;
        self.latest_timestamp = timestamp;
        self.hash = hash;
        self.chaining_key = chaining_key;
        self.remote_index = std.mem.littleToNative(u32, msg.sender_index);
        self.state = .consumed_initiation;
    }

    /// Create a Handshake Response (Type 2) after consuming an initiation.
    /// We are the responder: <- e, ee, se, psk, {}
    pub fn createResponse(self: *Handshake, sender_index: u32) !HandshakeResponse {
        if (self.state != .consumed_initiation) return error.InvalidState;

        var msg: HandshakeResponse = undefined;
        msg.message_type = std.mem.nativeToLittle(u32, 2);
        msg.sender_index = std.mem.nativeToLittle(u32, sender_index);
        msg.receiver_index = std.mem.nativeToLittle(u32, self.remote_index);
        self.sender_index = sender_index;

        // e: Generate responder ephemeral
        self.ephemeral_private = generateSecret();
        const ephemeral_public = try X25519.recoverPublicKey(self.ephemeral_private);
        msg.ephemeral = ephemeral_public;
        crypto.mixHash(&self.hash, &ephemeral_public);
        const ck_e = crypto.kdf1(self.chaining_key, &ephemeral_public);
        self.chaining_key = ck_e.ck;

        // ee: DH(responder_ephemeral, initiator_ephemeral)
        const dh_ee = try X25519.scalarmult(self.ephemeral_private, self.remote_ephemeral);
        const ck_ee = crypto.kdf1(self.chaining_key, &dh_ee);
        self.chaining_key = ck_ee.ck;

        // se: DH(responder_ephemeral, initiator_static)
        const dh_se = try X25519.scalarmult(self.ephemeral_private, self.remote_static);
        const ck_se = crypto.kdf1(self.chaining_key, &dh_se);
        self.chaining_key = ck_se.ck;

        // psk: Mix pre-shared key
        const psk_result = crypto.kdf3(self.chaining_key, &self.preshared_key);
        self.chaining_key = psk_result.ck;
        crypto.mixHash(&self.hash, &psk_result.key1);
        const key = psk_result.key2;

        // {}: Encrypt empty payload
        msg.encrypted_nothing = aead_encrypt_empty(&key, &self.hash);
        crypto.mixHash(&self.hash, &msg.encrypted_nothing);

        // MACs
        computeMacsResponse(&msg, self.remote_static);

        self.state = .created_response;
        return msg;
    }

    /// Consume a Handshake Response (Type 2) as the initiator.
    pub fn consumeResponse(self: *Handshake, msg: *const HandshakeResponse) !void {
        if (self.state != .created_initiation) return error.InvalidState;

        // Verify receiver_index matches our sender_index
        const recv_idx = std.mem.littleToNative(u32, msg.receiver_index);
        if (recv_idx != self.sender_index) return error.IndexMismatch;

        // e: Extract responder ephemeral
        const e = msg.ephemeral;
        crypto.mixHash(&self.hash, &e);
        const ck_e = crypto.kdf1(self.chaining_key, &e);
        self.chaining_key = ck_e.ck;

        // ee: DH(our_ephemeral, responder_ephemeral)
        const dh_ee = try X25519.scalarmult(self.ephemeral_private, e);
        const ck_ee = crypto.kdf1(self.chaining_key, &dh_ee);
        self.chaining_key = ck_ee.ck;

        // se: DH(our_static, responder_ephemeral)
        const dh_se = try X25519.scalarmult(self.static_private, e);
        const ck_se = crypto.kdf1(self.chaining_key, &dh_se);
        self.chaining_key = ck_se.ck;

        // psk: Mix pre-shared key
        const psk_result = crypto.kdf3(self.chaining_key, &self.preshared_key);
        self.chaining_key = psk_result.ck;
        crypto.mixHash(&self.hash, &psk_result.key1);
        const key = psk_result.key2;

        // {}: Decrypt empty payload (verification)
        _ = try aead_decrypt_empty(&key, &self.hash, &msg.encrypted_nothing);
        crypto.mixHash(&self.hash, &msg.encrypted_nothing);

        self.remote_ephemeral = e;
        self.remote_index = std.mem.littleToNative(u32, msg.sender_index);
        self.state = .consumed_response;
    }

    /// Derive transport keys after a complete handshake.
    /// Call after consumeResponse (initiator) or createResponse (responder).
    pub fn deriveTransportKeys(self: *Handshake) !TransportKeys {
        if (self.state != .consumed_response and self.state != .created_response)
            return error.InvalidState;

        // Final KDF to derive sending and receiving keys
        const keys = crypto.kdf2(self.chaining_key, &.{});
        const is_initiator = (self.state == .consumed_response);

        // PFS: Destroy ephemeral secrets immediately after use
        std.crypto.secureZero(u8, &self.ephemeral_private);
        std.crypto.secureZero(u8, &self.chaining_key);
        std.crypto.secureZero(u8, &self.hash);
        std.crypto.secureZero(u8, &self.remote_ephemeral);

        return .{
            // Initiator sends with key1, receives with key2
            // Responder sends with key2, receives with key1
            .sending_key = if (is_initiator) keys.ck else keys.key,
            .receiving_key = if (is_initiator) keys.key else keys.ck,
            .sending_index = self.sender_index,
            .receiving_index = self.remote_index,
            .is_initiator = is_initiator,
            .birthdate_ns = std.time.nanoTimestamp(),
        };
    }
};

// ─── AEAD helpers ───

/// AEAD encrypt a 32-byte public key: ChaCha20-Poly1305(key, nonce=0, ad=hash, plaintext)
fn aead_encrypt_key(key: *const [32]u8, hash: *const [32]u8, plaintext: *const [32]u8) [48]u8 {
    var ciphertext: [48]u8 = undefined;
    const nonce: [12]u8 = .{0} ** 12;
    ChaCha20Poly1305.encrypt(
        ciphertext[0..32],
        ciphertext[32..48],
        plaintext,
        hash,
        nonce,
        key.*,
    );
    return ciphertext;
}

/// AEAD encrypt a 12-byte timestamp
fn aead_encrypt_ts(key: *const [32]u8, hash: *const [32]u8, plaintext: *const [TIMESTAMP_LEN]u8) [TIMESTAMP_LEN + AUTHTAG_LEN]u8 {
    var ciphertext: [TIMESTAMP_LEN + AUTHTAG_LEN]u8 = undefined;
    const nonce: [12]u8 = .{0} ** 12;
    ChaCha20Poly1305.encrypt(
        ciphertext[0..TIMESTAMP_LEN],
        ciphertext[TIMESTAMP_LEN..][0..AUTHTAG_LEN],
        plaintext,
        hash,
        nonce,
        key.*,
    );
    return ciphertext;
}

fn aead_decrypt(key: *const [32]u8, hash: *const [32]u8, ciphertext: *const [48]u8) ![32]u8 {
    var plaintext: [32]u8 = undefined;
    const nonce: [12]u8 = .{0} ** 12;
    ChaCha20Poly1305.decrypt(
        &plaintext,
        ciphertext[0..32],
        ciphertext[32..48].*,
        hash,
        nonce,
        key.*,
    ) catch return error.DecryptionFailed;
    return plaintext;
}

fn aead_decrypt_ts(key: *const [32]u8, hash: *const [32]u8, ciphertext: *const [28]u8) ![TIMESTAMP_LEN]u8 {
    var plaintext: [TIMESTAMP_LEN]u8 = undefined;
    const nonce: [12]u8 = .{0} ** 12;
    ChaCha20Poly1305.decrypt(
        &plaintext,
        ciphertext[0..TIMESTAMP_LEN],
        ciphertext[TIMESTAMP_LEN..28].*,
        hash,
        nonce,
        key.*,
    ) catch return error.DecryptionFailed;
    return plaintext;
}

fn aead_encrypt_empty(key: *const [32]u8, hash: *const [32]u8) [AEAD_LEN]u8 {
    var tag: [AEAD_LEN]u8 = undefined;
    const nonce: [12]u8 = .{0} ** 12;
    ChaCha20Poly1305.encrypt(
        &.{},
        &tag,
        &.{},
        hash,
        nonce,
        key.*,
    );
    return tag;
}

fn aead_decrypt_empty(key: *const [32]u8, hash: *const [32]u8, ciphertext: *const [AEAD_LEN]u8) !void {
    const nonce: [12]u8 = .{0} ** 12;
    ChaCha20Poly1305.decrypt(
        &.{},
        &.{},
        ciphertext.*,
        hash,
        nonce,
        key.*,
    ) catch return error.DecryptionFailed;
}

// ─── TAI64N timestamp ───

fn tai64nNow() [TIMESTAMP_LEN]u8 {
    var output: [TIMESTAMP_LEN]u8 = undefined;
    // Use CLOCK_REALTIME (wall clock) — monotonic clock resets on reboot
    // which would cause anti-replay rejection by the remote peer
    const ts = std.posix.clock_gettime(.REALTIME) catch {
        // Fallback to nanoTimestamp if clock_gettime fails
        const now_ns_total = std.time.nanoTimestamp();
        const now_s: i64 = @intCast(@divFloor(now_ns_total, std.time.ns_per_s));
        const now_ns: u32 = @intCast(@mod(now_ns_total, std.time.ns_per_s));
        const tai_seconds: u64 = @intCast(now_s + 0x400000000000000A);
        std.mem.writeInt(u64, output[0..8], tai_seconds, .big);
        std.mem.writeInt(u32, output[8..12], now_ns, .big);
        return output;
    };

    // TAI64N: big-endian u64 seconds + big-endian u32 nanoseconds
    // TAI epoch offset: 2^62 + 10 = 0x400000000000000A
    const tai_seconds: u64 = @intCast(@as(isize, ts.sec) + 0x400000000000000A);
    std.mem.writeInt(u64, output[0..8], tai_seconds, .big);
    std.mem.writeInt(u32, output[8..12], @intCast(ts.nsec), .big);
    return output;
}

/// Generate a random 32-byte secret (clamped for X25519).
fn generateSecret() [32]u8 {
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    // Clamp for Curve25519
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    return secret;
}

/// Intermediate Noise IK state from the preamble (e, es, s decryption).
/// Returned by decryptInitiatorStatic so consumeInitiationFast can continue
/// without re-doing the expensive X25519 scalarmult.
pub const NoisePreamble = struct {
    initiator_static: [32]u8,
    chaining_key: [32]u8,
    hash: [32]u8,
    ephemeral: [32]u8,
};

/// Decrypt the initiator's static public key from a Handshake Initiation message.
///
/// Returns a NoisePreamble containing the decrypted static key AND the intermediate
/// Noise state, so consumeInitiationFast can continue without re-doing X25519.
///
/// Reference: WireGuard spec §5.4.2, kernel noise.c:wg_noise_handshake_consume_initiation
pub fn decryptInitiatorStatic(
    our_static_private: [32]u8,
    our_static_public: [32]u8,
    msg: *const HandshakeInitiation,
) !NoisePreamble {
    // Replicate initial Noise IK state
    var chaining_key: [32]u8 = undefined;
    Blake2s256.hash(CONSTRUCTION, &chaining_key, .{});
    var h = Blake2s256.init(.{});
    h.update(&chaining_key);
    h.update(IDENTIFIER);
    var hash: [32]u8 = undefined;
    h.final(&hash);
    crypto.mixHash(&hash, &our_static_public);

    // e: Extract ephemeral
    const e = msg.ephemeral;
    crypto.mixHash(&hash, &e);
    const ck_e = crypto.kdf1(chaining_key, &e);
    chaining_key = ck_e.ck;

    // es: DH(our_static_private, initiator_ephemeral)
    const dh_es = try X25519.scalarmult(our_static_private, e);
    const ck_es = crypto.kdf2(chaining_key, &dh_es);
    chaining_key = ck_es.ck; // MUST update CK before returning in NoisePreamble
    const key = ck_es.key;

    // s: Decrypt initiator's static public key
    const initiator_static = try aead_decrypt(&key, &hash, &msg.encrypted_static);
    crypto.mixHash(&hash, &msg.encrypted_static);

    return .{
        .initiator_static = initiator_static,
        .chaining_key = chaining_key,
        .hash = hash,
        .ephemeral = e,
    };
}

/// Verify MAC1 on an incoming initiation message (DoS protection gate).
/// Must be called BEFORE the expensive X25519 decryptInitiatorStatic.
/// MAC1 is keyed with our own public key so we can verify without knowing the sender.
pub fn verifyMac1(our_static_public: [32]u8, msg: *const HandshakeInitiation) bool {
    var mac1_key: [32]u8 = undefined;
    var h = Blake2s256.init(.{});
    h.update("mac1----");
    h.update(&our_static_public);
    h.final(&mac1_key);

    const msg_bytes = std.mem.asBytes(msg);
    var expected: [16]u8 = undefined;
    Blake2s128.hash(msg_bytes[0..116], &expected, .{ .key = &mac1_key });

    return std.crypto.timing_safe.eql([16]u8, expected, msg.mac1);
}

// ─── MAC computation ───

fn computeMacs(msg: *HandshakeInitiation, remote_static: [32]u8) void {
    // MAC1 = Keyed-Blake2s-128(key, msg_bytes_before_mac1)
    // where key = Blake2s-256("mac1----" || remote_static)
    // CRITICAL: Must use native Blake2s128 (16-byte output), NOT truncated Blake2s256.
    // Blake2 XORs outlen into the parameter block, so truncation produces wrong bits.
    var mac1_key: [32]u8 = undefined;
    var h = Blake2s256.init(.{});
    h.update("mac1----");
    h.update(&remote_static);
    h.final(&mac1_key);

    const msg_bytes = std.mem.asBytes(msg);
    // MAC1 covers bytes 0..116 (everything before mac1 field)
    Blake2s128.hash(msg_bytes[0..116], &msg.mac1, .{ .key = &mac1_key });
    @memset(&msg.mac2, 0);
}

fn computeMacsResponse(msg: *HandshakeResponse, remote_static: [32]u8) void {
    var mac1_key: [32]u8 = undefined;
    var h = Blake2s256.init(.{});
    h.update("mac1----");
    h.update(&remote_static);
    h.final(&mac1_key);

    const msg_bytes = std.mem.asBytes(msg);
    // MAC1 covers bytes 0..60 (everything before mac1 field in response)
    Blake2s128.hash(msg_bytes[0..60], &msg.mac1, .{ .key = &mac1_key });
    @memset(&msg.mac2, 0);
}

// ─── Tests ───

test "handshake roundtrip" {
    // Generate two keypairs
    const alice_private = generateSecret();
    const alice_public = try X25519.recoverPublicKey(alice_private);
    const bob_private = generateSecret();
    const bob_public = try X25519.recoverPublicKey(bob_private);

    // Alice initiates handshake with Bob
    var alice = try Handshake.init(alice_private, alice_public, bob_public);
    var bob = try Handshake.init(bob_private, bob_public, alice_public);

    // Alice creates initiation
    const initiation = try alice.createInitiation(42);
    try std.testing.expectEqual(initiation.message_type, std.mem.nativeToLittle(u32, 1));

    // Bob consumes initiation
    try bob.consumeInitiation(&initiation);
    try std.testing.expectEqual(bob.state, .consumed_initiation);

    // Bob creates response
    const response = try bob.createResponse(99);
    try std.testing.expectEqual(response.message_type, std.mem.nativeToLittle(u32, 2));

    // Alice consumes response
    try alice.consumeResponse(&response);
    try std.testing.expectEqual(alice.state, .consumed_response);

    // Both derive transport keys
    const alice_keys = try alice.deriveTransportKeys();
    const bob_keys = try bob.deriveTransportKeys();

    // Verify key agreement: Alice's sending = Bob's receiving, and vice versa
    try std.testing.expectEqualSlices(u8, &alice_keys.sending_key, &bob_keys.receiving_key);
    try std.testing.expectEqualSlices(u8, &alice_keys.receiving_key, &bob_keys.sending_key);

    // Verify indices
    try std.testing.expectEqual(alice_keys.sending_index, 42);
    try std.testing.expectEqual(bob_keys.sending_index, 99);
}

test "handshake replay protection" {
    const alice_private = generateSecret();
    const alice_public = try X25519.recoverPublicKey(alice_private);
    const bob_private = generateSecret();
    const bob_public = try X25519.recoverPublicKey(bob_private);

    var alice = try Handshake.init(alice_private, alice_public, bob_public);
    var bob = try Handshake.init(bob_private, bob_public, alice_public);

    // First handshake succeeds
    const init1 = try alice.createInitiation(1);
    try bob.consumeInitiation(&init1);

    // Replay of the same initiation should fail (timestamp not newer)
    const result = bob.consumeInitiation(&init1);
    try std.testing.expectError(error.ReplayAttack, result);
}

test "wire format sizes" {
    // Verify our structs match the expected wire sizes
    try std.testing.expectEqual(@sizeOf(HandshakeInitiation), 148);
    try std.testing.expectEqual(@sizeOf(HandshakeResponse), 92);
    try std.testing.expectEqual(@sizeOf(TransportHeader), 16);
}

test "handshake deinit zeros state" {
    const alice_private = generateSecret();
    const alice_public = try X25519.recoverPublicKey(alice_private);
    const bob_private = generateSecret();
    const bob_public = try X25519.recoverPublicKey(bob_private);

    var alice = try Handshake.init(alice_private, alice_public, bob_public);

    // Simulate some state
    const initiation = try alice.createInitiation(42);
    _ = initiation;

    // Deinit
    alice.deinit();

    // Verify state is reset
    try std.testing.expectEqual(alice.state, .zeroed);

    // Check if secrets are zeroed
    var all_zeros = true;
    for (alice.static_private) |b| {
        if (b != 0) all_zeros = false;
    }
    try std.testing.expect(all_zeros);

    all_zeros = true;
    for (alice.ephemeral_private) |b| {
        if (b != 0) all_zeros = false;
    }
    try std.testing.expect(all_zeros);
}
