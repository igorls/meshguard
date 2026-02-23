///! Thin Zig bindings for libsodium ChaCha20-Poly1305 IETF AEAD.
///!
///! Uses extern "c" declarations to link dynamically against libsodium.so.
///! libsodium's implementation uses hand-written AVX2 assembly (8-block width)
///! which is ~2× faster than Zig's stdlib ChaCha20 (2-block width on AVX2).
const std = @import("std");

// ─── libsodium extern declarations ───

extern "c" fn sodium_init() c_int;

extern "c" fn crypto_aead_chacha20poly1305_ietf_encrypt_detached(
    c: [*]u8,
    mac: [*]u8,
    maclen_p: ?*c_ulonglong,
    m: [*]const u8,
    mlen: c_ulonglong,
    ad: ?[*]const u8,
    adlen: c_ulonglong,
    nsec: ?*const u8,
    npub: [*]const u8,
    k: [*]const u8,
) c_int;

extern "c" fn crypto_aead_chacha20poly1305_ietf_decrypt_detached(
    m: [*]u8,
    nsec: ?*u8,
    c: [*]const u8,
    clen: c_ulonglong,
    mac: [*]const u8,
    ad: ?[*]const u8,
    adlen: c_ulonglong,
    npub: [*]const u8,
    k: [*]const u8,
) c_int;

// ─── Public API (matches Zig stdlib signature) ───

pub const tag_length = 16;
pub const nonce_length = 12;
pub const key_length = 32;

var initialized: bool = false;

pub fn init() void {
    if (!initialized) {
        _ = sodium_init();
        initialized = true;
    }
}

/// Encrypt in-place (src == dest supported). Writes ciphertext to `c` and auth tag to `tag`.
pub fn encrypt(
    c: []u8,
    tag: *[tag_length]u8,
    m: []const u8,
    ad: []const u8,
    npub: [nonce_length]u8,
    k: [key_length]u8,
) void {
    _ = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        c.ptr,
        tag,
        null,
        m.ptr,
        @intCast(m.len),
        if (ad.len > 0) ad.ptr else null,
        @intCast(ad.len),
        null,
        &npub,
        &k,
    );
}

/// Decrypt with authentication. Returns error if tag verification fails.
pub fn decrypt(
    m: []u8,
    c: []const u8,
    tag: [tag_length]u8,
    ad: []const u8,
    npub: [nonce_length]u8,
    k: [key_length]u8,
) !void {
    const rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        m.ptr,
        null,
        c.ptr,
        @intCast(c.len),
        &tag,
        if (ad.len > 0) ad.ptr else null,
        @intCast(ad.len),
        &npub,
        &k,
    );
    if (rc != 0) return error.AuthenticationFailed;
}
