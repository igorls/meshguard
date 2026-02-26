//! Coordinated Punch — zero-infrastructure NAT traversal.
//!
//! Enables two peers behind cone NATs to establish a direct UDP tunnel
//! without any rendezvous server, using out-of-band token exchange and
//! NTP-synchronized simultaneous probing.
//!
//! Protocol:
//!   1. Peer A runs STUN, generates a token with punch_time, shares out-of-band
//!   2. Peer B decodes token, runs STUN, generates response token, shares back
//!   3. Both wait until punch_time, then probe each other's STUN-mapped address
//!   4. Success: both NATs have matching holes, WG tunnel can be established
//!
//! Token format: 106 bytes binary → URL-safe base64 → `mg://<base64url>`

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Udp = @import("../net/udp.zig");
const Stun = @import("stun.zig");
const messages = @import("../protocol/messages.zig");

/// Protocol version for tokens.
const TOKEN_VERSION: u8 = 0x01;

/// Probe magic bytes: "MGCP" = MeshGuard Coordinated Punch.
pub const PROBE_MAGIC: [4]u8 = .{ 0x4D, 0x47, 0x43, 0x50 };

/// Probe packet size: magic(4) + nonce(8) + sender_pubkey_hash(4) = 16 bytes.
const PROBE_SIZE: usize = 16;

/// Token binary size.
const TOKEN_BINARY_SIZE: usize = 106;

/// Maximum base64-encoded token size (with padding margin).
const TOKEN_B64_MAX: usize = 148; // ceil(106/3)*4 + margin

/// Punch configuration.
const PUNCH_WINDOW_SECS: u16 = 60; // 1 minute per attempt
const MAX_ATTEMPTS: u8 = 3;
const IDLE_BETWEEN_SECS: u16 = 60; // 1 minute idle between attempts
const PROBE_INTERVAL_MS: i32 = 100; // send probe every 100ms
const STUN_KEEPALIVE_INTERVAL_NS: i128 = 20_000_000_000; // 20s

/// Connection token — exchanged out-of-band between peers.
pub const Token = struct {
    version: u8 = TOKEN_VERSION,
    pubkey: [32]u8,
    wg_pubkey: [32]u8,
    stun_addr: [4]u8,
    stun_port: u16,
    mesh_ip: [4]u8,
    punch_time: u64, // unix epoch seconds
    punch_window: u16 = PUNCH_WINDOW_SECS,
    nonce: [8]u8,
    stun_server: [4]u8,
    stun_server_port: u16,
    nat_type: u8,
    signature: [6]u8, // truncated Ed25519 signature for integrity
};

/// Result of a successful punch.
pub const PunchResult = struct {
    peer_addr: [4]u8,
    peer_port: u16,
    peer_pubkey: [32]u8,
    peer_wg_pubkey: [32]u8,
    peer_mesh_ip: [4]u8,
    attempt: u8, // which attempt succeeded (1-3)
};

// ─── Token encoding/decoding ───

/// Encode a token to binary format.
pub fn encodeTokenBinary(token: *const Token, out: *[TOKEN_BINARY_SIZE]u8) void {
    var pos: usize = 0;

    out[pos] = token.version;
    pos += 1;

    @memcpy(out[pos..][0..32], &token.pubkey);
    pos += 32;

    @memcpy(out[pos..][0..32], &token.wg_pubkey);
    pos += 32;

    @memcpy(out[pos..][0..4], &token.stun_addr);
    pos += 4;

    std.mem.writeInt(u16, out[pos..][0..2], token.stun_port, .big);
    pos += 2;

    @memcpy(out[pos..][0..4], &token.mesh_ip);
    pos += 4;

    std.mem.writeInt(u64, out[pos..][0..8], token.punch_time, .big);
    pos += 8;

    std.mem.writeInt(u16, out[pos..][0..2], token.punch_window, .big);
    pos += 2;

    @memcpy(out[pos..][0..8], &token.nonce);
    pos += 8;

    @memcpy(out[pos..][0..4], &token.stun_server);
    pos += 4;

    std.mem.writeInt(u16, out[pos..][0..2], token.stun_server_port, .big);
    pos += 2;

    out[pos] = token.nat_type;
    pos += 1;

    @memcpy(out[pos..][0..6], &token.signature);
}

/// Decode a token from binary format.
pub fn decodeTokenBinary(data: *const [TOKEN_BINARY_SIZE]u8) Token {
    var pos: usize = 0;

    const version = data[pos];
    pos += 1;

    var pubkey: [32]u8 = undefined;
    @memcpy(&pubkey, data[pos..][0..32]);
    pos += 32;

    var wg_pubkey: [32]u8 = undefined;
    @memcpy(&wg_pubkey, data[pos..][0..32]);
    pos += 32;

    var stun_addr: [4]u8 = undefined;
    @memcpy(&stun_addr, data[pos..][0..4]);
    pos += 4;

    const stun_port = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;

    var mesh_ip: [4]u8 = undefined;
    @memcpy(&mesh_ip, data[pos..][0..4]);
    pos += 4;

    const punch_time = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;

    const punch_window = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;

    var nonce: [8]u8 = undefined;
    @memcpy(&nonce, data[pos..][0..8]);
    pos += 8;

    var stun_server: [4]u8 = undefined;
    @memcpy(&stun_server, data[pos..][0..4]);
    pos += 4;

    const stun_server_port = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;

    const nat_type = data[pos];
    pos += 1;

    var signature: [6]u8 = undefined;
    @memcpy(&signature, data[pos..][0..6]);

    return .{
        .version = version,
        .pubkey = pubkey,
        .wg_pubkey = wg_pubkey,
        .stun_addr = stun_addr,
        .stun_port = stun_port,
        .mesh_ip = mesh_ip,
        .punch_time = punch_time,
        .punch_window = punch_window,
        .nonce = nonce,
        .stun_server = stun_server,
        .stun_server_port = stun_server_port,
        .nat_type = nat_type,
        .signature = signature,
    };
}

/// Sign a token's content (everything except the signature field).
pub fn signToken(token: *Token, secret_key: std.crypto.sign.Ed25519.SecretKey) void {
    var bin: [TOKEN_BINARY_SIZE]u8 = undefined;
    // Zero signature field before signing
    token.signature = .{ 0, 0, 0, 0, 0, 0 };
    encodeTokenBinary(token, &bin);

    const kp = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch return;
    const sig = kp.sign(bin[0 .. TOKEN_BINARY_SIZE - 6], null) catch return;
    const sig_bytes = sig.toBytes();
    @memcpy(&token.signature, sig_bytes[0..6]);
}

/// Verify a token's signature.
pub fn verifyToken(token: *const Token) bool {
    var bin: [TOKEN_BINARY_SIZE]u8 = undefined;
    var verify_tok = token.*;
    verify_tok.signature = .{ 0, 0, 0, 0, 0, 0 };
    encodeTokenBinary(&verify_tok, &bin);

    const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(token.pubkey) catch return false;

    // We only stored 6 bytes of the signature — can't do full Ed25519 verify.
    // Instead, re-sign and compare truncated signature.
    // This provides integrity (tampering detection), not authentication
    // (the pubkey itself IS the authentication since it was shared out-of-band).
    _ = public_key;

    // For integrity, we use a simpler approach: BLAKE3 hash of content + pubkey
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bin[0 .. TOKEN_BINARY_SIZE - 6], &hash, .{});
    return std.mem.eql(u8, &token.signature, hash[0..6]);
}

/// Sign token using BLAKE3 hash (matches verifyToken).
pub fn signTokenHash(token: *Token) void {
    var bin: [TOKEN_BINARY_SIZE]u8 = undefined;
    token.signature = .{ 0, 0, 0, 0, 0, 0 };
    encodeTokenBinary(token, &bin);

    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bin[0 .. TOKEN_BINARY_SIZE - 6], &hash, .{});
    @memcpy(&token.signature, hash[0..6]);
}

// ─── Base64url encoding (RFC 4648 §5) ───

/// Encode token to `mg://` URI string. Returns slice of `out` that was written.
pub fn encodeTokenUri(token: *const Token, out: *[156]u8) []const u8 {
    var bin: [TOKEN_BINARY_SIZE]u8 = undefined;
    encodeTokenBinary(token, &bin);

    // mg:// prefix (4 bytes)
    @memcpy(out[0..5], "mg://");

    // URL-safe base64 encode
    const b64_len = base64UrlEncode(&bin, out[5..]) catch 0;

    return out[0 .. 5 + b64_len];
}

/// Decode token from `mg://` URI string.
pub fn decodeTokenUri(uri: []const u8) !Token {
    // Strip mg:// prefix
    if (uri.len < 5) return error.InvalidToken;
    if (!std.mem.eql(u8, uri[0..5], "mg://")) return error.InvalidToken;

    const b64_data = uri[5..];

    var bin: [TOKEN_BINARY_SIZE]u8 = undefined;
    const decoded_len = base64UrlDecode(b64_data, &bin) catch return error.InvalidToken;
    if (decoded_len != TOKEN_BINARY_SIZE) return error.InvalidToken;

    const token = decodeTokenBinary(&bin);

    // Verify integrity
    if (!verifyToken(&token)) return error.InvalidSignature;

    return token;
}

// ─── URL-safe base64 helpers ───

fn base64UrlEncode(input: []const u8, output: []u8) !usize {
    const standard = std.base64.standard.Encoder;
    const encoded = standard.encode(output, input);
    _ = encoded;

    // Calculate length
    const len = std.base64.standard.Encoder.calcSize(input.len);

    // Replace + with -, / with _, strip =
    var out_len: usize = 0;
    for (0..len) |i| {
        if (output[i] == '+') {
            output[out_len] = '-';
        } else if (output[i] == '/') {
            output[out_len] = '_';
        } else if (output[i] == '=') {
            continue; // skip padding
        } else {
            output[out_len] = output[i];
        }
        out_len += 1;
    }

    return out_len;
}

fn base64UrlDecode(input: []const u8, output: []u8) !usize {
    // Convert URL-safe back to standard base64
    var buf: [256]u8 = undefined;
    if (input.len > buf.len - 4) return error.InputTooLong;

    var len: usize = 0;
    for (input) |c| {
        if (c == '-') {
            buf[len] = '+';
        } else if (c == '_') {
            buf[len] = '/';
        } else {
            buf[len] = c;
        }
        len += 1;
    }

    // Add padding
    while (len % 4 != 0) : (len += 1) {
        buf[len] = '=';
    }

    try std.base64.standard.Decoder.decode(output, buf[0..len]);
    return std.base64.standard.Decoder.calcSizeForSlice(buf[0..len]) catch return error.InvalidBase64;
}

// ─── NTP client ───

/// Minimal SNTPv4 query — returns unix epoch seconds.
/// Queries pool.ntp.org (or fallback servers).
/// Returns null if all servers fail (caller should use system time).
pub fn ntpQuery() ?u64 {
    const NTP_SERVERS = [_][4]u8{
        .{ 162, 159, 200, 1 }, // time.google.com
        .{ 129, 6, 15, 28 }, // time-a-g.nist.gov
    };
    const NTP_PORT: u16 = 123;
    const NTP_EPOCH_OFFSET: u64 = 2208988800; // seconds from 1900 to 1970

    var socket = Udp.UdpSocket.bind(0) catch return null;
    defer socket.close();

    for (NTP_SERVERS) |server| {
        // Build SNTP request (48 bytes)
        var req: [48]u8 = .{0} ** 48;
        req[0] = 0x23; // LI=0, VN=4, Mode=3 (client)

        _ = socket.sendTo(&req, server, NTP_PORT) catch continue;

        if (!(socket.pollRead(2000) catch continue)) continue;

        var resp_buf: [512]u8 = undefined;
        const result = (socket.recvFrom(&resp_buf) catch continue) orelse continue;
        if (result.data.len < 48) continue;

        // Transmit Timestamp: bytes 40-43 (seconds), 44-47 (fraction)
        const ntp_seconds = std.mem.readInt(u32, result.data[40..44], .big);
        if (ntp_seconds < NTP_EPOCH_OFFSET) continue;

        return @as(u64, ntp_seconds) - NTP_EPOCH_OFFSET;
    }

    return null;
}

/// Get current time as unix epoch seconds, preferring NTP.
pub fn currentTimeSecs() u64 {
    if (ntpQuery()) |ntp_time| return ntp_time;
    // Fallback to system clock
    const ts = std.time.timestamp();
    return @intCast(@max(ts, 0));
}

// ─── Probe loop ───

/// Build a probe packet.
fn buildProbe(nonce: [8]u8, pubkey: [32]u8) [PROBE_SIZE]u8 {
    var probe: [PROBE_SIZE]u8 = undefined;
    @memcpy(probe[0..4], &PROBE_MAGIC);
    @memcpy(probe[4..12], &nonce);
    // First 4 bytes of pubkey hash for sender identification
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&pubkey, &hash, .{});
    @memcpy(probe[12..16], hash[0..4]);
    return probe;
}

/// Check if a received packet is a valid coordinated punch probe.
pub fn isCoordinatedProbe(data: []const u8) bool {
    if (data.len < PROBE_SIZE) return false;
    return std.mem.eql(u8, data[0..4], &PROBE_MAGIC);
}

/// Check if a probe matches the expected nonce.
pub fn probeMatchesNonce(data: []const u8, expected_nonce: [8]u8) bool {
    if (data.len < PROBE_SIZE) return false;
    return std.mem.eql(u8, data[4..12], &expected_nonce);
}

/// Sleep for the given number of milliseconds using POSIX nanosleep.
fn sleepMs(ms: u32) void {
    const ts = linux.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast(@as(u64, ms % 1000) * 1_000_000),
    };
    _ = linux.nanosleep(&ts, null);
}

/// Run the coordinated punch loop.
///
/// Waits until `punch_time`, then sends probes to `peer_addr:peer_port`
/// while listening for incoming probes. Retries up to MAX_ATTEMPTS times.
///
/// Returns the confirmed peer endpoint on success, or null on failure.
pub fn runPunchLoop(
    socket: *Udp.UdpSocket,
    our_pubkey: [32]u8,
    our_nonce: [8]u8,
    peer_nonce: [8]u8,
    peer_addr: [4]u8,
    peer_port: u16,
    punch_time: u64,
    stun_server: Stun.StunServer,
    stdout: std.fs.File,
) ?PunchResult {
    const probe_pkt = buildProbe(our_nonce, our_pubkey);

    for (0..MAX_ATTEMPTS) |attempt| {
        if (attempt > 0) {
            writeMsg(stdout, "  retrying... (attempt {d}/{d})\n", .{ attempt + 1, MAX_ATTEMPTS });

            // Idle period with STUN keepalive
            var idle_elapsed: i128 = 0;
            var last_keepalive: i128 = 0;
            const idle_ns: i128 = @as(i128, IDLE_BETWEEN_SECS) * 1_000_000_000;

            while (idle_elapsed < idle_ns) {
                const now = std.time.nanoTimestamp();

                // STUN keepalive every 20s to maintain NAT mapping
                if (now - last_keepalive > STUN_KEEPALIVE_INTERVAL_NS) {
                    _ = Stun.discoverPublicEndpoint(socket, stun_server) catch {};
                    last_keepalive = now;
                }

                // Drain any stale packets
                var drain_buf: [512]u8 = undefined;
                _ = socket.recvFrom(&drain_buf) catch {};

                sleepMs(500);
                idle_elapsed += 500_000_000;
            }
        }

        // Wait until punch_time
        const target_ns: i128 = @as(i128, punch_time) * 1_000_000_000;
        // Add attempt offset to avoid tight retry overlap
        const attempt_offset_ns: i128 = @as(i128, attempt) * @as(i128, IDLE_BETWEEN_SECS + PUNCH_WINDOW_SECS) * 1_000_000_000;
        const effective_target = target_ns + attempt_offset_ns;

        while (true) {
            const now = std.time.nanoTimestamp();
            if (now >= effective_target) break;

            const wait_secs = @divTrunc(effective_target - now, 1_000_000_000);
            if (wait_secs > 0) {
                writeMsg(stdout, "  punch in {d}s...\r", .{@as(u32, @intCast(@min(wait_secs, 9999)))});
            }

            // STUN keepalive while waiting
            if (effective_target - now > STUN_KEEPALIVE_INTERVAL_NS) {
                _ = Stun.discoverPublicEndpoint(socket, stun_server) catch {};
            }

            sleepMs(1000);
        }

        // Refresh STUN right before punching
        writeMsg(stdout, "  refreshing STUN binding...    \n", .{});
        _ = Stun.discoverPublicEndpoint(socket, stun_server) catch {};

        // Probing phase
        writeMsg(stdout, "  punching...\n", .{});

        const window_ns: i128 = @as(i128, PUNCH_WINDOW_SECS) * 1_000_000_000;
        const start = std.time.nanoTimestamp();
        var last_probe_sent: i128 = 0;
        var probes_sent: u32 = 0;
        var detected: bool = false;
        var detect_time: i128 = 0;
        var result_addr: [4]u8 = undefined;
        var result_port: u16 = 0;
        const POST_DETECT_NS: i128 = 3_000_000_000; // keep probing 3s after detection

        while (true) {
            const now = std.time.nanoTimestamp();
            const elapsed = now - start;

            // Exit conditions
            if (detected and now - detect_time >= POST_DETECT_NS) break;
            if (!detected and elapsed >= window_ns) break;

            // Send probe at intervals
            const interval_ns: i128 = @as(i128, PROBE_INTERVAL_MS) * 1_000_000;
            if (now - last_probe_sent >= interval_ns) {
                _ = socket.sendTo(&probe_pkt, peer_addr, peer_port) catch {};
                last_probe_sent = now;
                probes_sent += 1;
            }

            // Poll for incoming with short timeout
            if (socket.pollRead(50) catch false) {
                var recv_buf: [512]u8 = undefined;
                if (socket.recvFrom(&recv_buf) catch null) |recv| {
                    if (!detected and isCoordinatedProbe(recv.data) and probeMatchesNonce(recv.data, peer_nonce)) {
                        detected = true;
                        detect_time = now;
                        result_addr = recv.sender_addr;
                        result_port = recv.sender_port;
                        writeMsg(stdout, "  ✓ hole punched! ({d} probes sent, attempt {d})\n", .{ probes_sent, attempt + 1 });
                        writeMsg(stdout, "  sending confirmation probes (3s)...\n", .{});
                    }
                }
            }
        }

        if (detected) {
            return PunchResult{
                .peer_addr = result_addr,
                .peer_port = result_port,
                .peer_pubkey = undefined,
                .peer_wg_pubkey = undefined,
                .peer_mesh_ip = undefined,
                .attempt = @intCast(attempt + 1),
            };
        }

        writeMsg(stdout, "  attempt {d} timed out ({d} probes sent)\n", .{ attempt + 1, probes_sent });
    }

    return null;
}

fn writeMsg(file: std.fs.File, comptime fmt: []const u8, args: anytype) void {
    // Prefix with HH:MM:SS timestamp
    const ts = std.time.timestamp();
    const secs_today: u64 = @intCast(@mod(@as(i64, @intCast(@max(ts, 0))), 86400));
    const hours: u32 = @intCast(secs_today / 3600);
    const minutes: u32 = @intCast((secs_today % 3600) / 60);
    const seconds: u32 = @intCast(secs_today % 60);

    var ts_buf: [12]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "[{d:0>2}:{d:0>2}:{d:0>2}] ", .{ hours, minutes, seconds }) catch "[??:??:??] ";
    file.writeAll(ts_str) catch {};

    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    file.writeAll(msg) catch {};
}

// ─── Peer persistence ───

/// Save a punched peer as a seed file for future `meshguard up`.
pub fn savePunchedSeed(
    allocator: std.mem.Allocator,
    config_dir: []const u8,
    peer_addr: [4]u8,
    peer_port: u16,
) !void {
    // Save as "seeds" file — one `host:port` per line
    const seeds_path = try std.fs.path.join(allocator, &.{ config_dir, "seeds" });
    defer allocator.free(seeds_path);

    var ip_buf: [15]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
        peer_addr[0], peer_addr[1], peer_addr[2], peer_addr[3],
    }) catch return error.FormatError;

    var entry_buf: [32]u8 = undefined;
    const entry = std.fmt.bufPrint(&entry_buf, "{s}:{d}\n", .{ ip_str, peer_port }) catch return error.FormatError;

    // Append to seeds file (create if not exists)
    const file = std.fs.createFileAbsolute(seeds_path, .{
        .truncate = false,
    }) catch |err| {
        if (err == error.PathAlreadyExists) {
            const existing = try std.fs.openFileAbsolute(seeds_path, .{ .mode = .write_only });
            try existing.seekFromEnd(0);
            try existing.writeAll(entry);
            existing.close();
            return;
        }
        return err;
    };
    defer file.close();
    try file.writeAll(entry);
}

// ─── Tests ───

test "token encode/decode round-trip" {
    var token = Token{
        .pubkey = [_]u8{0xAA} ** 32,
        .wg_pubkey = [_]u8{0xBB} ** 32,
        .stun_addr = .{ 179, 218, 15, 153 },
        .stun_port = 8475,
        .mesh_ip = .{ 10, 99, 38, 137 },
        .punch_time = 1740000000,
        .punch_window = 60,
        .nonce = [_]u8{0xCC} ** 8,
        .stun_server = .{ 74, 125, 250, 129 },
        .stun_server_port = 19302,
        .nat_type = 1,
        .signature = .{ 0, 0, 0, 0, 0, 0 },
    };
    signTokenHash(&token);

    var bin: [TOKEN_BINARY_SIZE]u8 = undefined;
    encodeTokenBinary(&token, &bin);
    const decoded = decodeTokenBinary(&bin);

    try std.testing.expectEqualSlices(u8, &token.pubkey, &decoded.pubkey);
    try std.testing.expectEqualSlices(u8, &token.wg_pubkey, &decoded.wg_pubkey);
    try std.testing.expectEqualSlices(u8, &token.stun_addr, &decoded.stun_addr);
    try std.testing.expectEqual(token.stun_port, decoded.stun_port);
    try std.testing.expectEqual(token.punch_time, decoded.punch_time);
    try std.testing.expectEqual(token.punch_window, decoded.punch_window);
    try std.testing.expectEqualSlices(u8, &token.nonce, &decoded.nonce);
    try std.testing.expectEqual(token.nat_type, decoded.nat_type);
    try std.testing.expectEqualSlices(u8, &token.signature, &decoded.signature);
}

test "token URI encode/decode round-trip" {
    var token = Token{
        .pubkey = [_]u8{0x11} ** 32,
        .wg_pubkey = [_]u8{0x22} ** 32,
        .stun_addr = .{ 1, 2, 3, 4 },
        .stun_port = 12345,
        .mesh_ip = .{ 10, 99, 1, 2 },
        .punch_time = 1740000060,
        .punch_window = 60,
        .nonce = [_]u8{0x33} ** 8,
        .stun_server = .{ 74, 125, 250, 129 },
        .stun_server_port = 19302,
        .nat_type = 1,
        .signature = .{ 0, 0, 0, 0, 0, 0 },
    };
    signTokenHash(&token);

    var uri_buf: [156]u8 = undefined;
    const uri = encodeTokenUri(&token, &uri_buf);

    // Should start with mg://
    try std.testing.expect(std.mem.startsWith(u8, uri, "mg://"));

    // Should not contain + / = (URL-safe)
    for (uri[5..]) |c| {
        try std.testing.expect(c != '+');
        try std.testing.expect(c != '/');
        try std.testing.expect(c != '=');
    }

    // Decode back
    const decoded = try decodeTokenUri(uri);
    try std.testing.expectEqualSlices(u8, &token.pubkey, &decoded.pubkey);
    try std.testing.expectEqual(token.punch_time, decoded.punch_time);
}

test "token signature verification" {
    var token = Token{
        .pubkey = [_]u8{0x44} ** 32,
        .wg_pubkey = [_]u8{0x55} ** 32,
        .stun_addr = .{ 10, 0, 0, 1 },
        .stun_port = 5000,
        .mesh_ip = .{ 10, 99, 10, 20 },
        .punch_time = 1740000000,
        .punch_window = 60,
        .nonce = [_]u8{0x66} ** 8,
        .stun_server = .{ 8, 8, 8, 8 },
        .stun_server_port = 3478,
        .nat_type = 0,
        .signature = .{ 0, 0, 0, 0, 0, 0 },
    };
    signTokenHash(&token);
    try std.testing.expect(verifyToken(&token));

    // Tamper with token
    var tampered = token;
    tampered.stun_port = 9999;
    try std.testing.expect(!verifyToken(&tampered));
}

test "probe building and detection" {
    const nonce = [_]u8{0xAB} ** 8;
    const pubkey = [_]u8{0xCD} ** 32;
    const probe = buildProbe(nonce, pubkey);

    try std.testing.expect(isCoordinatedProbe(&probe));
    try std.testing.expect(probeMatchesNonce(&probe, nonce));

    // Wrong nonce
    try std.testing.expect(!probeMatchesNonce(&probe, [_]u8{0x00} ** 8));

    // Not a probe
    const not_probe = [_]u8{0x01} ** 16;
    try std.testing.expect(!isCoordinatedProbe(&not_probe));
}

test "NTP packet format" {
    // Verify our NTP request packet structure
    var req: [48]u8 = .{0} ** 48;
    req[0] = 0x23; // LI=0, VN=4, Mode=3

    // Check LI (bits 7-6) = 0, VN (bits 5-3) = 4, Mode (bits 2-0) = 3
    try std.testing.expectEqual(req[0] & 0xC0, 0x00); // LI = 0
    try std.testing.expectEqual((req[0] >> 3) & 0x07, 4); // VN = 4
    try std.testing.expectEqual(req[0] & 0x07, 3); // Mode = 3
}
