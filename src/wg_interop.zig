///! Standalone WireGuard interop test binary.
///!
///! Bypasses SWIM gossip to directly test WG tunnel establishment
///! against a kernel WireGuard peer. Used for interop validation.
///!
///! Usage:
///!   wg-interop-test --private-key <base64> --peer-pub <base64> \
///!     --peer-endpoint <ip:port> --local-ip <a.b.c.d/mask> --listen-port <port>
const std = @import("std");
const posix = std.posix;
const lib = @import("lib.zig");

const Device = lib.wireguard.Device;
const noise = lib.wireguard.Noise;
const Tun = lib.net.Tun;
const Udp = lib.net.Udp;
const RtNetlink = lib.wireguard.RtNetlink;

pub fn main() !void {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    const stderr = std.fs.File{ .handle = std.posix.STDERR_FILENO };

    // Parse CLI args
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    var private_key_b64: ?[]const u8 = null;
    var peer_pub_b64: ?[]const u8 = null;
    var peer_endpoint: ?[]const u8 = null;
    var local_ip_cidr: ?[]const u8 = null;
    var listen_port: u16 = 51830;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--private-key") and i + 1 < args.len) {
            i += 1;
            private_key_b64 = args[i];
        } else if (std.mem.eql(u8, args[i], "--peer-pub") and i + 1 < args.len) {
            i += 1;
            peer_pub_b64 = args[i];
        } else if (std.mem.eql(u8, args[i], "--peer-endpoint") and i + 1 < args.len) {
            i += 1;
            peer_endpoint = args[i];
        } else if (std.mem.eql(u8, args[i], "--local-ip") and i + 1 < args.len) {
            i += 1;
            local_ip_cidr = args[i];
        } else if (std.mem.eql(u8, args[i], "--listen-port") and i + 1 < args.len) {
            i += 1;
            listen_port = std.fmt.parseInt(u16, args[i], 10) catch 51830;
        }
    }

    if (private_key_b64 == null or peer_pub_b64 == null or peer_endpoint == null or local_ip_cidr == null) {
        try stderr.writeAll("Usage: wg-interop-test --private-key <base64> --peer-pub <base64> --peer-endpoint <ip:port> --local-ip <a.b.c.d/mask> [--listen-port <port>]\n");
        std.process.exit(1);
    }

    // Decode base64 keys
    const private_key = decodeBase64Key(private_key_b64.?) catch {
        try stderr.writeAll("error: invalid base64 private key\n");
        std.process.exit(1);
    };
    const peer_pub = decodeBase64Key(peer_pub_b64.?) catch {
        try stderr.writeAll("error: invalid base64 peer public key\n");
        std.process.exit(1);
    };

    // Derive our public key
    const public_key = std.crypto.dh.X25519.recoverPublicKey(private_key) catch {
        try stderr.writeAll("error: failed to derive public key\n");
        std.process.exit(1);
    };

    // Parse local IP/mask
    const ip_info = parseIpCidr(local_ip_cidr.?) catch {
        try stderr.writeAll("error: invalid local IP (expected a.b.c.d/mask)\n");
        std.process.exit(1);
    };

    // Parse peer endpoint
    const ep = parseEndpoint(peer_endpoint.?) catch {
        try stderr.writeAll("error: invalid peer endpoint (expected ip:port)\n");
        std.process.exit(1);
    };

    // Print config
    try stdout.writeAll("=== WireGuard Interop Test ===\n");
    var pub_b64: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&pub_b64, &public_key);
    try writeFormatted(stdout, "  our pubkey: {s}\n", .{&pub_b64});
    var peer_b64: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&peer_b64, &peer_pub);
    try writeFormatted(stdout, "  peer pubkey: {s}\n", .{&peer_b64});
    try writeFormatted(stdout, "  local IP: {d}.{d}.{d}.{d}/{d}\n", .{ ip_info.ip[0], ip_info.ip[1], ip_info.ip[2], ip_info.ip[3], ip_info.mask });
    try writeFormatted(stdout, "  peer endpoint: {d}.{d}.{d}.{d}:{d}\n", .{ ep.addr[0], ep.addr[1], ep.addr[2], ep.addr[3], ep.port });
    try writeFormatted(stdout, "  listen port: {d}\n", .{listen_port});

    // Create WG device
    var wg_dev = Device.WgDevice.init(private_key, public_key);

    // Open TUN
    var tun = Tun.TunDevice.open("wg-test0") catch |err| {
        try writeFormatted(stderr, "error: failed to open TUN: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer tun.close();

    // Configure TUN IP
    const ifindex = RtNetlink.getInterfaceIndex("wg-test0") catch |err| {
        try writeFormatted(stderr, "error: ifindex: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    RtNetlink.addAddress(ifindex, ip_info.ip, ip_info.mask) catch |err| {
        try writeFormatted(stderr, "error: addAddress: {s}\n", .{@errorName(err)});
    };
    RtNetlink.setInterfaceUp(ifindex, true) catch |err| {
        try writeFormatted(stderr, "error: ifup: {s}\n", .{@errorName(err)});
    };
    tun.setMtu(1420) catch {};

    // Add route for peer's subnet
    const peer_subnet = [4]u8{ ip_info.ip[0], ip_info.ip[1], ip_info.ip[2], 0 };
    RtNetlink.addRoute(ifindex, peer_subnet, ip_info.mask) catch {};

    try stdout.writeAll("  TUN wg-test0 configured\n");

    // Open UDP socket
    var udp = try Udp.UdpSocket.bind(listen_port);
    defer udp.close();
    try writeFormatted(stdout, "  UDP listening on :{d}\n", .{listen_port});

    // Add peer
    const slot = wg_dev.addPeer(.{0} ** 32, peer_pub, ep.addr, ep.port) catch |err| {
        try writeFormatted(stderr, "error: addPeer: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.writeAll("  peer added\n");

    // Initiate handshake
    if (wg_dev.initiateHandshake(slot)) |init_msg| {
        const msg_bytes = std.mem.asBytes(&init_msg);
        _ = udp.sendTo(msg_bytes, ep.addr, ep.port) catch 0;
        try stdout.writeAll("  handshake initiation sent\n");
    } else |_| {
        try stdout.writeAll("  handshake initiation failed\n");
    }

    // Event loop
    try stdout.writeAll("  running event loop (Ctrl+C to stop)...\n");
    try tun.setNonBlocking();

    var recv_buf: [1500]u8 = undefined;
    var tun_buf: [1500]u8 = undefined;
    var encrypt_buf: [1600]u8 = undefined;

    while (true) {
        var fds = [_]posix.pollfd{
            .{ .fd = udp.fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = tun.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = posix.poll(&fds, 1000) catch continue;

        // UDP incoming
        if (fds[0].revents & posix.POLL.IN != 0) {
            while (true) {
                const result = udp.recvFrom(&recv_buf) catch break;
                if (result == null) break;
                const recv = result.?;

                switch (Device.PacketType.classify(recv.data)) {
                    .wg_handshake_init => {
                        if (recv.data.len >= @sizeOf(noise.HandshakeInitiation)) {
                            const msg: *const noise.HandshakeInitiation = @ptrCast(@alignCast(recv.data.ptr));
                            if (wg_dev.handleInitiation(msg)) |hs| {
                                const resp = std.mem.asBytes(&hs.response);
                                _ = udp.sendTo(resp, recv.sender_addr, recv.sender_port) catch 0;
                                try stdout.writeAll("  << responded to initiation\n");
                            } else |_| {}
                        }
                    },
                    .wg_handshake_resp => {
                        if (recv.data.len >= @sizeOf(noise.HandshakeResponse)) {
                            const msg: *const noise.HandshakeResponse = @ptrCast(@alignCast(recv.data.ptr));
                            if (wg_dev.handleResponse(msg)) |s| {
                                if (wg_dev.peers[s]) |*p| {
                                    p.endpoint_addr = recv.sender_addr;
                                    p.endpoint_port = recv.sender_port;
                                }
                                try stdout.writeAll("  << handshake completed!\n");
                            } else |_| {
                                try stdout.writeAll("  << handshake response failed\n");
                            }
                        }
                    },
                    .wg_transport => {
                        var decrypt_buf: [1500]u8 = undefined;
                        if (wg_dev.decryptTransport(recv.data, &decrypt_buf)) |r| {
                            tun.write(decrypt_buf[0..r.len]) catch {};
                            try writeFormatted(stdout, "  >> transport: decrypted {d}B, wrote to TUN\n", .{r.len});
                        } else |e| {
                            try writeFormatted(stdout, "  >> transport: decrypt failed: {s}\n", .{@errorName(e)});
                        }
                    },
                    else => {},
                }
            }
        }

        // TUN outgoing
        if (fds[1].revents & posix.POLL.IN != 0) {
            while (true) {
                const n = tun.read(&tun_buf) catch |e| {
                    try writeFormatted(stdout, "  TUN read error: {s}\n", .{@errorName(e)});
                    break;
                };
                if (n == 0) break;

                try writeFormatted(stdout, "  TUN: read {d}B, encrypting for slot {d}\n", .{ n, slot });

                // Route to the single peer (slot 0)
                if (wg_dev.encryptForPeer(slot, tun_buf[0..n], &encrypt_buf)) |enc_len| {
                    if (wg_dev.peers[slot]) |peer| {
                        const sent = udp.sendTo(encrypt_buf[0..enc_len], peer.endpoint_addr, peer.endpoint_port) catch 0;
                        try writeFormatted(stdout, "  TUN: encrypted {d}B -> sent {d}B to peer\n", .{ enc_len, sent });
                    }
                } else |e| {
                    try writeFormatted(stdout, "  TUN: encrypt failed: {s}\n", .{@errorName(e)});
                }
            }
        }
    }
}

// ─── Helpers ───

fn decodeBase64Key(b64: []const u8) ![32]u8 {
    var key: [32]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(b64) catch return error.InvalidBase64;
    if (decoded_len != 32) return error.InvalidKeyLength;
    decoder.decode(&key, b64) catch return error.InvalidBase64;
    return key;
}

fn parseIpCidr(s: []const u8) !struct { ip: [4]u8, mask: u8 } {
    // Parse "a.b.c.d/mask"
    var slash_idx: ?usize = null;
    for (s, 0..) |c, idx| {
        if (c == '/') {
            slash_idx = idx;
            break;
        }
    }
    const ip_str = if (slash_idx) |si| s[0..si] else s;
    const mask_str = if (slash_idx) |si| s[si + 1 ..] else "24";

    var ip: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;
    for (ip_str, 0..) |c, idx| {
        if (c == '.' or idx == ip_str.len - 1) {
            const end = if (c == '.') idx else idx + 1;
            ip[octet_idx] = std.fmt.parseInt(u8, ip_str[start..end], 10) catch return error.InvalidIp;
            octet_idx += 1;
            start = idx + 1;
        }
    }
    if (octet_idx != 4) return error.InvalidIp;
    const mask = std.fmt.parseInt(u8, mask_str, 10) catch return error.InvalidMask;
    return .{ .ip = ip, .mask = mask };
}

fn parseEndpoint(s: []const u8) !struct { addr: [4]u8, port: u16 } {
    // Parse "a.b.c.d:port"
    var colon_idx: ?usize = null;
    for (s, 0..) |c, idx| {
        if (c == ':') colon_idx = idx;
    }
    const ci = colon_idx orelse return error.NoPort;
    const ip_result = try parseIpCidr(s[0..ci]);
    const port = std.fmt.parseInt(u16, s[ci + 1 ..], 10) catch return error.InvalidPort;
    return .{ .addr = ip_result.ip, .port = port };
}

fn writeFormatted(file: std.fs.File, comptime fmt: []const u8, args: anytype) !void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = file.write(msg) catch {};
}
