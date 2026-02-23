const std = @import("std");
const lib = @import("lib.zig");

const Config = lib.config.Config;
const Identity = lib.identity.Keys;
const posix = std.posix;

const version = "0.1.0";

const usage =
    \\meshguard — decentralized WireGuard mesh VPN daemon
    \\
    \\USAGE:
    \\  meshguard <command> [options]
    \\
    \\COMMANDS:
    \\  up          Start the daemon and join the mesh
    \\  down        Stop the daemon
    \\  status      Show mesh status
    \\  keygen      Generate a new identity keypair (--force to overwrite)
    \\  trust       Authorize a peer's public key (--name <label>)
    \\  revoke      Revoke a peer's public key
    \\  export      Print this node's public key
    \\  version     Print version
    \\
    \\OPTIONS:
    \\  --config <path>     Path to config file
    \\  --seed <ip:port>    Seed peer address (can be repeated)
    \\  --seed-dns <domain> DNS domain for seed discovery
    \\  --seed-mdns         Enable mDNS seed discovery
    \\  -h, --help          Show this help
    \\
;

fn getStdOut() std.fs.File {
    return .{ .handle = std.posix.STDOUT_FILENO };
}

fn getStdErr() std.fs.File {
    return .{ .handle = std.posix.STDERR_FILENO };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try getStdErr().writeAll(usage);
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version")) {
        try getStdOut().writeAll("meshguard " ++ version ++ "\n");
        return;
    }

    if (std.mem.eql(u8, command, "-h") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "help")) {
        try getStdOut().writeAll(usage);
        return;
    }

    if (std.mem.eql(u8, command, "keygen")) {
        try cmdKeygen(allocator, args[2..]);
        return;
    }

    if (std.mem.eql(u8, command, "export")) {
        try cmdExport(allocator);
        return;
    }

    if (std.mem.eql(u8, command, "trust")) {
        if (args.len < 3) {
            try getStdErr().writeAll("error: 'trust' requires a public key or path argument\n");
            std.process.exit(1);
        }
        try cmdTrust(allocator, args[2], args[3..]);
        return;
    }

    if (std.mem.eql(u8, command, "revoke")) {
        if (args.len < 3) {
            try getStdErr().writeAll("error: 'revoke' requires a public key or name argument\n");
            std.process.exit(1);
        }
        try cmdRevoke(allocator, args[2]);
        return;
    }

    if (std.mem.eql(u8, command, "up")) {
        try cmdUp(allocator, args[2..]);
        return;
    }

    if (std.mem.eql(u8, command, "down")) {
        try cmdDown(allocator);
        return;
    }

    if (std.mem.eql(u8, command, "status")) {
        try cmdStatus(allocator);
        return;
    }

    try getStdErr().writeAll("error: unknown command\n\n");
    try getStdErr().writeAll(usage);
    std.process.exit(1);
}

// ─── Command implementations ───

fn writeFormatted(file: std.fs.File, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try file.writeAll(msg);
}

fn cmdKeygen(allocator: std.mem.Allocator, extra_args: []const []const u8) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    // Parse --force flag
    var force = false;
    for (extra_args) |arg| {
        if (std.mem.eql(u8, arg, "--force")) {
            force = true;
        }
    }

    // Check if identity already exists
    if (!force) {
        if (Identity.load(allocator, config_dir)) |existing| {
            _ = existing;
            const stderr = getStdErr();
            try stderr.writeAll("error: identity already exists. Use 'meshguard keygen --force' to overwrite.\n");

            // Show existing public key for convenience
            const pk_path = try std.fs.path.join(allocator, &.{ config_dir, "identity.pub" });
            defer allocator.free(pk_path);
            const pk_file = try std.fs.openFileAbsolute(pk_path, .{});
            defer pk_file.close();
            var pk_raw: [45]u8 = undefined;
            const pk_read = try pk_file.readAll(&pk_raw);
            const pk_b64 = std.mem.trimRight(u8, pk_raw[0..pk_read], "\n\r ");
            try writeFormatted(stderr, "Existing public key: {s}\n", .{pk_b64});

            std.process.exit(1);
        } else |_| {
            // No existing identity — proceed with generation
        }
    }

    const kp = Identity.generate();
    try Identity.save(allocator, config_dir, kp);

    var b64_buf: [44]u8 = undefined;
    const pub_b64 = std.base64.standard.Encoder.encode(&b64_buf, &kp.public_key.toBytes());

    const stdout = getStdOut();
    try stdout.writeAll("Identity keypair generated.\n");
    try writeFormatted(stdout, "Public key: {s}\n", .{pub_b64});
    try writeFormatted(stdout, "Saved to:   {s}/\n", .{config_dir});
}

fn cmdExport(allocator: std.mem.Allocator) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    const kp = Identity.load(allocator, config_dir) catch |err| {
        if (err == error.FileNotFound) {
            try getStdErr().writeAll("error: no identity found. Run 'meshguard keygen' first.\n");
            std.process.exit(1);
        }
        return err;
    };

    var buf: [44]u8 = undefined;
    const pub_b64 = std.base64.standard.Encoder.encode(&buf, &kp.public_key.toBytes());

    const stdout = getStdOut();
    try stdout.writeAll(pub_b64);
    try stdout.writeAll("\n");
}

fn cmdTrust(allocator: std.mem.Allocator, key_or_path: []const u8, extra_args: []const []const u8) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    // Parse --name <label> from extra args
    var peer_name: ?[]const u8 = null;
    var i: usize = 0;
    while (i < extra_args.len) : (i += 1) {
        if (std.mem.eql(u8, extra_args[i], "--name")) {
            if (i + 1 < extra_args.len) {
                peer_name = extra_args[i + 1];
                i += 1;
            } else {
                try getStdErr().writeAll("error: --name requires a value\n");
                std.process.exit(1);
            }
        }
    }

    // Step 1: Validate the key
    var key_b64_buf: [44]u8 = undefined;
    var pk_bytes: [32]u8 = undefined;
    if (lib.identity.Trust.validateKey(key_or_path, &key_b64_buf, &pk_bytes)) |err_msg| {
        try writeFormatted(getStdErr(), "error: {s}\n", .{err_msg});
        std.process.exit(1);
    }

    // Determine the key b64 string and name
    const key_b64: []const u8 = blk: {
        for (key_b64_buf, 0..) |c, idx| {
            if (c == 0) break :blk key_b64_buf[0..idx];
        }
        break :blk &key_b64_buf;
    };

    const auto_name: []const u8 = if (std.fs.path.isAbsolute(key_or_path) or std.mem.endsWith(u8, key_or_path, ".pub"))
        std.fs.path.stem(key_or_path)
    else if (key_or_path.len >= 8)
        key_or_path[0..8]
    else
        key_or_path;

    const name = peer_name orelse auto_name;
    const stdout = getStdOut();
    const stderr = getStdErr();

    // Step 2: Check if this exact key already exists under any name
    if (try lib.identity.Trust.findExistingByKey(allocator, config_dir, key_b64)) |existing_name| {
        defer allocator.free(existing_name);

        if (std.mem.eql(u8, existing_name, name)) {
            // Same key, same name — already trusted
            try writeFormatted(stdout, "Peer '{s}' is already trusted.\n", .{name});
            return;
        } else {
            // Same key, different name — rename it
            try lib.identity.Trust.removeKeyFile(allocator, config_dir, existing_name);
            try lib.identity.Trust.addAuthorizedKey(allocator, config_dir, key_b64, name);
            try writeFormatted(stdout, "Peer renamed from '{s}' to '{s}'.\n", .{ existing_name, name });
            return;
        }
    }

    // Step 3: Check if the target name already exists with a different key
    if (try lib.identity.Trust.checkNameConflict(allocator, config_dir, name, key_b64)) |conflict| {
        if (conflict.key_matches) {
            // Same key same name (shouldn't reach here, but just in case)
            try writeFormatted(stdout, "Peer '{s}' is already trusted.\n", .{name});
            return;
        }

        // Different key, same name — prompt user
        try writeFormatted(stderr, "warning: peer '{s}' already exists with a different key.\n", .{name});
        try stderr.writeAll("Overwrite? [y/N] ");

        // Read user input
        const stdin_file: std.fs.File = .{ .handle = std.posix.STDIN_FILENO };
        var input_buf: [16]u8 = undefined;
        const read = stdin_file.readAll(&input_buf) catch 0;
        const answer = std.mem.trimRight(u8, input_buf[0..read], "\n\r ");

        if (answer.len > 0 and (answer[0] == 'y' or answer[0] == 'Y')) {
            try lib.identity.Trust.addAuthorizedKey(allocator, config_dir, key_b64, name);
            try writeFormatted(stdout, "Peer '{s}' updated with new key.\n", .{name});
        } else {
            try stderr.writeAll("Aborted.\n");
            std.process.exit(1);
        }
        return;
    }

    // Step 4: New key, new name — just add it
    try lib.identity.Trust.addAuthorizedKey(allocator, config_dir, key_b64, name);
    try writeFormatted(stdout, "Peer '{s}' trusted.\n", .{name});
}

fn cmdRevoke(allocator: std.mem.Allocator, key_or_name: []const u8) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    try lib.identity.Trust.removeAuthorizedKey(allocator, config_dir, key_or_name);

    try getStdOut().writeAll("Peer revoked.\n");
}

fn cmdUp(allocator: std.mem.Allocator, extra_args: []const []const u8) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    const stdout = getStdOut();
    const stderr = getStdErr();

    // Parse --seed, --announce, and --kernel arguments
    const messages = @import("protocol/messages.zig");
    var seed_buf: [16]messages.Endpoint = undefined;
    var seed_count: usize = 0;
    var announce_addr: ?[4]u8 = null;
    var use_kernel_wg: bool = false;
    {
        var i: usize = 0;
        while (i < extra_args.len) : (i += 1) {
            if (std.mem.eql(u8, extra_args[i], "--seed") and i + 1 < extra_args.len) {
                i += 1;
                if (lib.discovery.Seed.parseEndpoint(extra_args[i])) |ep| {
                    if (seed_count < seed_buf.len) {
                        seed_buf[seed_count] = ep;
                        seed_count += 1;
                    }
                } else {
                    try writeFormatted(stderr, "warning: ignoring invalid seed '{s}'\n", .{extra_args[i]});
                }
            } else if (std.mem.eql(u8, extra_args[i], "--announce") and i + 1 < extra_args.len) {
                i += 1;
                // Parse IP address (just the IP, ports come from config)
                const ip_str_arg = extra_args[i];
                announce_addr = parseIpv4(ip_str_arg);
                if (announce_addr == null) {
                    try writeFormatted(stderr, "warning: ignoring invalid announce address '{s}'\n", .{ip_str_arg});
                }
            } else if (std.mem.eql(u8, extra_args[i], "--kernel")) {
                use_kernel_wg = true;
            }
        }
    }

    // Load identity
    const kp = Identity.load(allocator, config_dir) catch |err| {
        if (err == error.FileNotFound) {
            try stderr.writeAll("error: no identity found. Run 'meshguard keygen' first.\n");
            std.process.exit(1);
        }
        return err;
    };

    // Derive mesh IP from public key
    const pub_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(kp.public_key.toBytes());
    const mesh_ip = lib.wireguard.Ip.deriveFromPubkey(pub_key);
    var ip_str_buf: [15]u8 = undefined;
    const ip_str = lib.wireguard.Ip.formatIp(mesh_ip, &ip_str_buf);

    try stdout.writeAll("meshguard starting...\n");
    try writeFormatted(stdout, "  mesh IP: {s}\n", .{ip_str});
    try writeFormatted(stdout, "  interface: {s}\n", .{lib.wireguard.Config.DEFAULT_IFNAME});
    try writeFormatted(stdout, "  mode: {s}\n", .{if (use_kernel_wg) "kernel" else "userspace"});

    // Derive a WireGuard X25519 private key from the Ed25519 seed
    // Standard Ed25519→X25519 conversion: SHA-512(seed), take first 32 bytes, clamp
    const sk_bytes = kp.secret_key.seed();
    var hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&sk_bytes, &hash, .{});
    var wg_private_key: [32]u8 = hash[0..32].*;

    // Clamp the key per Curve25519 convention
    wg_private_key[0] &= 248;
    wg_private_key[31] &= 127;
    wg_private_key[31] |= 64;

    // Derive WG public key from clamped private key (X25519 base point mult)
    const wg_public_key = std.crypto.dh.X25519.recoverPublicKey(wg_private_key) catch {
        try stderr.writeAll("error: failed to derive WG public key\n");
        std.process.exit(1);
    };

    // Setup WireGuard interface (kernel or TUN)
    if (use_kernel_wg) {
        // Kernel mode: configure via netlink
        const cfg = lib.wireguard.Config.MeshConfig{
            .private_key = wg_private_key,
            .listen_port = 51830,
            .mesh_ip = mesh_ip,
        };

        lib.wireguard.Config.setup(cfg) catch |err| {
            switch (err) {
                error.PermissionDenied => try stderr.writeAll("error: permission denied. Run with sudo.\n"),
                error.InterfaceAlreadyExists => try stderr.writeAll("error: interface mg0 already exists. Run 'meshguard down' first.\n"),
                error.WireGuardModuleNotLoaded => try stderr.writeAll("error: WireGuard kernel module not loaded. Run 'modprobe wireguard'.\n"),
                else => try writeFormatted(stderr, "error: failed to create interface: {s}\n", .{@errorName(err)}),
            }
            std.process.exit(1);
        };
    } else {
        // Userspace mode: create TUN interface and configure IP via rtnetlink
        // TUN creation happens later in the event loop setup
    }

    try stdout.writeAll("  interface mg0 created and configured\n");

    // Bind gossip UDP socket
    const gossip_port: u16 = 51821;
    var gossip_socket = lib.net.Udp.UdpSocket.bind(gossip_port) catch {
        try stderr.writeAll("error: failed to bind gossip port 51821\n");
        lib.wireguard.Config.teardown(lib.wireguard.Config.DEFAULT_IFNAME) catch {};
        std.process.exit(1);
    };
    defer gossip_socket.close();

    try writeFormatted(stdout, "  gossip port: {d}\n", .{gossip_port});

    // Initialize membership table
    var membership = lib.discovery.Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();

    // Create WG event handler context
    var wg_handler_ctx = WgHandlerCtx{ .stdout = stdout, .membership = &membership, .socket = &gossip_socket };

    // Initialize SWIM protocol
    var swim = lib.discovery.Swim.SwimProtocol.init(
        &membership,
        gossip_socket,
        .{ .gossip_port = gossip_port },
        kp.public_key.toBytes(),
        wg_public_key,
        mesh_ip,
        51830,
        .{
            .ctx = @ptrCast(&wg_handler_ctx),
            .onPeerJoin = &wgOnPeerJoin,
            .onPeerDead = &wgOnPeerDead,
            .onPeerPunched = &wgOnPeerPunched,
        },
    );

    // Load authorized keys and enable trust enforcement
    const authorized_peers = lib.identity.Trust.loadAuthorizedKeys(allocator, config_dir) catch &.{};
    defer {
        for (authorized_peers) |peer| {
            allocator.free(peer.name);
        }
        allocator.free(authorized_peers);
    }
    if (authorized_peers.len > 0) {
        for (authorized_peers) |peer| {
            swim.addAuthorizedKey(peer.public_key.toBytes());
        }
        swim.enableTrust();
        try writeFormatted(stdout, "  trust: {d} authorized peer(s)\n", .{authorized_peers.len});
    }

    // Determine public endpoint: --announce overrides STUN
    if (announce_addr) |addr| {
        const announced_ep = messages.Endpoint{ .addr = addr, .port = gossip_port };
        swim.setPublicEndpoint(announced_ep, .public);
        var ann_ip_buf: [15]u8 = undefined;
        const ann_ip = lib.wireguard.Ip.formatIp(addr, &ann_ip_buf);
        try writeFormatted(stdout, "  announced endpoint: {s}:{d}\n", .{ ann_ip, gossip_port });
    } else {
        // Run STUN to discover our public endpoint and NAT type
        const Stun = lib.nat.Stun;
        try stdout.writeAll("  discovering public endpoint (STUN)...\n");
        const stun_result = Stun.discover(&gossip_socket, gossip_port, &Stun.DEFAULT_STUN_SERVERS);
        swim.setPublicEndpoint(
            if (stun_result.nat_type != .unknown) messages.Endpoint{ .addr = stun_result.external.addr, .port = stun_result.external.port } else null,
            stun_result.nat_type,
        );
        switch (stun_result.nat_type) {
            .public => {
                var pub_ip_buf: [15]u8 = undefined;
                const pub_ip = lib.wireguard.Ip.formatIp(stun_result.external.addr, &pub_ip_buf);
                try writeFormatted(stdout, "  public endpoint: {s}:{d} (no NAT)\n", .{ pub_ip, stun_result.external.port });
            },
            .cone => {
                var pub_ip_buf: [15]u8 = undefined;
                const pub_ip = lib.wireguard.Ip.formatIp(stun_result.external.addr, &pub_ip_buf);
                try writeFormatted(stdout, "  public endpoint: {s}:{d} (behind NAT, cone)\n", .{ pub_ip, stun_result.external.port });
            },
            .symmetric => try stdout.writeAll("  NAT type: symmetric (hole punching may fail)\n"),
            .unknown => try stdout.writeAll("  STUN: could not determine public endpoint\n"),
        }
    }

    // Seed initial peers
    if (seed_count > 0) {
        try writeFormatted(stdout, "  seeds: {d} peer(s)\n", .{seed_count});
        swim.seedPeers(seed_buf[0..seed_count]);
    }

    // Install SIGINT/SIGTERM handler for clean shutdown
    const swim_ptr = &swim;
    installSignalHandler(swim_ptr);

    // Run event loop
    if (use_kernel_wg) {
        // Kernel mode: SWIM owns the socket
        try stdout.writeAll("meshguard is running (kernel WG mode). Press Ctrl+C to stop.\n");
        swim.run() catch |err| {
            try writeFormatted(stderr, "error: gossip loop failed: {s}\n", .{@errorName(err)});
        };
    } else {
        // Userspace mode: multiplexed event loop with TUN
        try stdout.writeAll("meshguard is running (userspace WG mode). Press Ctrl+C to stop.\n");

        var wg_device = lib.wireguard.Device.WgDevice.init(wg_private_key, wg_public_key);
        wg_handler_ctx.wg_device = &wg_device;
        wg_handler_ctx.use_kernel = false;

        // Open TUN device
        var tun_dev = lib.net.Tun.TunDevice.open("mg0") catch |err| {
            try writeFormatted(stderr, "error: failed to open TUN device: {s}\n", .{@errorName(err)});
            try stderr.writeAll("  hint: run with sudo or set CAP_NET_ADMIN\n");
            std.process.exit(1);
        };
        defer tun_dev.close();

        // Configure TUN IP via rtnetlink
        const ifindex = lib.wireguard.RtNetlink.getInterfaceIndex("mg0") catch |err| {
            try writeFormatted(stderr, "error: failed to get TUN ifindex: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        lib.wireguard.RtNetlink.addAddress(ifindex, mesh_ip, 16) catch |err| {
            try writeFormatted(stderr, "error: failed to set TUN IP: {s}\n", .{@errorName(err)});
        };
        lib.wireguard.RtNetlink.setInterfaceUp(ifindex, true) catch |err| {
            try writeFormatted(stderr, "error: failed to bring up TUN: {s}\n", .{@errorName(err)});
        };

        // Set MTU to 1420 (1500 - 80 WG overhead) to prevent fragmentation
        tun_dev.setMtu(1420) catch |err| {
            try writeFormatted(stderr, "warning: failed to set MTU: {s}\n", .{@errorName(err)});
        };

        // Add mesh subnet route: 10.99.0.0/16 via mg0
        lib.wireguard.RtNetlink.addRoute(ifindex, .{ 10, 99, 0, 0 }, 16) catch |err| {
            try writeFormatted(stderr, "warning: failed to add mesh route: {s}\n", .{@errorName(err)});
        };

        try writeFormatted(stdout, "  TUN device: {s} (fd={d}, mtu=1420)\n", .{ tun_dev.getName(), tun_dev.fd });

        // Run multiplexed event loop
        userspaceEventLoop(&swim, &wg_device, &gossip_socket, tun_dev, stdout) catch |err| {
            try writeFormatted(stderr, "error: event loop failed: {s}\n", .{@errorName(err)});
        };
    }

    // Cleanup
    try stdout.writeAll("\nmeshguard stopping...\n");
    if (use_kernel_wg) {
        lib.wireguard.Config.teardown(lib.wireguard.Config.DEFAULT_IFNAME) catch {};
    }
    try stdout.writeAll("meshguard stopped.\n");
}

// ─── Signal handling ───

var g_swim_stop: ?*lib.discovery.Swim.SwimProtocol = null;

fn signalHandler(sig: i32) callconv(.c) void {
    _ = sig;
    if (g_swim_stop) |swim_ref| {
        swim_ref.stop();
    }
}

fn installSignalHandler(swim_ref: *lib.discovery.Swim.SwimProtocol) void {
    g_swim_stop = swim_ref;

    const sa: posix.Sigaction = .{
        .handler = .{ .handler = &signalHandler },
        .mask = .{0} ** @typeInfo(@TypeOf(@as(posix.Sigaction, undefined).mask)).array.len,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &sa, null);
    posix.sigaction(posix.SIG.TERM, &sa, null);
}

const WgHandlerCtx = struct {
    stdout: std.fs.File,
    membership: *lib.discovery.Membership.MembershipTable,
    wg_device: ?*lib.wireguard.Device.WgDevice = null,
    socket: ?*lib.net.Udp.UdpSocket = null,
    use_kernel: bool = true,
};

fn wgOnPeerJoin(ctx: *anyopaque, peer: *const lib.discovery.Membership.Peer) void {
    const handler: *WgHandlerCtx = @ptrCast(@alignCast(ctx));

    if (peer.wg_pubkey) |wg_key| {
        var ip_buf: [15]u8 = undefined;
        const ip_str = lib.wireguard.Ip.formatIp(peer.mesh_ip, &ip_buf);

        if (handler.use_kernel) {
            // Kernel mode: configure via netlink
            const endpoint_addr: ?[4]u8 = if (peer.nat_type == .public) blk: {
                break :blk if (peer.gossip_endpoint) |ep|
                    ep.addr
                else if (peer.public_endpoint) |pub_ep|
                    pub_ep.addr
                else
                    null;
            } else null;

            lib.wireguard.Config.addPeer(lib.wireguard.Config.DEFAULT_IFNAME, .{
                .public_key = wg_key,
                .endpoint_addr = endpoint_addr,
                .endpoint_port = if (endpoint_addr != null) peer.wg_port else 0,
                .allowed_ips = &.{.{ .addr = peer.mesh_ip, .cidr = 32 }},
                .persistent_keepalive = 25,
            }) catch {
                writeFormatted(handler.stdout, "  warning: failed to add WG peer {s}\n", .{ip_str}) catch {};
                return;
            };
        } else if (handler.wg_device) |dev| {
            // Userspace mode: register peer in WgDevice
            const peer_addr = if (peer.gossip_endpoint) |ep| ep.addr else if (peer.public_endpoint) |pub_ep| pub_ep.addr else [4]u8{ 0, 0, 0, 0 };
            const peer_port = if (peer.gossip_endpoint) |ep| ep.port else if (peer.public_endpoint) |pub_ep| pub_ep.port else @as(u16, 0);

            // Pass peer.mesh_ip as allowed_ip to enable O(1) lookup
            const slot = dev.addPeer(peer.pubkey, wg_key, peer.mesh_ip, peer_addr, peer_port) catch {
                writeFormatted(handler.stdout, "  warning: failed to add userspace WG peer {s}\n", .{ip_str}) catch {};
                return;
            };

            // Initiate handshake if we have an endpoint
            if (peer_addr[0] != 0 or peer_addr[1] != 0 or peer_addr[2] != 0 or peer_addr[3] != 0) {
                if (dev.initiateHandshake(slot)) |init_msg| {
                    // Send handshake initiation via UDP socket
                    if (handler.socket) |sock| {
                        const msg_bytes = std.mem.asBytes(&init_msg);
                        _ = sock.sendTo(msg_bytes, peer_addr, peer_port) catch 0;
                    }
                    writeFormatted(handler.stdout, "  peer joined (userspace): {s} [handshake sent]\n", .{ip_str}) catch {};
                } else |_| {
                    writeFormatted(handler.stdout, "  peer joined (userspace): {s} [handshake pending]\n", .{ip_str}) catch {};
                }
            } else {
                writeFormatted(handler.stdout, "  peer joined (userspace): {s} [awaiting endpoint]\n", .{ip_str}) catch {};
            }
            return;
        }

        writeFormatted(handler.stdout, "  peer joined: {s}\n", .{ip_str}) catch {};
    }
}

fn wgOnPeerDead(ctx: *anyopaque, pubkey: [32]u8) void {
    const handler: *WgHandlerCtx = @ptrCast(@alignCast(ctx));

    if (handler.use_kernel) {
        if (handler.membership.peers.get(pubkey)) |peer| {
            if (peer.wg_pubkey) |wg_key| {
                lib.wireguard.Config.removePeer(lib.wireguard.Config.DEFAULT_IFNAME, wg_key) catch {};
            }
        }
    } else if (handler.wg_device) |dev| {
        // Userspace mode: remove from WgDevice
        if (handler.membership.peers.get(pubkey)) |peer| {
            if (peer.wg_pubkey) |wg_key| {
                dev.removePeer(wg_key);
            }
        }
    }
    writeFormatted(handler.stdout, "  peer removed\n", .{}) catch {};
}

fn wgOnPeerPunched(ctx: *anyopaque, peer: *const lib.discovery.Membership.Peer, endpoint: @import("protocol/messages.zig").Endpoint) void {
    const handler: *WgHandlerCtx = @ptrCast(@alignCast(ctx));

    if (peer.wg_pubkey) |wg_key| {
        var ip_buf: [15]u8 = undefined;
        const ip_str = lib.wireguard.Ip.formatIp(peer.mesh_ip, &ip_buf);

        if (handler.use_kernel) {
            lib.wireguard.Config.addPeer(lib.wireguard.Config.DEFAULT_IFNAME, .{
                .public_key = wg_key,
                .endpoint_addr = endpoint.addr,
                .endpoint_port = peer.wg_port,
                .allowed_ips = &.{.{ .addr = peer.mesh_ip, .cidr = 32 }},
                .persistent_keepalive = 25,
            }) catch {
                writeFormatted(handler.stdout, "  warning: failed to update WG peer after punch\n", .{}) catch {};
                return;
            };
        } else if (handler.wg_device) |dev| {
            // Userspace mode: update peer endpoint
            if (dev.findByWgPubkey(wg_key)) |slot| {
                if (dev.peers[slot]) |*p| {
                    p.endpoint_addr = endpoint.addr;
                    p.endpoint_port = endpoint.port;
                }
            }
        }

        writeFormatted(handler.stdout, "  peer punched: {s} (direct connection established)\n", .{ip_str}) catch {};
    }
}

/// Userspace multiplexed event loop.
/// Polls both the UDP socket (for WG/SWIM/STUN) and the TUN device (for outgoing IP).
fn userspaceEventLoop(
    swim: *lib.discovery.Swim.SwimProtocol,
    wg_dev: *lib.wireguard.Device.WgDevice,
    udp_sock: *lib.net.Udp.UdpSocket,
    tun_dev: lib.net.Tun.TunDevice,
    stdout: std.fs.File,
) !void {
    const Device = lib.wireguard.Device;

    // Set TUN to non-blocking for poll
    var tun_mut = tun_dev;
    try tun_mut.setNonBlocking();

    var recv_buf: [1500]u8 = undefined;
    var tun_buf: [1500]u8 = undefined;
    var encrypt_buf: [1600]u8 = undefined; // MTU + WG overhead

    while (swim.running.load(.acquire)) {
        // Poll both fds with 50ms timeout
        var fds = [_]posix.pollfd{
            .{ .fd = udp_sock.fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = tun_dev.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = posix.poll(&fds, 50) catch continue;

        // ── Handle incoming UDP packets ──
        if (fds[0].revents & posix.POLL.IN != 0) {
            while (true) {
                const result = udp_sock.recvFrom(&recv_buf) catch break;
                if (result == null) break;
                const recv = result.?;

                switch (Device.PacketType.classify(recv.data)) {
                    .wg_handshake_init => {
                        // Someone is initiating a handshake with us
                        if (recv.data.len >= @sizeOf(lib.wireguard.Noise.HandshakeInitiation)) {
                            const msg: *const lib.wireguard.Noise.HandshakeInitiation = @ptrCast(@alignCast(recv.data.ptr));
                            if (wg_dev.handleInitiation(msg)) |hs_result| {
                                // Send response back
                                const resp_bytes = std.mem.asBytes(&hs_result.response);
                                _ = udp_sock.sendTo(resp_bytes, recv.sender_addr, recv.sender_port) catch 0;
                                writeFormatted(stdout, "  WG handshake: responded to initiation\n", .{}) catch {};
                            } else |_| {}
                        }
                    },
                    .wg_handshake_resp => {
                        // Response to our handshake initiation
                        if (recv.data.len >= @sizeOf(lib.wireguard.Noise.HandshakeResponse)) {
                            const msg: *const lib.wireguard.Noise.HandshakeResponse = @ptrCast(@alignCast(recv.data.ptr));
                            if (wg_dev.handleResponse(msg)) |slot| {
                                // Update peer endpoint from where the response came from
                                if (wg_dev.peers[slot]) |*p| {
                                    p.endpoint_addr = recv.sender_addr;
                                    p.endpoint_port = recv.sender_port;
                                }
                                writeFormatted(stdout, "  WG handshake: completed with peer\n", .{}) catch {};
                            } else |_| {}
                        }
                    },
                    .wg_transport => {
                        // Encrypted data packet — decrypt and write to TUN
                        var decrypt_buf: [1500]u8 = undefined;
                        if (wg_dev.decryptTransport(recv.data, &decrypt_buf)) |result2| {
                            tun_mut.write(decrypt_buf[0..result2.len]) catch {};
                        } else |_| {}
                    },
                    .wg_cookie => {
                        // Cookie reply — ignore for now
                    },
                    .stun => {
                        // STUN response — feed to SWIM (it handles STUN internally)
                        swim.feedPacket(recv.data, recv.sender_addr, recv.sender_port);
                    },
                    .swim => {
                        // SWIM gossip — feed to SWIM protocol
                        swim.feedPacket(recv.data, recv.sender_addr, recv.sender_port);
                    },
                    .unknown => {},
                }
            }
        }

        // ── Handle outgoing IP packets from TUN ──
        if (fds[1].revents & posix.POLL.IN != 0) {
            while (true) {
                const n = tun_mut.read(&tun_buf) catch break;
                if (n == 0) break;

                const ip_packet = tun_buf[0..n];

                // Extract destination IP from IP header (bytes 16-19 in IPv4)
                if (n < 20) continue;
                const dst_ip: [4]u8 = ip_packet[16..20].*;

                // Look up destination peer by mesh IP and encrypt
                // Optimization: use O(1) WgDevice lookup instead of scanning SWIM membership
                const target_slot = wg_dev.findByAllowedIp(dst_ip);
                if (target_slot) |slot| {
                    if (wg_dev.encryptForPeer(slot, ip_packet, &encrypt_buf)) |enc_len| {
                        const peer = &(wg_dev.peers[slot].?);
                        if (peer.endpoint_addr[0] != 0) {
                            _ = udp_sock.sendTo(encrypt_buf[0..enc_len], peer.endpoint_addr, peer.endpoint_port) catch 0;
                        }
                    } else |_| {}
                }
            }
        }

        // ── Run SWIM timers (gossip probes, expiry, hole punch) ──
        swim.tickTimersOnly();
    }
}

/// Parse a dotted-decimal IPv4 address like "1.2.3.4" into [4]u8.
fn parseIpv4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet: u16 = 0;
    var dots: u8 = 0;

    for (s) |c| {
        if (c == '.') {
            if (octet > 255) return null;
            result[dots] = @intCast(octet);
            dots += 1;
            if (dots > 3) return null;
            octet = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
        } else {
            return null;
        }
    }

    if (dots != 3 or octet > 255) return null;
    result[3] = @intCast(octet);
    return result;
}

fn cmdDown(allocator: std.mem.Allocator) !void {
    _ = allocator;
    const stdout = getStdOut();
    const stderr = getStdErr();

    lib.wireguard.Config.teardown(lib.wireguard.Config.DEFAULT_IFNAME) catch |err| {
        switch (err) {
            error.SocketCreateFailed => try stderr.writeAll("error: permission denied. Run with sudo.\n"),
            error.NetlinkError => try stderr.writeAll("error: interface mg0 not found.\n"),
            else => try writeFormatted(stderr, "error: {s}\n", .{@errorName(err)}),
        }
        std.process.exit(1);
    };

    try stdout.writeAll("meshguard stopped. Interface mg0 removed.\n");
}

fn cmdStatus(allocator: std.mem.Allocator) !void {
    _ = allocator;
    // TODO: Phase 2 — query running daemon for mesh status
    // For now, check if mg0 exists
    const stdout = getStdOut();
    const stderr = getStdErr();

    const ifindex = lib.wireguard.RtNetlink.getInterfaceIndex("mg0") catch {
        try stderr.writeAll("meshguard is not running (no mg0 interface).\n");
        std.process.exit(1);
    };

    try writeFormatted(stdout, "meshguard is running.\n  interface: mg0 (index {d})\n", .{ifindex});
}
