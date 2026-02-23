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
    \\  trust --org Trust an organization's public key
    \\  revoke      Revoke a peer's public key
    \\  export      Print this node's public key
    \\  org-keygen  Generate a new org keypair
    \\  org-sign    Sign a node's key with org key (--name <label>)
    \\  version     Print version
    \\
    \\OPTIONS:
    \\  --config <path>     Path to config file
    \\  --seed <host:port>   Seed peer (IP or hostname, can be repeated)
    \\  --dns <domain>       Discover seeds via DNS TXT records
    \\  --mdns               Discover seeds via mDNS on LAN
    \\  --announce <ip>      Override public IP (skip STUN)
    \\  --kernel             Use kernel WireGuard (requires root)
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

    if (std.mem.eql(u8, command, "org-keygen")) {
        try cmdOrgKeygen(allocator);
        return;
    }

    if (std.mem.eql(u8, command, "org-sign")) {
        if (args.len < 3) {
            try getStdErr().writeAll("error: 'org-sign' requires a node public key or .pub file\n");
            std.process.exit(1);
        }
        try cmdOrgSign(allocator, args[2], args[3..]);
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

    // Check for --org flag first
    var is_org = false;
    var peer_name: ?[]const u8 = null;
    var i: usize = 0;
    while (i < extra_args.len) : (i += 1) {
        if (std.mem.eql(u8, extra_args[i], "--org")) {
            is_org = true;
        } else if (std.mem.eql(u8, extra_args[i], "--name")) {
            if (i + 1 < extra_args.len) {
                peer_name = extra_args[i + 1];
                i += 1;
            } else {
                try getStdErr().writeAll("error: --name requires a value\n");
                std.process.exit(1);
            }
        }
    }

    if (is_org) {
        return cmdTrustOrg(allocator, config_dir, key_or_path, peer_name);
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

/// Trust an org public key — auto-accept nodes signed by this org.
fn cmdTrustOrg(allocator: std.mem.Allocator, config_dir: []const u8, key_or_path: []const u8, name_override: ?[]const u8) !void {
    const stdout = getStdOut();
    const stderr = getStdErr();
    const Org = lib.identity.Org;

    // Validate the key
    var key_b64_buf: [44]u8 = undefined;
    var pk_bytes: [32]u8 = undefined;
    if (lib.identity.Trust.validateKey(key_or_path, &key_b64_buf, &pk_bytes)) |err_msg| {
        try writeFormatted(stderr, "error: {s}\n", .{err_msg});
        std.process.exit(1);
    }

    const key_b64: []const u8 = blk: {
        for (key_b64_buf, 0..) |c, idx| {
            if (c == 0) break :blk key_b64_buf[0..idx];
        }
        break :blk &key_b64_buf;
    };

    // Derive deterministic domain for the name
    const domain = Org.deriveOrgDomain(pk_bytes);
    const name = name_override orelse &domain;

    try lib.identity.Trust.addTrustedOrg(allocator, config_dir, key_b64, name);
    try writeFormatted(stdout, "Org '{s}' trusted (domain: {s}.mesh).\n", .{ name, domain });
    try writeFormatted(stdout, "Nodes signed by this org will be auto-accepted.\n", .{});
}

/// Generate an org Ed25519 keypair.
fn cmdOrgKeygen(allocator: std.mem.Allocator) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    const stdout = getStdOut();
    const stderr = getStdErr();
    const Org = lib.identity.Org;

    // Check if org key already exists
    const org_key_path = try std.fs.path.join(allocator, &.{ config_dir, "org", "org.key" });
    defer allocator.free(org_key_path);

    if (std.fs.accessAbsolute(org_key_path, .{})) |_| {
        try stderr.writeAll("error: org keypair already exists. Use --force to overwrite.\n");
        std.process.exit(1);
    } else |_| {}

    const kp = Org.generateOrgKeyPair();
    try Org.saveOrgKeyPair(allocator, config_dir, kp);

    var pk_buf: [44]u8 = undefined;
    const pk_b64 = std.base64.standard.Encoder.encode(&pk_buf, &kp.public_key.toBytes());
    const domain = Org.deriveOrgDomain(kp.public_key.toBytes());

    try writeFormatted(stdout, "Org keypair generated.\n", .{});
    try writeFormatted(stdout, "  public key: {s}\n", .{pk_b64});
    try writeFormatted(stdout, "  domain:     {s}.mesh\n", .{domain});
    try writeFormatted(stdout, "\nShare the public key with peers who should trust your org.\n", .{});
    try writeFormatted(stdout, "Sign nodes with: meshguard org-sign <node.pub> --name <label>\n", .{});
}

/// Sign a node's public key with the org private key, producing a NodeCertificate.
fn cmdOrgSign(allocator: std.mem.Allocator, node_key_path: []const u8, extra_args: []const []const u8) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    const stdout = getStdOut();
    const stderr = getStdErr();
    const Org = lib.identity.Org;

    // Parse --name and --expires from extra args
    var node_name: []const u8 = "node";
    var expires_at: i64 = 0; // default: never
    var j: usize = 0;
    while (j < extra_args.len) : (j += 1) {
        if (std.mem.eql(u8, extra_args[j], "--name")) {
            if (j + 1 < extra_args.len) {
                node_name = extra_args[j + 1];
                j += 1;
            }
        } else if (std.mem.eql(u8, extra_args[j], "--expires")) {
            if (j + 1 < extra_args.len) {
                expires_at = std.fmt.parseInt(i64, extra_args[j + 1], 10) catch 0;
                j += 1;
            }
        }
    }

    // Load org keypair
    const org_kp = Org.loadOrgKeyPair(allocator, config_dir) catch {
        try stderr.writeAll("error: no org keypair found. Run 'meshguard org-keygen' first.\n");
        std.process.exit(1);
    };

    // Validate node key
    var key_b64_buf: [44]u8 = undefined;
    var node_pk_bytes: [32]u8 = undefined;
    if (lib.identity.Trust.validateKey(node_key_path, &key_b64_buf, &node_pk_bytes)) |err_msg| {
        try writeFormatted(stderr, "error: {s}\n", .{err_msg});
        std.process.exit(1);
    }

    // Issue certificate
    const cert = Org.issueCertificate(org_kp, node_pk_bytes, node_name, expires_at) catch {
        try stderr.writeAll("error: failed to sign certificate\n");
        std.process.exit(1);
    };

    // Save certificate
    const cert_filename = try std.fmt.allocPrint(allocator, "{s}.cert", .{node_name});
    defer allocator.free(cert_filename);

    const cert_path = try std.fs.path.join(allocator, &.{ config_dir, cert_filename });
    defer allocator.free(cert_path);

    try Org.saveCertificate(allocator, cert_path, &cert);

    const domain = Org.deriveOrgDomain(org_kp.public_key.toBytes());
    try writeFormatted(stdout, "Certificate signed for '{s}'.\n", .{node_name});
    try writeFormatted(stdout, "  mesh domain: {s}.{s}.mesh\n", .{ node_name, domain });
    try writeFormatted(stdout, "  saved to:    {s}\n", .{cert_path});
    if (expires_at == 0) {
        try stdout.writeAll("  expires:     never\n");
    } else {
        try writeFormatted(stdout, "  expires:     {d}\n", .{expires_at});
    }
    try writeFormatted(stdout, "\nCopy this file to the node as: ~/.config/meshguard/node.cert\n", .{});
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

    // Parse --seed, --announce, --kernel, --dns, --mdns, and --encrypt-workers arguments
    const messages = @import("protocol/messages.zig");
    var seed_buf: [16]messages.Endpoint = undefined;
    var seed_count: usize = 0;
    var announce_addr: ?[4]u8 = null;
    var use_kernel_wg: bool = false;
    var dns_domain: []const u8 = "";
    var use_mdns: bool = false;
    var encrypt_workers: usize = 0; // 0 = auto (CPU count)
    // Collect raw seed strings for hostname resolution
    var seed_strs: [16][]const u8 = undefined;
    var seed_str_count: usize = 0;
    {
        var i: usize = 0;
        while (i < extra_args.len) : (i += 1) {
            if (std.mem.eql(u8, extra_args[i], "--seed") and i + 1 < extra_args.len) {
                i += 1;
                if (seed_str_count < seed_strs.len) {
                    seed_strs[seed_str_count] = extra_args[i];
                    seed_str_count += 1;
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
            } else if (std.mem.eql(u8, extra_args[i], "--dns") and i + 1 < extra_args.len) {
                i += 1;
                dns_domain = extra_args[i];
            } else if (std.mem.eql(u8, extra_args[i], "--mdns")) {
                use_mdns = true;
            } else if (std.mem.eql(u8, extra_args[i], "--encrypt-workers") and i + 1 < extra_args.len) {
                i += 1;
                encrypt_workers = std.fmt.parseInt(usize, extra_args[i], 10) catch 0;
            }
        }
    }

    // Resolve seeds (static + DNS TXT + mDNS)
    const has_discovery = dns_domain.len > 0 or use_mdns;
    if (has_discovery) {
        const resolved = lib.discovery.Seed.resolveSeeds(
            allocator,
            seed_strs[0..seed_str_count],
            dns_domain,
            use_mdns,
        ) catch &.{};
        defer if (resolved.len > 0) allocator.free(resolved);

        for (resolved) |ep| {
            if (seed_count < seed_buf.len) {
                seed_buf[seed_count] = ep;
                seed_count += 1;
            }
        }
    } else {
        // No DNS/mDNS — parse static seeds directly (fast path, no allocator)
        for (seed_strs[0..seed_str_count]) |seed_str| {
            if (lib.discovery.Seed.parseEndpoint(seed_str)) |ep| {
                if (seed_count < seed_buf.len) {
                    seed_buf[seed_count] = ep;
                    seed_count += 1;
                }
            } else {
                try writeFormatted(stderr, "warning: ignoring invalid seed '{s}'\n", .{seed_str});
            }
        }
    }
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

        // Enable GSO/GRO offloads for large packet coalescing
        tun_dev.enableOffload();
        if (tun_dev.vnet_hdr) {
            try stdout.writeAll("  GSO/GRO offloads: enabled (IFF_VNET_HDR)\n");
        } else {
            try stdout.writeAll("  GSO/GRO offloads: disabled (fallback to single-packet)\n");
        }

        // Run multiplexed event loop
        userspaceEventLoop(&swim, &wg_device, &gossip_socket, tun_dev, stdout, encrypt_workers) catch |err| {
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
        swim_ref.broadcastLeave();
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

            const slot = dev.addPeerWithMeshIp(peer.pubkey, wg_key, peer_addr, peer_port, peer.mesh_ip) catch {
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

/// Maximum data-plane worker threads (TUN readers + encrypt workers combined).
const MAX_WORKERS: usize = 8;
const MAX_ENCRYPT_WORKERS: usize = 16;

// ── Zero-copy parallel encryption pipeline ──────────────────────────────

/// Stage 1: TUN reader pipeline — reads from TUN, builds PacketBatches per-peer,
/// assigns nonces in bulk, pushes batch indices to CryptoQueue + PeerTxRing.
/// Does NOT encrypt — leaves that to the crypto workers.
fn tunReaderPipeline(
    running: *const std.atomic.Value(bool),
    wg_dev: *lib.wireguard.Device.WgDevice,
    tun_fd: posix.fd_t,
    vnet_hdr: bool,
    pool: *lib.net.Pipeline.DataPlanePool,
    crypto_q: *lib.net.Pipeline.CryptoQueue,
) void {
    const Offload = lib.net.Offload;
    const MAX_PEERS = lib.wireguard.Device.MAX_PEERS;

    var tun_buf: [Offload.VNET_HDR_LEN + 65535]u8 = undefined;
    // Per-peer batch building: thread-local staging
    var local_batches: [MAX_PEERS]?u16 = .{null} ** MAX_PEERS;

    // Thread-local buffer cache to avoid per-packet mutex contention
    const BUF_CACHE_SIZE: usize = 128;
    var buf_cache: [BUF_CACHE_SIZE]u16 = undefined;
    var buf_cache_count: usize = 0;

    // GSO segment buffers
    var seg_bufs: [64][1500]u8 = undefined;
    var seg_slices: [64][]u8 = undefined;
    for (0..64) |i| {
        seg_slices[i] = &seg_bufs[i];
    }

    while (running.load(.acquire)) {
        var fds = [_]posix.pollfd{
            .{ .fd = tun_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = posix.poll(&fds, 50) catch continue;

        if (fds[0].revents & posix.POLL.IN == 0) continue;

        // Track which peers have partial batches to flush
        var touched_peers: [MAX_PEERS]bool = .{false} ** MAX_PEERS;

        // Drain available packets
        while (true) {
            const n = posix.read(tun_fd, &tun_buf) catch break;
            if (n == 0) break;

            if (vnet_hdr) {
                if (n <= Offload.VNET_HDR_LEN) continue;
                const vhdr: *const Offload.VirtioNetHdr = @ptrCast(@alignCast(&tun_buf));
                const ip_data = tun_buf[Offload.VNET_HDR_LEN..n];

                if (vhdr.gso_type != Offload.GSO_NONE) {
                    // GSO super-packet — split and stage each segment
                    var seg_sizes: [64]usize = undefined;
                    const seg_count = Offload.gsoSplit(
                        vhdr.*,
                        ip_data,
                        &seg_slices,
                        &seg_sizes,
                        64,
                    );
                    for (0..seg_count) |s| {
                        stageSegment(wg_dev, pool, crypto_q, seg_bufs[s][0..seg_sizes[s]], &local_batches, &touched_peers, &buf_cache, &buf_cache_count);
                    }
                } else {
                    if (ip_data.len < 20) continue;
                    const mutable_data = tun_buf[Offload.VNET_HDR_LEN..n];
                    Offload.completeChecksum(vhdr.*, mutable_data);
                    stageSegment(wg_dev, pool, crypto_q, mutable_data, &local_batches, &touched_peers, &buf_cache, &buf_cache_count);
                }
            } else {
                if (n < 20) continue;
                stageSegment(wg_dev, pool, crypto_q, tun_buf[0..n], &local_batches, &touched_peers, &buf_cache, &buf_cache_count);
            }
        }

        // Flush partial batches for all touched peers (bound latency)
        for (0..MAX_PEERS) |slot| {
            if (touched_peers[slot]) {
                if (local_batches[slot]) |batch_idx| {
                    dispatchBatch(wg_dev, pool, crypto_q, @intCast(slot), batch_idx);
                    local_batches[slot] = null;
                }
            }
        }
    }
}

/// Stage a single IP segment into the per-peer batch.
fn stageSegment(
    wg_dev: *lib.wireguard.Device.WgDevice,
    pool: *lib.net.Pipeline.DataPlanePool,
    crypto_q: *lib.net.Pipeline.CryptoQueue,
    ip_packet: []const u8,
    local_batches: *[lib.wireguard.Device.MAX_PEERS]?u16,
    touched_peers: *[lib.wireguard.Device.MAX_PEERS]bool,
    buf_cache: *[128]u16,
    buf_cache_count: *usize,
) void {
    const Pipeline = lib.net.Pipeline;
    if (ip_packet.len < 20 or ip_packet.len > 1500) return;

    const dst_ip: [4]u8 = ip_packet[16..20].*;
    const peer_slot = wg_dev.lookupByMeshIp(dst_ip) orelse return;
    const peer = wg_dev.peers[peer_slot] orelse return;
    if (peer.endpoint_addr[0] == 0) return;

    // Allocate or reuse batch for this peer
    if (local_batches[peer_slot] == null) {
        local_batches[peer_slot] = pool.allocBatch() orelse return; // drop if OOM
    }

    const batch_idx = local_batches[peer_slot].?;
    var batch = &pool.batches[batch_idx];

    // Thread-local buffer cache: refill in bulk when empty
    if (buf_cache_count.* == 0) {
        buf_cache_count.* = pool.allocBufferBatch(buf_cache);
        if (buf_cache_count.* == 0) return; // pool exhausted, drop
    }

    // Pop from local cache (zero contention)
    buf_cache_count.* -= 1;
    const buf_idx = buf_cache[buf_cache_count.*];
    var pkt = &pool.buffers[buf_idx];

    // ZERO-COPY: write IP payload at offset 16, leaving room for WG transport header
    @memcpy(pkt.data[Pipeline.WG_HEADER_LEN..][0..ip_packet.len], ip_packet);
    pkt.len = @intCast(ip_packet.len);
    pkt.endpoint_addr = peer.endpoint_addr;
    pkt.endpoint_port = peer.endpoint_port;

    // Add to batch
    batch.buf_indices[batch.count] = buf_idx;
    batch.lengths[batch.count] = @intCast(ip_packet.len);
    batch.count += 1;
    touched_peers[peer_slot] = true;

    // If batch is full, dispatch immediately
    if (batch.count >= Pipeline.BATCH_SIZE) {
        dispatchBatch(wg_dev, pool, crypto_q, @intCast(peer_slot), batch_idx);
        local_batches[peer_slot] = null;
    }
}

/// Dispatch a complete batch: assign nonces, push to CryptoQueue + PeerTxRing.
fn dispatchBatch(
    wg_dev: *lib.wireguard.Device.WgDevice,
    pool: *lib.net.Pipeline.DataPlanePool,
    crypto_q: *lib.net.Pipeline.CryptoQueue,
    peer_slot: u16,
    batch_idx: u16,
) void {
    const Pipeline = lib.net.Pipeline;
    var peer = &(wg_dev.peers[peer_slot] orelse return);
    var batch = &pool.batches[batch_idx];
    batch.peer_slot = peer_slot;

    const tun = &(peer.active_tunnel orelse {
        // No active tunnel — return resources
        var i: usize = 0;
        while (i < batch.count) : (i += 1) {
            pool.freeBuffers(&.{batch.buf_indices[i]});
        }
        pool.freeBatch(batch_idx);
        return;
    });

    // 1. Lock per-peer push_lock briefly for nonce assignment + ring insertion
    peer.tx_ring.push_lock.lock();

    // Bulk nonce assignment: fetchAdd(count) claims a contiguous block
    const start_nonce = tun.send_counter.fetchAdd(batch.count, .monotonic);
    for (0..batch.count) |i| {
        batch.nonces[i] = start_nonce + i;
    }

    // Push batch index into per-peer TxRing (maintains nonce ordering)
    peer.tx_ring.push(batch_idx);

    peer.tx_ring.push_lock.unlock();

    // 2. Mark batch as Encrypting and dispatch to crypto workers
    batch.state.store(@intFromEnum(Pipeline.BatchState.Encrypting), .release);
    crypto_q.push(batch_idx);
}

/// Stage 2 + Opportunistic Stage 3: Crypto worker + Tx flusher.
/// Pops batches from CryptoQueue, encrypts all packets in-place (zero-copy via pool indices),
/// marks batch Ready, then tries to acquire peer's send_lock to flush Ready batches in order.
fn cryptoWorkerPipeline(
    running: *const std.atomic.Value(bool),
    wg_dev: *lib.wireguard.Device.WgDevice,
    udp_fd: posix.fd_t,
    pool: *lib.net.Pipeline.DataPlanePool,
    crypto_q: *lib.net.Pipeline.CryptoQueue,
) void {
    const Pipeline = lib.net.Pipeline;

    while (running.load(.acquire)) {
        const batch_idx = crypto_q.pop() orelse break; // null = closed
        var batch = &pool.batches[batch_idx];
        var peer = &(wg_dev.peers[batch.peer_slot] orelse continue);
        var tun = &(peer.active_tunnel orelse continue);

        // STAGE 2: Encrypt all packets in-place (100% cache-local, no locks)
        for (0..batch.count) |i| {
            var pkt = &pool.buffers[batch.buf_indices[i]];
            if (tun.encryptPreassigned(&pkt.data, batch.lengths[i], batch.nonces[i])) |enc_len| {
                pkt.len = @intCast(enc_len);
            } else {
                pkt.len = 0; // mark as failed
            }
        }

        // Mark batch as Ready for sequential sending
        batch.state.store(@intFromEnum(Pipeline.BatchState.Ready), .release);

        // STAGE 3: Opportunistic Tx flush
        // If another crypto worker is already sending for this peer, tryLock fails
        // and we safely go back to encrypting. They will drain our Ready batch.
        if (!peer.tx_ring.send_lock.tryLock()) continue;
        defer peer.tx_ring.send_lock.unlock();

        flushPeerTxRing(peer, pool, udp_fd);
    }
}

/// Drain all Ready batches from a peer's TxRing in strict nonce order.
/// Called while holding peer.tx_ring.send_lock.
/// Uses UDP GSO (sendmsg with UDP_SEGMENT cmsg) to send all encrypted packets
/// for this peer in a single syscall — ~45x fewer syscalls than sendmmsg.
fn flushPeerTxRing(
    peer: *lib.wireguard.Device.WgPeer,
    pool: *lib.net.Pipeline.DataPlanePool,
    udp_fd: posix.fd_t,
) void {
    const Pipeline = lib.net.Pipeline;
    const BatchUdp = lib.net.BatchUdp;
    var gso_tx = BatchUdp.GSOSender{};

    while (!peer.tx_ring.isEmpty()) {
        const head_idx = peer.tx_ring.peekHead();
        var head_batch = &pool.batches[head_idx];

        // Strict ROB: if next sequential batch isn't Ready, stop!
        if (head_batch.state.load(.acquire) != @intFromEnum(Pipeline.BatchState.Ready)) break;

        // Pack encrypted packets into GSO buffer for single sendmsg
        for (0..head_batch.count) |i| {
            const pkt = &pool.buffers[head_batch.buf_indices[i]];
            if (pkt.len > 0) {
                if (!gso_tx.append(pkt.data[0..pkt.len])) {
                    // GSO buffer full — flush and start a new one
                    _ = gso_tx.sendGSO(udp_fd, peer.endpoint_addr, peer.endpoint_port);
                    gso_tx.reset();
                    _ = gso_tx.append(pkt.data[0..pkt.len]);
                }
            }
        }

        // Bulk-free all buffer indices from this batch (single lock acquisition)
        pool.freeBuffers(head_batch.buf_indices[0..head_batch.count]);
        head_batch.state.store(@intFromEnum(Pipeline.BatchState.Empty), .release);
        pool.freeBatch(head_idx);

        peer.tx_ring.advanceHead();
    }

    // Flush remaining GSO buffer
    if (gso_tx.used > 0) {
        _ = gso_tx.sendGSO(udp_fd, peer.endpoint_addr, peer.endpoint_port);
    }
}

/// Legacy data-plane worker: reads TUN, encrypts, sends UDP (serial).
/// Used only when encrypt_workers == 0 (legacy mode).
fn dataPlaneWorker(
    running: *const std.atomic.Value(bool),
    wg_dev: *lib.wireguard.Device.WgDevice,
    tun_fd: posix.fd_t,
    udp_fd: posix.fd_t,
    vnet_hdr: bool,
) void {
    const BatchUdp = lib.net.BatchUdp;
    const Offload = lib.net.Offload;

    var tx = BatchUdp.BatchSender{};
    var tun_buf: [Offload.VNET_HDR_LEN + 65535]u8 = undefined;
    var encrypt_bufs: [BatchUdp.BATCH_SIZE][1600]u8 = undefined;
    var seg_bufs: [BatchUdp.BATCH_SIZE][1500]u8 = undefined;
    var seg_slices: [BatchUdp.BATCH_SIZE][]u8 = undefined;
    for (0..BatchUdp.BATCH_SIZE) |i| {
        seg_slices[i] = &seg_bufs[i];
    }

    while (running.load(.acquire)) {
        var fds = [_]posix.pollfd{
            .{ .fd = tun_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = posix.poll(&fds, 50) catch continue;

        if (fds[0].revents & posix.POLL.IN != 0) {
            tx.reset();
            var send_idx: usize = 0;

            while (send_idx < BatchUdp.BATCH_SIZE) {
                const n = posix.read(tun_fd, &tun_buf) catch break;
                if (n == 0) break;

                if (vnet_hdr) {
                    if (n <= Offload.VNET_HDR_LEN) continue;
                    const vhdr: *const Offload.VirtioNetHdr = @ptrCast(@alignCast(&tun_buf));
                    const ip_data = tun_buf[Offload.VNET_HDR_LEN..n];

                    if (vhdr.gso_type != Offload.GSO_NONE) {
                        var seg_sizes: [BatchUdp.BATCH_SIZE]usize = undefined;
                        const seg_count = Offload.gsoSplit(
                            vhdr.*,
                            ip_data,
                            &seg_slices,
                            &seg_sizes,
                            BatchUdp.BATCH_SIZE - send_idx,
                        );
                        for (0..seg_count) |s| {
                            if (send_idx >= BatchUdp.BATCH_SIZE) break;
                            encryptAndQueue(wg_dev, seg_bufs[s][0..seg_sizes[s]], &encrypt_bufs[send_idx], &tx, &send_idx);
                        }
                    } else {
                        if (ip_data.len < 20) continue;
                        const mutable_data = tun_buf[Offload.VNET_HDR_LEN..n];
                        Offload.completeChecksum(vhdr.*, mutable_data);
                        encryptAndQueue(wg_dev, mutable_data, &encrypt_bufs[send_idx], &tx, &send_idx);
                    }
                } else {
                    if (n < 20) continue;
                    const ip_packet = tun_buf[0..n];
                    encryptAndQueue(wg_dev, ip_packet, &encrypt_bufs[send_idx], &tx, &send_idx);
                }
            }

            _ = tx.flush(udp_fd);
        }
    }
}

/// Encrypt an IP packet and queue it for batch sending.
fn encryptAndQueue(
    wg_dev: *lib.wireguard.Device.WgDevice,
    ip_packet: []const u8,
    encrypt_buf: *[1600]u8,
    tx: *lib.net.BatchUdp.BatchSender,
    send_idx: *usize,
) void {
    const dst_ip: [4]u8 = ip_packet[16..20].*;
    const target_slot = wg_dev.lookupByMeshIp(dst_ip);
    if (target_slot) |slot| {
        if (wg_dev.encryptForPeer(slot, ip_packet, encrypt_buf)) |enc_len| {
            if (wg_dev.peers[slot]) |peer| {
                if (peer.endpoint_addr[0] != 0) {
                    tx.queue(encrypt_buf[0..enc_len], peer.endpoint_addr, peer.endpoint_port);
                    send_idx.* += 1;
                }
            }
        } else |_| {}
    }
}

/// Write decrypted packets to TUN, coalescing consecutive same-flow TCP
/// segments into GSO super-packets to reduce TUN write syscalls.
///
/// For a batch of N packets where many are same-flow TCP, this can reduce
/// syscalls from N to ~1, since the kernel segments the super-packet for us.
fn writeCoalescedToTun(
    tun_dev: *const lib.net.Tun.TunDevice,
    storage: *const [64][1500]u8,
    lens: *const [64]usize,
    n: usize,
) void {
    const Offload = lib.net.Offload;

    var i: usize = 0;
    while (i < n) {
        const pkt_a = storage[i][0..lens[i]];

        // Try to coalesce consecutive packets
        if (pkt_a.len >= 40) {
            var coalesce_end = i;
            var total_payload: usize = 0;
            var first_seg_payload: usize = 0;

            // Check how many consecutive packets can coalesce with pkt_a
            var j: usize = i + 1;
            while (j < n) : (j += 1) {
                const prev = storage[coalesce_end][0..lens[coalesce_end]];
                const curr = storage[j][0..lens[j]];
                const payload_b = Offload.canCoalesceTCP(prev, curr);
                if (payload_b == 0) break;
                if (coalesce_end == i) {
                    // Record first segment's payload size for gso_size
                    const ip_version = pkt_a[0] >> 4;
                    var iph_len: usize = undefined;
                    if (ip_version == 4) {
                        iph_len = @as(usize, pkt_a[0] & 0x0F) * 4;
                    } else {
                        iph_len = 40;
                    }
                    const tcph_len = @as(usize, pkt_a[iph_len + 12] >> 4) * 4;
                    first_seg_payload = pkt_a.len - iph_len - tcph_len;
                    total_payload = first_seg_payload;
                }
                total_payload += payload_b;
                coalesce_end = j;
            }

            if (coalesce_end > i and first_seg_payload > 0) {
                // Coalesce: build super-packet = headers of pkt_a + all payloads
                const ip_version = pkt_a[0] >> 4;
                var iph_len: usize = undefined;
                if (ip_version == 4) {
                    iph_len = @as(usize, pkt_a[0] & 0x0F) * 4;
                } else {
                    iph_len = 40;
                }
                const tcph_len = @as(usize, pkt_a[iph_len + 12] >> 4) * 4;
                const headers_len = iph_len + tcph_len;
                const total_len = headers_len + total_payload;

                if (total_len <= 65535) {
                    // Build the super-packet in a stack buffer
                    var super_pkt: [65535]u8 = undefined;
                    @memcpy(super_pkt[0..headers_len], pkt_a[0..headers_len]);

                    // Copy payloads from all segments
                    var off: usize = headers_len;
                    var k: usize = i;
                    while (k <= coalesce_end) : (k += 1) {
                        const seg = storage[k][0..lens[k]];
                        const seg_payload = seg[headers_len..];
                        @memcpy(super_pkt[off..][0..seg_payload.len], seg_payload);
                        off += seg_payload.len;
                    }

                    // Fix IP total length and last segment's TCP flags (PSH)
                    if (ip_version == 4) {
                        std.mem.writeInt(u16, super_pkt[2..4], @intCast(total_len), .big);
                        // Recalculate IP checksum
                        super_pkt[10] = 0;
                        super_pkt[11] = 0;
                        var csum: u32 = 0;
                        var ci: usize = 0;
                        while (ci < iph_len) : (ci += 2) {
                            csum += @as(u32, super_pkt[ci]) << 8 | @as(u32, super_pkt[ci + 1]);
                        }
                        while (csum > 0xFFFF) csum = (csum & 0xFFFF) + (csum >> 16);
                        const ip_csum = ~@as(u16, @intCast(csum & 0xFFFF));
                        super_pkt[10] = @intCast(ip_csum >> 8);
                        super_pkt[11] = @intCast(ip_csum & 0xFF);
                    } else {
                        std.mem.writeInt(u16, super_pkt[4..6], @intCast(total_len - 40), .big);
                    }

                    // Build GSO header
                    const protocol: u8 = if (ip_version == 4) pkt_a[9] else pkt_a[6];
                    const vhdr = Offload.makeGSOHeader(
                        protocol,
                        ip_version == 6,
                        @intCast(iph_len),
                        @intCast(tcph_len),
                        @intCast(first_seg_payload),
                    );

                    // Write super-packet with GSO header to TUN
                    tun_dev.writeGSO(vhdr, super_pkt[0..total_len]) catch {};

                    i = coalesce_end + 1;
                    continue;
                }
            }
        }

        // Not coalesceable — write individually with GSO_NONE
        var vhdr_bytes = std.mem.zeroes([Offload.VNET_HDR_LEN]u8);
        var iov = [_]posix.iovec_const{
            .{ .base = &vhdr_bytes, .len = Offload.VNET_HDR_LEN },
            .{ .base = pkt_a.ptr, .len = pkt_a.len },
        };
        _ = posix.writev(tun_dev.fd, &iov) catch {};
        i += 1;
    }
}

/// Process a single incoming UDP packet: classify and dispatch to the appropriate handler.
/// Shared by both GRO (single coalesced buffer) and legacy batch (recvmmsg) receive paths.
fn processIncomingPacket(
    pkt: []const u8,
    sender_addr: [4]u8,
    sender_port: u16,
    wg_dev: *lib.wireguard.Device.WgDevice,
    swim: *lib.discovery.Swim.SwimProtocol,
    udp_sock: *lib.net.Udp.UdpSocket,
    stdout: std.fs.File,
    decrypt_storage: *[64][1500]u8,
    decrypt_lens: *[64]usize,
    n_decrypted: *usize,
) void {
    const Device = lib.wireguard.Device;

    switch (Device.PacketType.classify(pkt)) {
        .wg_handshake_init => {
            if (pkt.len >= @sizeOf(lib.wireguard.Noise.HandshakeInitiation)) {
                const msg: *const lib.wireguard.Noise.HandshakeInitiation = @ptrCast(@alignCast(pkt.ptr));
                if (wg_dev.handleInitiation(msg)) |hs_result| {
                    const resp_bytes = std.mem.asBytes(&hs_result.response);
                    _ = udp_sock.sendTo(resp_bytes, sender_addr, sender_port) catch 0;
                    writeFormatted(stdout, "  WG handshake: responded to initiation\n", .{}) catch {};
                } else |_| {}
            }
        },
        .wg_handshake_resp => {
            if (pkt.len >= @sizeOf(lib.wireguard.Noise.HandshakeResponse)) {
                const msg: *const lib.wireguard.Noise.HandshakeResponse = @ptrCast(@alignCast(pkt.ptr));
                if (wg_dev.handleResponse(msg)) |slot| {
                    if (wg_dev.peers[slot]) |*p| {
                        p.endpoint_addr = sender_addr;
                        p.endpoint_port = sender_port;
                    }
                    writeFormatted(stdout, "  WG handshake: completed with peer\n", .{}) catch {};
                } else |_| {}
            }
        },
        .wg_transport => {
            if (n_decrypted.* < 64) {
                if (wg_dev.decryptTransport(pkt, &decrypt_storage[n_decrypted.*])) |result| {
                    decrypt_lens[n_decrypted.*] = result.len;
                    n_decrypted.* += 1;
                } else |_| {}
            }
        },
        .wg_cookie => {},
        .stun => swim.feedPacket(pkt, sender_addr, sender_port),
        .swim => swim.feedPacket(pkt, sender_addr, sender_port),
        .unknown => {},
    }
}

/// Userspace multiplexed event loop with multi-threaded data plane.
///
/// Architecture (parallel mode, encrypt_workers > 0):
/// - N TUN reader threads: read from TUN queues, split GSO, push to EncryptQueue.
/// - M encrypt workers: pop from queue, encrypt via UDP GSO (single sendmsg per peer).
/// - Control-plane (this function): receives all UDP (GRO coalesced or batch),
///   dispatches handshakes, SWIM gossip, and decrypts transport → TUN.
///
/// Architecture (legacy mode, encrypt_workers == 0):
/// - N data-plane workers: each reads TUN, encrypts, sends UDP (serial).
fn userspaceEventLoop(
    swim: *lib.discovery.Swim.SwimProtocol,
    wg_dev: *lib.wireguard.Device.WgDevice,
    udp_sock: *lib.net.Udp.UdpSocket,
    tun_dev: lib.net.Tun.TunDevice,
    stdout: std.fs.File,
    encrypt_workers_arg: usize,
) !void {
    const BatchUdp = lib.net.BatchUdp;

    // Determine TUN reader count: min(cpus, MAX_WORKERS), at least 1
    const cpu_count = std.Thread.getCpuCount() catch 1;
    const n_tun_readers = @min(cpu_count, MAX_WORKERS);

    // Determine encrypt worker count
    const n_encrypt = if (encrypt_workers_arg > 0)
        @min(encrypt_workers_arg, MAX_ENCRYPT_WORKERS)
    else
        0; // 0 = legacy serial mode

    if (n_encrypt > 0) {
        writeFormatted(stdout, "  pipeline: {d} TUN readers + {d} encrypt workers (on {d} CPUs)\n", .{ n_tun_readers, n_encrypt, cpu_count }) catch {};

        // Enable UDP GRO+GSO on the socket for coalesced I/O
        udp_sock.enableGRO();
        udp_sock.enableGSO();
        writeFormatted(stdout, "  UDP offloads: GRO + GSO enabled\n", .{}) catch {};
    } else {
        writeFormatted(stdout, "  data-plane workers: {d} (on {d} CPUs, serial mode)\n", .{ n_tun_readers, cpu_count }) catch {};
    }

    // Open additional TUN queue fds for workers
    var tun_fds: [MAX_WORKERS]posix.fd_t = undefined;
    var opened_workers: usize = 0;

    for (0..n_tun_readers) |w| {
        if (w == 0) {
            tun_fds[0] = tun_dev.fd;
        } else {
            const extra_tun = tun_dev.openQueue() catch {
                writeFormatted(stdout, "  warning: could not open TUN queue {d}\n", .{w}) catch {};
                break;
            };
            tun_fds[w] = extra_tun.fd;
        }
        opened_workers += 1;
    }

    writeFormatted(stdout, "  opened {d} TUN queues\n", .{opened_workers}) catch {};

    // Set all TUN fds to non-blocking
    for (0..opened_workers) |w| {
        const flags = posix.fcntl(tun_fds[w], posix.F.GETFL, 0) catch continue;
        _ = posix.fcntl(tun_fds[w], posix.F.SETFL, flags | @as(usize, 0x800)) catch {};
    }

    // Total thread pool
    const MAX_TOTAL_THREADS = MAX_WORKERS + MAX_ENCRYPT_WORKERS;
    var threads: [MAX_TOTAL_THREADS]std.Thread = undefined;
    var spawned: usize = 0;

    // Zero-copy pipeline state (heap allocated — DataPlanePool is ~33MB)
    const Pipeline = lib.net.Pipeline;
    var data_pool: *Pipeline.DataPlanePool = undefined;
    var crypto_queue: *Pipeline.CryptoQueue = undefined;

    if (n_encrypt > 0) {
        const page_alloc = std.heap.page_allocator;
        data_pool = page_alloc.create(Pipeline.DataPlanePool) catch {
            writeFormatted(stdout, "  error: failed to allocate data plane pool\n", .{}) catch {};
            return error.OutOfMemory;
        };
        data_pool.* = .{};
        data_pool.init();

        crypto_queue = page_alloc.create(Pipeline.CryptoQueue) catch {
            writeFormatted(stdout, "  error: failed to allocate crypto queue\n", .{}) catch {};
            return error.OutOfMemory;
        };
        crypto_queue.* = Pipeline.CryptoQueue{};

        // Parallel pipeline: TUN readers + encrypt workers
        for (0..opened_workers) |w| {
            threads[spawned] = std.Thread.spawn(.{}, tunReaderPipeline, .{
                &swim.running,
                wg_dev,
                tun_fds[w],
                tun_dev.vnet_hdr,
                data_pool,
                crypto_queue,
            }) catch {
                writeFormatted(stdout, "  warning: failed to spawn TUN reader {d}\n", .{w}) catch {};
                continue;
            };
            spawned += 1;
        }

        for (0..n_encrypt) |e| {
            threads[spawned] = std.Thread.spawn(.{}, cryptoWorkerPipeline, .{
                &swim.running,
                wg_dev,
                udp_sock.fd,
                data_pool,
                crypto_queue,
            }) catch {
                writeFormatted(stdout, "  warning: failed to spawn encrypt worker {d}\n", .{e}) catch {};
                continue;
            };
            spawned += 1;
        }
    } else {
        // Legacy serial mode: each worker does TUN read + encrypt + send
        for (0..opened_workers) |w| {
            threads[spawned] = std.Thread.spawn(.{}, dataPlaneWorker, .{
                &swim.running,
                wg_dev,
                tun_fds[w],
                udp_sock.fd,
                tun_dev.vnet_hdr,
            }) catch {
                writeFormatted(stdout, "  warning: failed to spawn worker {d}\n", .{w}) catch {};
                continue;
            };
            spawned += 1;
        }
    }
    writeFormatted(stdout, "  spawned {d} data-plane threads\n", .{spawned}) catch {};

    // ── Control-plane loop: SWIM + handshakes + decrypt on original gossip socket ──
    // Use GRO receiver when pipeline is active (UDP GRO enabled), else batch receiver
    var gro_rx = BatchUdp.GROReceiver{};
    var batch_rx = BatchUdp.BatchReceiver{};
    batch_rx.setupPointers();
    const use_gro = n_encrypt > 0;

    while (swim.running.load(.acquire)) {
        var fds = [_]posix.pollfd{
            .{ .fd = udp_sock.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = posix.poll(&fds, 50) catch continue;

        if (fds[0].revents & posix.POLL.IN != 0) {
            // ── Two-pass decrypt→coalesce→write ──
            // Pass 1: decrypt all transport packets, handle non-transport inline
            const MAX_DECRYPTED = 64;
            var decrypt_storage: [MAX_DECRYPTED][1500]u8 = undefined;
            var decrypt_lens: [MAX_DECRYPTED]usize = undefined;
            var n_decrypted: usize = 0;

            if (use_gro) {
                // GRO path: single recvmsg returns coalesced buffer
                const total = gro_rx.recvGRO(udp_sock.fd);
                if (total > 0) {
                    const sender = gro_rx.getSender();
                    const seg_size: usize = if (gro_rx.segment_size > 0)
                        @as(usize, gro_rx.segment_size)
                    else
                        total;

                    var offset: usize = 0;
                    while (offset < total) {
                        const pkt_len = @min(seg_size, total - offset);
                        const pkt = gro_rx.buf[offset..][0..pkt_len];
                        processIncomingPacket(
                            pkt,
                            sender.addr,
                            sender.port,
                            wg_dev,
                            swim,
                            udp_sock,
                            stdout,
                            &decrypt_storage,
                            &decrypt_lens,
                            &n_decrypted,
                        );
                        offset += pkt_len;
                    }
                }
            } else {
                // Legacy batch path: recvmmsg returns individual packets
                const count = batch_rx.recvBatch(udp_sock.fd);
                for (0..count) |i| {
                    const pkt = batch_rx.getPacket(i);
                    const sender = batch_rx.getSender(i);
                    processIncomingPacket(
                        pkt,
                        sender.addr,
                        sender.port,
                        wg_dev,
                        swim,
                        udp_sock,
                        stdout,
                        &decrypt_storage,
                        &decrypt_lens,
                        &n_decrypted,
                    );
                }
            }

            // Pass 2: coalesce same-flow TCP segments and write to TUN
            if (n_decrypted > 0) {
                if (tun_dev.vnet_hdr) {
                    writeCoalescedToTun(&tun_dev, &decrypt_storage, &decrypt_lens, n_decrypted);
                } else {
                    // No vnet_hdr — write each packet individually
                    for (0..n_decrypted) |d| {
                        _ = posix.write(tun_dev.fd, decrypt_storage[d][0..decrypt_lens[d]]) catch {};
                    }
                }
            }
        }

        swim.tickTimersOnly();
    }

    // Signal encrypt workers to stop, then wait for all threads
    crypto_queue.close();
    for (0..spawned) |w| {
        threads[w].join();
    }

    // Close extra TUN fds (skip tun_fds[0] — primary, closed by caller)
    for (1..opened_workers) |w| {
        posix.close(tun_fds[w]);
    }
}

/// Look up which WgDevice peer slot corresponds to a mesh IP address.
fn findPeerByMeshIp(
    wg_dev: *const lib.wireguard.Device.WgDevice,
    swim: *const lib.discovery.Swim.SwimProtocol,
    mesh_ip: [4]u8,
) ?usize {
    // Walk membership table to find identity_key for this mesh IP,
    // then map to WgDevice slot
    var iter = swim.membership.peers.iterator();
    while (iter.next()) |entry| {
        const peer = entry.value_ptr;
        if (std.mem.eql(u8, &peer.mesh_ip, &mesh_ip)) {
            return wg_dev.findByIdentity(entry.key_ptr.*);
        }
    }
    return null;
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
    const stdout = getStdOut();
    const stderr = getStdErr();

    const Netlink = lib.wireguard.Netlink;

    // Check if interface exists
    const ifindex = lib.wireguard.RtNetlink.getInterfaceIndex("mg0") catch {
        try stderr.writeAll("meshguard is not running (no mg0 interface).\n");
        std.process.exit(1);
    };

    // Resolve WireGuard generic netlink family
    const family_id = Netlink.resolveWireguardFamily() catch {
        try writeFormatted(stdout, "meshguard is running.\n  interface: mg0 (index {d})\n  (could not query WireGuard device — kernel module not loaded?)\n", .{ifindex});
        return;
    };

    // Query device info
    const dev = Netlink.getDevice(family_id, "mg0") catch {
        try writeFormatted(stdout, "meshguard is running.\n  interface: mg0 (index {d})\n  (could not query device status)\n", .{ifindex});
        return;
    };

    // Format public key as hex prefix
    try writeFormatted(stdout, "meshguard is running.\n", .{});
    try writeFormatted(stdout, "  interface: mg0 (index {d})\n", .{ifindex});
    try writeFormatted(stdout, "  public key: {x:0>2}{x:0>2}{x:0>2}{x:0>2}...{x:0>2}{x:0>2}\n", .{
        dev.public_key[0],  dev.public_key[1],  dev.public_key[2], dev.public_key[3],
        dev.public_key[30], dev.public_key[31],
    });
    try writeFormatted(stdout, "  listening port: {d}\n", .{dev.listen_port});
    try writeFormatted(stdout, "  peers: {d}\n", .{dev.peer_count});

    if (dev.peer_count == 0) return;

    try stdout.writeAll("\n");

    // Display each peer
    const now = std.time.timestamp();
    for (dev.peers[0..dev.peer_count]) |peer| {
        // Peer pubkey (hex prefix)
        try writeFormatted(stdout, "  peer: {x:0>2}{x:0>2}{x:0>2}{x:0>2}...\n", .{
            peer.public_key[0], peer.public_key[1], peer.public_key[2], peer.public_key[3],
        });

        // Mesh IP (from allowed IPs)
        if (peer.allowed_ip[0] != 0) {
            try writeFormatted(stdout, "    mesh ip: {d}.{d}.{d}.{d}/{d}\n", .{
                peer.allowed_ip[0], peer.allowed_ip[1], peer.allowed_ip[2], peer.allowed_ip[3],
                peer.allowed_cidr,
            });
        }

        // Endpoint
        if (peer.endpoint_addr[0] != 0 or peer.endpoint_port != 0) {
            try writeFormatted(stdout, "    endpoint: {d}.{d}.{d}.{d}:{d}\n", .{
                peer.endpoint_addr[0], peer.endpoint_addr[1],
                peer.endpoint_addr[2], peer.endpoint_addr[3],
                peer.endpoint_port,
            });
        }

        // Last handshake
        if (peer.last_handshake_sec > 0) {
            const ago = now - peer.last_handshake_sec;
            if (ago < 60) {
                try writeFormatted(stdout, "    last handshake: {d}s ago\n", .{ago});
            } else if (ago < 3600) {
                try writeFormatted(stdout, "    last handshake: {d}m {d}s ago\n", .{ @divFloor(ago, 60), @mod(ago, 60) });
            } else {
                try writeFormatted(stdout, "    last handshake: {d}h {d}m ago\n", .{ @divFloor(ago, 3600), @divFloor(@mod(ago, 3600), 60) });
            }
        } else {
            try stdout.writeAll("    last handshake: never\n");
        }

        // Transfer stats
        const rx = formatBytes(peer.rx_bytes);
        const tx = formatBytes(peer.tx_bytes);
        try writeFormatted(stdout, "    transfer: ↓ {d}.{d:0>1} {s}  ↑ {d}.{d:0>1} {s}\n", .{
            rx.whole, rx.frac, rx.unit, tx.whole, tx.frac, tx.unit,
        });
    }
}

const FormattedBytes = struct {
    whole: u64,
    frac: u64, // single decimal digit
    unit: []const u8,
};

fn formatBytes(bytes: u64) FormattedBytes {
    if (bytes < 1024) {
        return .{ .whole = bytes, .frac = 0, .unit = "B" };
    } else if (bytes < 1024 * 1024) {
        return .{ .whole = bytes / 1024, .frac = (bytes % 1024) * 10 / 1024, .unit = "KiB" };
    } else if (bytes < 1024 * 1024 * 1024) {
        const mib = bytes / (1024 * 1024);
        const rem = bytes % (1024 * 1024);
        return .{ .whole = mib, .frac = rem * 10 / (1024 * 1024), .unit = "MiB" };
    } else {
        const gib = bytes / (1024 * 1024 * 1024);
        const rem = bytes % (1024 * 1024 * 1024);
        return .{ .whole = gib, .frac = rem * 10 / (1024 * 1024 * 1024), .unit = "GiB" };
    }
}
