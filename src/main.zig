const std = @import("std");
const lib = @import("lib.zig");

const Config = lib.config.Config;
const Identity = lib.identity.Keys;
const posix = std.posix;

const version = "0.7.0";

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
    \\  connect     Direct peer connection via token exchange (no seed needed)
    \\  keygen      Generate a new identity keypair (--force to overwrite)
    \\  trust       Authorize a peer's public key (--name <label>)
    \\  trust --org Trust an organization's public key
    \\  revoke      Revoke a peer's public key
    \\  export      Print this node's public key
    \\  org-keygen  Generate a new org keypair
    \\  org-sign    Sign a node's key with org key (--name <label>)
    \\  org-vouch   Vouch for an external node (auto-propagates to org members)
    \\  config show Show local node configuration (works offline)
    \\  service     Manage service access policies
    \\  upgrade     Upgrade to the latest release from GitHub
    \\  version     Print version
    \\
    \\OPTIONS:
    \\  --config <path>     Path to config file
    \\  --seed <host:port>   Seed peer (IP or hostname, can be repeated)
    \\  --dns <domain>       Discover seeds via DNS TXT records
    \\  --mdns               Discover seeds via mDNS on LAN
    \\  --announce <ip>      Override public IP (skip STUN)
    \\  --kernel             Use kernel WireGuard (requires root)
    \\  --open               Accept all peers (skip trust enforcement)
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

    // Initialize libsodium (AVX2 ChaCha20-Poly1305 assembly)
    @import("crypto/sodium.zig").init();
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

    if (std.mem.eql(u8, command, "connect")) {
        try cmdConnect(allocator, args[2..]);
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

    if (std.mem.eql(u8, command, "upgrade")) {
        try cmdUpgrade(allocator);
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

    if (std.mem.eql(u8, command, "org-vouch")) {
        if (args.len < 3) {
            try getStdErr().writeAll("error: 'org-vouch' requires a node public key or .pub file\n");
            std.process.exit(1);
        }
        try cmdOrgVouch(allocator, args[2]);
        return;
    }

    if (std.mem.eql(u8, command, "config")) {
        if (args.len < 3 or !std.mem.eql(u8, args[2], "show")) {
            try getStdErr().writeAll("usage: meshguard config show\n");
            std.process.exit(1);
        }
        try cmdConfigShow(allocator);
        return;
    }

    if (std.mem.eql(u8, command, "service")) {
        try cmdService(allocator, args[2..]);
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

fn cmdOrgVouch(allocator: std.mem.Allocator, node_key_arg: []const u8) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    const stdout = getStdOut();
    const stderr = getStdErr();
    const Org = lib.identity.Org;

    // Load org keypair
    const org_kp = Org.loadOrgKeyPair(allocator, config_dir) catch {
        try stderr.writeAll("error: no org keypair found. Run 'meshguard org-keygen' first.\n");
        std.process.exit(1);
    };

    // Validate the external node pubkey
    var key_b64_buf: [44]u8 = undefined;
    var node_pk_bytes: [32]u8 = undefined;
    if (lib.identity.Trust.validateKey(node_key_arg, &key_b64_buf, &node_pk_bytes)) |err_msg| {
        try writeFormatted(stderr, "error: {s}\n", .{err_msg});
        std.process.exit(1);
    }

    // Create lamport timestamp (unix seconds — good enough for vouch ordering)
    const lamport: u64 = @intCast(@divTrunc(std.time.timestamp(), 1));

    // Sign the vouch: Ed25519(vouched_pubkey ‖ lamport)
    var sign_buf: [40]u8 = undefined;
    @memcpy(sign_buf[0..32], &node_pk_bytes);
    std.mem.writeInt(u64, sign_buf[32..40], lamport, .little);

    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = Ed25519.KeyPair.fromSecretKey(org_kp.secret_key) catch {
        try stderr.writeAll("error: failed to derive signing key\n");
        std.process.exit(1);
    };
    const signature = kp.sign(&sign_buf, null) catch {
        try stderr.writeAll("error: failed to sign vouch\n");
        std.process.exit(1);
    };

    // Save vouch to config dir for gossip broadcast
    const vouch_dir = try std.fs.path.join(allocator, &.{ config_dir, "vouched" });
    defer allocator.free(vouch_dir);
    std.fs.makeDirAbsolute(vouch_dir) catch {};

    // Use first 8 hex chars of node pubkey as filename
    var hex_buf: [16]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        node_pk_bytes[0], node_pk_bytes[1], node_pk_bytes[2], node_pk_bytes[3],
        node_pk_bytes[4], node_pk_bytes[5], node_pk_bytes[6], node_pk_bytes[7],
    }) catch "vouch";

    const vouch_filename = try std.fmt.allocPrint(allocator, "{s}.vouch", .{hex});
    defer allocator.free(vouch_filename);

    const vouch_path = try std.fs.path.join(allocator, &.{ vouch_dir, vouch_filename });
    defer allocator.free(vouch_path);

    // Write binary vouch: [32B org_pubkey][32B vouched_pubkey][8B lamport][64B signature]
    const org_pub_bytes = org_kp.public_key.toBytes();
    var vouch_data: [136]u8 = undefined;
    @memcpy(vouch_data[0..32], &org_pub_bytes);
    @memcpy(vouch_data[32..64], &node_pk_bytes);
    std.mem.writeInt(u64, vouch_data[64..72], lamport, .little);
    @memcpy(vouch_data[72..136], &signature.toBytes());

    const file = try std.fs.createFileAbsolute(vouch_path, .{});
    defer file.close();
    try file.writeAll(&vouch_data);

    const b64 = std.base64.standard.Encoder;
    var node_b64: [44]u8 = undefined;
    _ = b64.encode(&node_b64, &node_pk_bytes);

    try writeFormatted(stdout, "Vouch signed for external node.\n", .{});
    try writeFormatted(stdout, "  node pubkey: {s}\n", .{node_b64});
    try writeFormatted(stdout, "  saved to:    {s}\n", .{vouch_path});
    try stdout.writeAll("\nThis vouch will be gossiped to all org members on next 'meshguard up'.\n");
    try stdout.writeAll("All nodes trusting this org will auto-accept the vouched node.\n");
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
    var open_mode: bool = false; // --open: skip trust, accept any peer
    // Collect raw seed strings for hostname resolution
    var seed_strs: [16][]const u8 = undefined;
    var seed_str_count: usize = 0;
    {
        var i: usize = 0;
        while (i < extra_args.len) : (i += 1) {
            if (std.mem.eql(u8, extra_args[i], "--help") or std.mem.eql(u8, extra_args[i], "-h")) {
                try getStdOut().writeAll(usage);
                return;
            } else if (std.mem.eql(u8, extra_args[i], "--seed") and i + 1 < extra_args.len) {
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
            } else if (std.mem.eql(u8, extra_args[i], "--open")) {
                open_mode = true;
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

    // Also load seeds from config file (written by `meshguard connect`)
    {
        const seeds_path = std.fs.path.join(allocator, &.{ config_dir, "seeds" }) catch null;
        defer if (seeds_path) |p| allocator.free(p);

        if (seeds_path) |path| {
            const file = std.fs.openFileAbsolute(path, .{}) catch null;
            if (file) |f| {
                defer f.close();
                var file_buf: [1024]u8 = undefined;
                const read = f.readAll(&file_buf) catch 0;
                if (read > 0) {
                    // Parse line by line: "host:port\n"
                    var rest: []const u8 = file_buf[0..read];
                    while (rest.len > 0) {
                        const nl = std.mem.indexOfScalar(u8, rest, '\n');
                        const line = if (nl) |n| rest[0..n] else rest;
                        rest = if (nl) |n| rest[n + 1 ..] else rest[rest.len..];
                        const trimmed = std.mem.trimRight(u8, line, "\r \t");
                        if (trimmed.len == 0) continue;
                        if (lib.discovery.Seed.parseEndpoint(trimmed)) |ep| {
                            if (seed_count < seed_buf.len) {
                                seed_buf[seed_count] = ep;
                                seed_count += 1;
                            }
                        }
                    }
                }
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
    var gossip_socket = blk: {
        if (announce_addr) |addr| {
            // Bind to announced IP for correct source-based routing on multi-homed servers
            break :blk lib.net.Udp.UdpSocket.bindAddr(addr, gossip_port) catch {
                try stderr.writeAll("error: failed to bind gossip port to announced address\n");
                lib.wireguard.Config.teardown(lib.wireguard.Config.DEFAULT_IFNAME) catch {};
                std.process.exit(1);
            };
        } else {
            break :blk lib.net.Udp.UdpSocket.bind(gossip_port) catch {
                try stderr.writeAll("error: failed to bind gossip port 51821\n");
                lib.wireguard.Config.teardown(lib.wireguard.Config.DEFAULT_IFNAME) catch {};
                std.process.exit(1);
            };
        }
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

    // Load authorized keys and enable trust enforcement (unless --open)
    if (!open_mode) {
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

        // Load trusted organizations
        const trusted_orgs = lib.identity.Trust.loadTrustedOrgs(allocator, config_dir) catch &.{};
        defer {
            for (trusted_orgs) |org| {
                allocator.free(org.name);
            }
            allocator.free(trusted_orgs);
        }
        if (trusted_orgs.len > 0) {
            for (trusted_orgs) |org| {
                swim.addTrustedOrg(org.public_key);
            }
            // Enable trust enforcement when org trust is configured
            if (!swim.enforce_trust) swim.enableTrust();
            try writeFormatted(stdout, "  org trust: {d} trusted org(s)\n", .{trusted_orgs.len});
        }
    } else {
        try stdout.writeAll("  trust: OPEN (accepting all peers)\n");
    }

    // Load service access policies
    const ServicePolicy = lib.services.Policy;
    var service_filter = ServicePolicy.ServiceFilter.loadFromDir(config_dir);
    service_filter.resolveAliases(config_dir);
    service_filter.resolveOrgNames(config_dir);
    if (service_filter.global != null or service_filter.peer_count > 0 or service_filter.org_count > 0) {
        try writeFormatted(stdout, "  services: {d} peer, {d} org, {s} global, default={s}\n", .{
            @as(usize, service_filter.peer_count),
            @as(usize, service_filter.org_count),
            if (service_filter.global != null) @as([]const u8, "yes") else @as([]const u8, "no"),
            if (service_filter.default_action == .allow) @as([]const u8, "allow") else @as([]const u8, "deny"),
        });
    }

    // Load our own org certificate (if present)
    const cert_path = try std.fs.path.join(allocator, &.{ config_dir, "node.cert" });
    defer allocator.free(cert_path);
    if (lib.identity.Org.loadCertificate(allocator, cert_path)) |cert| {
        var cert_wire: [186]u8 = undefined;
        cert.serialize(&cert_wire);
        swim.setOrgCert(cert_wire);
        try writeFormatted(stdout, "  org cert: {s} (org member)\n", .{cert.getName()});
    } else |_| {}

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
            .cone, .symmetric => {
                var pub_ip_buf: [15]u8 = undefined;
                const pub_ip = lib.wireguard.Ip.formatIp(stun_result.external.addr, &pub_ip_buf);
                const nat_type_str = if (stun_result.nat_type == .cone) "cone" else "symmetric";
                try writeFormatted(stdout, "  public endpoint: {s}:{d} (behind NAT, {s})\n", .{ pub_ip, stun_result.external.port, nat_type_str });

                // Try UPnP port forwarding
                try stdout.writeAll("  trying UPnP port forwarding...\n");
                const UPnP = lib.nat.UPnP;
                if (UPnP.addPortMapping(gossip_port, gossip_port, "meshguard", 3600)) |upnp_result| {
                    // Use UPnP external IP if available, otherwise fall back to STUN IP
                    const effective_ip = if (upnp_result.external_ip[0] == 0 and upnp_result.external_ip[1] == 0)
                        stun_result.external.addr
                    else
                        upnp_result.external_ip;
                    var upnp_ip_buf: [15]u8 = undefined;
                    const upnp_ip = lib.wireguard.Ip.formatIp(effective_ip, &upnp_ip_buf);
                    try writeFormatted(stdout, "  ✓ UPnP: port {d} forwarded (external IP: {s})\n", .{ gossip_port, upnp_ip });
                    // Update public endpoint — UPnP makes us directly reachable
                    swim.setPublicEndpoint(
                        messages.Endpoint{ .addr = effective_ip, .port = gossip_port },
                        .public,
                    );
                } else |upnp_err| {
                    try writeFormatted(stdout, "  UPnP: {s} (will use hole punching)\n", .{@errorName(upnp_err)});
                }
            },
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
        userspaceEventLoop(&swim, &wg_device, &gossip_socket, tun_dev, stdout, encrypt_workers, &service_filter) catch |err| {
            try writeFormatted(stderr, "error: event loop failed: {s}\n", .{@errorName(err)});
        };
    }

    // Send leave announcement safely from the main thread (covers kernel mode)
    swim.broadcastLeave();

    // Cleanup
    try stdout.writeAll("\nmeshguard stopping...\n");
    if (use_kernel_wg) {
        lib.wireguard.Config.teardown(lib.wireguard.Config.DEFAULT_IFNAME) catch {};
    }
    try stdout.writeAll("meshguard stopped.\n");
}

// ─── Coordinated Punch (meshguard connect) ───

fn cmdConnect(allocator: std.mem.Allocator, extra_args: []const []const u8) !void {
    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    const stdout = getStdOut();
    const stderr = getStdErr();
    const CoordinatedPunch = lib.nat.CoordinatedPunch;
    const Stun = lib.nat.Stun;

    // Parse subcommand
    var mode: enum { generate, join } = .generate;
    var join_token_arg: ?[]const u8 = null;
    var punch_delay_min: u64 = 1; // default: 1 minute

    {
        var i: usize = 0;
        while (i < extra_args.len) : (i += 1) {
            if (std.mem.eql(u8, extra_args[i], "--generate")) {
                mode = .generate;
            } else if (std.mem.eql(u8, extra_args[i], "--join") and i + 1 < extra_args.len) {
                mode = .join;
                i += 1;
                join_token_arg = extra_args[i];
            } else if (std.mem.eql(u8, extra_args[i], "--in") and i + 1 < extra_args.len) {
                i += 1;
                punch_delay_min = std.fmt.parseInt(u64, extra_args[i], 10) catch 1;
            } else if (std.mem.eql(u8, extra_args[i], "--help") or std.mem.eql(u8, extra_args[i], "-h")) {
                try stdout.writeAll(
                    \\meshguard connect — Direct peer connection via token exchange
                    \\
                    \\USAGE:
                    \\  meshguard connect --generate [--in <minutes>]
                    \\  meshguard connect --join <mg://token>
                    \\
                    \\FLOW:
                    \\  1. Initiator runs --generate, shares mg:// token with peer
                    \\  2. Peer runs --join <token>, shares response token back
                    \\  3. Initiator pastes response token
                    \\  4. Both sides punch simultaneously (NTP-synced)
                    \\
                    \\OPTIONS:
                    \\  --in <minutes>  Punch delay (default: 1 minute)
                    \\
                );
                return;
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

    // Derive WG keys (same as cmdUp)
    const sk_bytes = kp.secret_key.seed();
    var hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&sk_bytes, &hash, .{});
    var wg_private_key: [32]u8 = hash[0..32].*;
    wg_private_key[0] &= 248;
    wg_private_key[31] &= 127;
    wg_private_key[31] |= 64;
    const wg_public_key = std.crypto.dh.X25519.recoverPublicKey(wg_private_key) catch {
        try stderr.writeAll("error: failed to derive WG public key\n");
        std.process.exit(1);
    };

    // Derive mesh IP
    const mesh_ip = lib.wireguard.Ip.deriveFromPubkey(kp.public_key);

    // Must use the same gossip port the daemon will bind to,
    // so the NAT hole punched here stays valid after restart.
    const gossip_port: u16 = 51821;

    // Stop running service first (otherwise we can't bind the port)
    const was_running = blk: {
        const stat = std.fs.openFileAbsolute("/etc/systemd/system/meshguard.service", .{}) catch break :blk false;
        stat.close();
        // Check if service is active
        var child = std.process.Child.init(&.{ "systemctl", "is-active", "--quiet", "meshguard" }, allocator);
        child.stderr_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        const term = child.spawnAndWait() catch break :blk false;
        break :blk (term.Exited == 0);
    };

    if (was_running) {
        try stdout.writeAll("  stopping meshguard service (need gossip port)...\n");
        var stop = std.process.Child.init(&.{ "systemctl", "stop", "meshguard" }, allocator);
        stop.stderr_behavior = .Ignore;
        stop.stdout_behavior = .Ignore;
        _ = stop.spawnAndWait() catch {};
        // Brief pause for port to be released
        const ts = std.os.linux.timespec{ .sec = 1, .nsec = 0 };
        _ = std.os.linux.nanosleep(&ts, null);
    }

    // Bind to the gossip port (same port meshguard up will use)
    var socket = lib.net.Udp.UdpSocket.bind(gossip_port) catch {
        try stderr.writeAll("error: failed to bind gossip port 51821\n");
        try stderr.writeAll("  hint: is meshguard already running? Stop it first.\n");
        std.process.exit(1);
    };
    defer socket.close();

    // STUN discovery
    try stdout.writeAll("  discovering public endpoint (STUN)...\n");
    const stun_result = Stun.discover(&socket, gossip_port, &Stun.DEFAULT_STUN_SERVERS);
    if (stun_result.nat_type == .unknown) {
        try stderr.writeAll("error: STUN failed — could not determine public endpoint\n");
        try stderr.writeAll("  hint: check internet connectivity or firewall\n");
        std.process.exit(1);
    }

    var pub_ip_buf: [15]u8 = undefined;
    const pub_ip = lib.wireguard.Ip.formatIp(stun_result.external.addr, &pub_ip_buf);
    const nat_label: []const u8 = switch (stun_result.nat_type) {
        .public => "no NAT",
        .cone => "cone NAT",
        .symmetric => "symmetric NAT",
        .unknown => "unknown",
    };
    try writeFormatted(stdout, "  public endpoint: {s}:{d} ({s})\n", .{ pub_ip, stun_result.external.port, nat_label });

    if (stun_result.nat_type == .symmetric) {
        try stderr.writeAll("warning: symmetric NAT detected — coordinated punch may fail\n");
    }

    // Get synchronized time
    try stdout.writeAll("  syncing time (NTP)...\n");
    const ntp_time = CoordinatedPunch.currentTimeSecs();

    // Pick STUN server used (for token)
    const stun_server = Stun.DEFAULT_STUN_SERVERS[0];

    switch (mode) {
        .generate => {
            // ── Initiator flow ──
            try stdout.writeAll("\n── Coordinated Punch (initiator) ──\n\n");

            const punch_time = ntp_time + (punch_delay_min * 60);

            // Generate nonce
            var nonce: [8]u8 = undefined;
            std.crypto.random.bytes(&nonce);

            // Build token
            var token = CoordinatedPunch.Token{
                .pubkey = kp.public_key.toBytes(),
                .wg_pubkey = wg_public_key,
                .stun_addr = stun_result.external.addr,
                .stun_port = stun_result.external.port,
                .mesh_ip = mesh_ip,
                .punch_time = punch_time,
                .nonce = nonce,
                .stun_server = stun_server.host,
                .stun_server_port = stun_server.port,
                .nat_type = @intFromEnum(stun_result.nat_type),
                .signature = .{ 0, 0, 0, 0, 0, 0 },
            };
            CoordinatedPunch.signTokenHash(&token);

            // Encode and print
            var uri_buf: [156]u8 = undefined;
            const uri = CoordinatedPunch.encodeTokenUri(&token, &uri_buf);

            var mesh_ip_buf: [15]u8 = undefined;
            const mesh_ip_str = lib.wireguard.Ip.formatIp(mesh_ip, &mesh_ip_buf);

            try writeFormatted(stdout, "  your mesh IP: {s}\n", .{mesh_ip_str});
            try writeFormatted(stdout, "  punch in: {d} minute(s)\n\n", .{punch_delay_min});
            try stdout.writeAll("Send this command to your peer:\n\n  meshguard connect --join ");
            try stdout.writeAll(uri);
            try stdout.writeAll("\n\n");
            try stdout.writeAll("Paste peer's response token: ");

            // Read peer's response token from stdin
            const stdin: std.fs.File = .{ .handle = std.posix.STDIN_FILENO };
            var input_buf: [256]u8 = undefined;
            const input_len = stdin.read(&input_buf) catch {
                try stderr.writeAll("\nerror: failed to read stdin\n");
                std.process.exit(1);
            };
            if (input_len == 0) {
                try stderr.writeAll("\nerror: no input received\n");
                std.process.exit(1);
            }
            const peer_uri = std.mem.trimRight(u8, input_buf[0..input_len], "\n\r \t");

            // Decode peer's token
            const peer_token = CoordinatedPunch.decodeTokenUri(peer_uri) catch {
                try stderr.writeAll("error: invalid peer token\n");
                std.process.exit(1);
            };

            var peer_ip_buf: [15]u8 = undefined;
            const peer_ip = lib.wireguard.Ip.formatIp(peer_token.mesh_ip, &peer_ip_buf);
            var peer_ep_buf: [15]u8 = undefined;
            const peer_ep = lib.wireguard.Ip.formatIp(peer_token.stun_addr, &peer_ep_buf);
            try writeFormatted(stdout, "\n  peer: {s} at {s}:{d}\n", .{ peer_ip, peer_ep, peer_token.stun_port });

            // Run punch loop
            const result = CoordinatedPunch.runPunchLoop(
                &socket,
                kp.public_key.toBytes(),
                nonce,
                peer_token.nonce,
                peer_token.stun_addr,
                peer_token.stun_port,
                punch_time,
                stun_server,
                stdout,
            );

            if (result) |punch| {
                try finalizePunch(allocator, config_dir, stdout, stderr, punch, peer_token);
            } else {
                try stderr.writeAll("\n  ✗ punch failed after 3 attempts\n");
                try stderr.writeAll("  hint: ensure both peers are running and behind cone NAT\n");
                std.process.exit(1);
            }
        },
        .join => {
            // ── Joiner flow ──
            const peer_uri = join_token_arg orelse {
                try stderr.writeAll("error: --join requires a mg:// token\n");
                std.process.exit(1);
            };

            const peer_token = CoordinatedPunch.decodeTokenUri(peer_uri) catch {
                try stderr.writeAll("error: invalid token\n");
                std.process.exit(1);
            };

            try stdout.writeAll("\n── Coordinated Punch (joiner) ──\n\n");

            var peer_ip_buf: [15]u8 = undefined;
            const peer_ip = lib.wireguard.Ip.formatIp(peer_token.mesh_ip, &peer_ip_buf);
            var peer_ep_buf: [15]u8 = undefined;
            const peer_ep = lib.wireguard.Ip.formatIp(peer_token.stun_addr, &peer_ep_buf);
            try writeFormatted(stdout, "  peer: {s} at {s}:{d}\n", .{ peer_ip, peer_ep, peer_token.stun_port });

            // Use same punch_time from initiator's token
            const punch_time = peer_token.punch_time;

            // Generate our nonce
            var nonce: [8]u8 = undefined;
            std.crypto.random.bytes(&nonce);

            // Build response token
            var response_token = CoordinatedPunch.Token{
                .pubkey = kp.public_key.toBytes(),
                .wg_pubkey = wg_public_key,
                .stun_addr = stun_result.external.addr,
                .stun_port = stun_result.external.port,
                .mesh_ip = mesh_ip,
                .punch_time = punch_time,
                .nonce = nonce,
                .stun_server = stun_server.host,
                .stun_server_port = stun_server.port,
                .nat_type = @intFromEnum(stun_result.nat_type),
                .signature = .{ 0, 0, 0, 0, 0, 0 },
            };
            CoordinatedPunch.signTokenHash(&response_token);

            var uri_buf: [156]u8 = undefined;
            const uri = CoordinatedPunch.encodeTokenUri(&response_token, &uri_buf);

            try stdout.writeAll("\nPaste this response token on your peer's terminal:\n\n  ");
            try stdout.writeAll(uri);
            try stdout.writeAll("\n\n");

            const secs_until = if (punch_time > ntp_time) punch_time - ntp_time else 0;
            try writeFormatted(stdout, "  punch in ~{d}s — waiting...\n", .{secs_until});

            // Run punch loop
            const result = CoordinatedPunch.runPunchLoop(
                &socket,
                kp.public_key.toBytes(),
                nonce,
                peer_token.nonce,
                peer_token.stun_addr,
                peer_token.stun_port,
                punch_time,
                stun_server,
                stdout,
            );

            if (result) |punch| {
                try finalizePunch(allocator, config_dir, stdout, stderr, punch, peer_token);
            } else {
                try stderr.writeAll("\n  ✗ punch failed after 3 attempts\n");
                try stderr.writeAll("  hint: ensure both peers are running and behind cone NAT\n");
                std.process.exit(1);
            }
        },
    }
}

/// Post-punch: auto-trust peer, save seed, offer systemd restart.
fn finalizePunch(
    allocator: std.mem.Allocator,
    config_dir: []const u8,
    stdout: std.fs.File,
    stderr: std.fs.File,
    punch: lib.nat.CoordinatedPunch.PunchResult,
    peer_token: lib.nat.CoordinatedPunch.Token,
) !void {
    var peer_ep_buf: [21]u8 = undefined;
    const peer_ep = std.fmt.bufPrint(&peer_ep_buf, "{d}.{d}.{d}.{d}:{d}", .{
        punch.peer_addr[0], punch.peer_addr[1], punch.peer_addr[2], punch.peer_addr[3],
        punch.peer_port,
    }) catch "?";

    var peer_mesh_buf: [15]u8 = undefined;
    const peer_mesh = lib.wireguard.Ip.formatIp(peer_token.mesh_ip, &peer_mesh_buf);

    try stdout.writeAll("\n  ✓ Direct connection established!\n");
    try writeFormatted(stdout, "    peer: {s}\n", .{peer_mesh});
    try writeFormatted(stdout, "    endpoint: {s}\n\n", .{peer_ep});

    // Auto-trust the peer
    const b64 = std.base64.standard.Encoder;
    var pk_b64_buf: [44]u8 = undefined;
    _ = b64.encode(&pk_b64_buf, &peer_token.pubkey);

    lib.identity.Trust.addAuthorizedKey(allocator, config_dir, &pk_b64_buf, "punch-peer") catch |err| {
        try writeFormatted(stderr, "  warning: could not auto-trust peer: {s}\n", .{@errorName(err)});
    };
    try stdout.writeAll("  peer trusted (auto-added to authorized keys)\n");

    // Save punched endpoint as seed
    lib.nat.CoordinatedPunch.savePunchedSeed(allocator, config_dir, punch.peer_addr, punch.peer_port) catch |err| {
        try writeFormatted(stderr, "  warning: could not save seed: {s}\n", .{@errorName(err)});
    };
    try stdout.writeAll("  seed saved to config\n\n");

    // Offer next steps
    try stdout.writeAll("  To start the mesh:\n");
    try writeFormatted(stdout, "    meshguard up --seed {s}\n\n", .{peer_ep});

    // Check if systemd service exists and offer auto-restart
    const service_exists = blk: {
        const stat = std.fs.openFileAbsolute("/etc/systemd/system/meshguard.service", .{}) catch break :blk false;
        stat.close();
        break :blk true;
    };

    if (service_exists) {
        try stdout.writeAll("  systemd service detected. Restart now? [Y/n] ");

        const stdin: std.fs.File = .{ .handle = std.posix.STDIN_FILENO };
        var input_buf: [16]u8 = undefined;
        const input_len = stdin.read(&input_buf) catch 0;
        const answer = std.mem.trimRight(u8, input_buf[0..input_len], "\n\r \t");

        if (answer.len == 0 or answer[0] == 'Y' or answer[0] == 'y') {
            try stdout.writeAll("  restarting meshguard service...\n");
            var child = std.process.Child.init(&.{ "systemctl", "restart", "meshguard" }, allocator);
            child.stderr_behavior = .Ignore;
            child.stdout_behavior = .Ignore;
            const term = child.spawnAndWait() catch {
                try stderr.writeAll("  warning: failed to restart service. Run manually:\n");
                try stderr.writeAll("    sudo systemctl restart meshguard\n");
                return;
            };
            if (term.Exited == 0) {
                try stdout.writeAll("  ✓ meshguard service restarted\n");
            } else {
                try stderr.writeAll("  warning: systemctl returned non-zero. Run manually:\n");
                try stderr.writeAll("    sudo systemctl restart meshguard\n");
            }
        } else {
            try stdout.writeAll("  Remember to restart the service soon (NAT mapping expires):\n");
            try stdout.writeAll("    sudo systemctl restart meshguard\n");
        }
    }
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
const MAX_RX_WORKERS: usize = 8; // Parallel UDP RX + decrypt workers
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
    const Pipeline = lib.net.Pipeline;
    const MAX_PEERS = lib.wireguard.Device.MAX_PEERS;

    var tun_buf: [Offload.VNET_HDR_LEN + 65535]u8 align(@alignOf(Offload.VirtioNetHdr)) = undefined;
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
                    // ── ZERO-COPY GSO path ──
                    // Split directly into pool buffers, eliminating the seg_bufs intermediate copy.
                    // All segments share the same dst IP → one peer lookup for entire GSO batch.
                    if (ip_data.len < 20) continue;
                    const dst_ip: [4]u8 = ip_data[16..20].*;
                    const peer_slot = wg_dev.lookupByMeshIp(dst_ip) orelse continue;
                    const peer = wg_dev.peers[peer_slot] orelse continue;
                    if (peer.endpoint_addr[0] == 0) continue;

                    // Ensure we have enough buffers in local cache (up to 64 segments)
                    const max_segs: usize = 64;
                    while (buf_cache_count < max_segs) {
                        const remaining = buf_cache[buf_cache_count..];
                        const filled = pool.allocBufferBatch(remaining);
                        if (filled == 0) break;
                        buf_cache_count += filled;
                    }
                    if (buf_cache_count == 0) continue;

                    const avail = @min(buf_cache_count, max_segs);

                    // Build output slices pointing directly into pool buffer data areas
                    var pool_slices: [64][]u8 = undefined;
                    var pool_indices: [64]u16 = undefined;
                    for (0..avail) |i| {
                        const idx = buf_cache[buf_cache_count - 1 - i];
                        pool_indices[i] = idx;
                        pool_slices[i] = pool.buffers[idx].data[Pipeline.WG_HEADER_LEN..];
                    }

                    var seg_sizes: [64]usize = undefined;
                    const seg_count = Offload.gsoSplit(
                        vhdr.*,
                        ip_data,
                        pool_slices[0..avail],
                        &seg_sizes,
                        avail,
                    );

                    if (seg_count == 0) continue;
                    // Consume the used buffers from cache
                    buf_cache_count -= seg_count;

                    // Allocate or reuse batch for this peer
                    if (local_batches[peer_slot] == null) {
                        local_batches[peer_slot] = pool.allocBatch() orelse continue;
                    }
                    touched_peers[peer_slot] = true;

                    // Stage all segments into the batch (no memcpy — data already in pool buffers)
                    for (0..seg_count) |s| {
                        const buf_idx = pool_indices[s];
                        var pkt = &pool.buffers[buf_idx];
                        pkt.len = @intCast(seg_sizes[s]);
                        pkt.endpoint_addr = peer.endpoint_addr;
                        pkt.endpoint_port = peer.endpoint_port;

                        const batch_idx = local_batches[peer_slot].?;
                        var batch = &pool.batches[batch_idx];
                        batch.buf_indices[batch.count] = buf_idx;
                        batch.lengths[batch.count] = @intCast(seg_sizes[s]);
                        batch.count += 1;

                        if (batch.count >= Pipeline.BATCH_SIZE) {
                            dispatchBatch(wg_dev, pool, crypto_q, @intCast(peer_slot), batch_idx);
                            local_batches[peer_slot] = pool.allocBatch();
                        }
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

/// io_uring-based TUN reader pipeline.
/// Replaces poll()+read() with pre-submitted io_uring read SQEs (32 in-flight).
/// All packet processing (GSO split, peer lookup, batch staging) is identical
/// to tunReaderPipeline.
fn tunReaderIoUring(
    running: *const std.atomic.Value(bool),
    wg_dev: *lib.wireguard.Device.WgDevice,
    tun_fd: posix.fd_t,
    vnet_hdr: bool,
    pool: *lib.net.Pipeline.DataPlanePool,
    crypto_q: *lib.net.Pipeline.CryptoQueue,
) void {
    const Offload = lib.net.Offload;
    const Pipeline = lib.net.Pipeline;
    const MAX_PEERS = lib.wireguard.Device.MAX_PEERS;
    const IoUringReader = lib.net.IoUring.TunRingReader;

    // Initialize io_uring reader — if this fails, fall back to poll+read
    var reader = IoUringReader.init(tun_fd) catch {
        // Fallback to legacy poll+read path
        tunReaderPipeline(running, wg_dev, tun_fd, vnet_hdr, pool, crypto_q);
        return;
    };
    defer reader.deinit();

    // Per-peer batch building: thread-local staging
    var local_batches: [MAX_PEERS]?u16 = .{null} ** MAX_PEERS;

    // Thread-local buffer cache to avoid per-packet mutex contention
    const BUF_CACHE_SIZE: usize = 128;
    var buf_cache: [BUF_CACHE_SIZE]u16 = undefined;
    var buf_cache_count: usize = 0;

    // CQE batch buffer
    var cqes: [IoUringReader.RING_DEPTH]std.os.linux.io_uring_cqe = undefined;

    while (running.load(.acquire)) {
        // Wait for at least 1 completed read
        const n_cqes = reader.waitCompletions(&cqes, 1) catch continue;
        if (n_cqes == 0) continue;

        // Track which peers have partial batches to flush
        var touched_peers: [MAX_PEERS]bool = .{false} ** MAX_PEERS;

        // Process each completed read
        for (cqes[0..n_cqes]) |cqe| {
            const slot: u32 = @intCast(cqe.user_data);

            // Get the read data from this CQE
            const data = reader.getReadData(cqe) orelse {
                // Error or zero-length read — resubmit and continue
                reader.resubmit(slot, tun_fd) catch {};
                continue;
            };

            const n = data.len;

            if (vnet_hdr) {
                if (n <= Offload.VNET_HDR_LEN) {
                    reader.resubmit(slot, tun_fd) catch {};
                    continue;
                }
                const vhdr: *const Offload.VirtioNetHdr = @ptrCast(@alignCast(data.ptr));
                const ip_data = data[Offload.VNET_HDR_LEN..];

                if (vhdr.gso_type != Offload.GSO_NONE) {
                    // ── ZERO-COPY GSO path (identical to tunReaderPipeline) ──
                    if (ip_data.len < 20) {
                        reader.resubmit(slot, tun_fd) catch {};
                        continue;
                    }
                    const dst_ip: [4]u8 = ip_data[16..20].*;
                    const peer_slot = wg_dev.lookupByMeshIp(dst_ip) orelse {
                        reader.resubmit(slot, tun_fd) catch {};
                        continue;
                    };
                    const peer = wg_dev.peers[peer_slot] orelse {
                        reader.resubmit(slot, tun_fd) catch {};
                        continue;
                    };
                    if (peer.endpoint_addr[0] == 0) {
                        reader.resubmit(slot, tun_fd) catch {};
                        continue;
                    }

                    const max_segs: usize = 64;
                    while (buf_cache_count < max_segs) {
                        const remaining = buf_cache[buf_cache_count..];
                        const filled = pool.allocBufferBatch(remaining);
                        if (filled == 0) break;
                        buf_cache_count += filled;
                    }
                    if (buf_cache_count == 0) {
                        reader.resubmit(slot, tun_fd) catch {};
                        continue;
                    }

                    const avail = @min(buf_cache_count, max_segs);
                    var pool_slices: [64][]u8 = undefined;
                    var pool_indices: [64]u16 = undefined;
                    for (0..avail) |i| {
                        const idx = buf_cache[buf_cache_count - 1 - i];
                        pool_indices[i] = idx;
                        pool_slices[i] = pool.buffers[idx].data[Pipeline.WG_HEADER_LEN..];
                    }

                    var seg_sizes: [64]usize = undefined;
                    const seg_count = Offload.gsoSplit(
                        vhdr.*,
                        ip_data,
                        pool_slices[0..avail],
                        &seg_sizes,
                        avail,
                    );

                    if (seg_count == 0) {
                        reader.resubmit(slot, tun_fd) catch {};
                        continue;
                    }
                    buf_cache_count -= seg_count;

                    if (local_batches[peer_slot] == null) {
                        local_batches[peer_slot] = pool.allocBatch() orelse {
                            reader.resubmit(slot, tun_fd) catch {};
                            continue;
                        };
                    }
                    touched_peers[peer_slot] = true;

                    for (0..seg_count) |s| {
                        const buf_idx = pool_indices[s];
                        var pkt = &pool.buffers[buf_idx];
                        pkt.len = @intCast(seg_sizes[s]);
                        pkt.endpoint_addr = peer.endpoint_addr;
                        pkt.endpoint_port = peer.endpoint_port;

                        const batch_idx = local_batches[peer_slot].?;
                        var batch = &pool.batches[batch_idx];
                        batch.buf_indices[batch.count] = buf_idx;
                        batch.lengths[batch.count] = @intCast(seg_sizes[s]);
                        batch.count += 1;

                        if (batch.count >= Pipeline.BATCH_SIZE) {
                            dispatchBatch(wg_dev, pool, crypto_q, @intCast(peer_slot), batch_idx);
                            local_batches[peer_slot] = pool.allocBatch();
                        }
                    }
                } else {
                    if (ip_data.len < 20) {
                        reader.resubmit(slot, tun_fd) catch {};
                        continue;
                    }
                    // Need mutable slice for checksum — copy into a temp buffer
                    // because io_uring slot buffer may be const
                    var mutable_buf: [65535]u8 = undefined;
                    const pkt_len = ip_data.len;
                    @memcpy(mutable_buf[0..pkt_len], ip_data);
                    Offload.completeChecksum(vhdr.*, mutable_buf[0..pkt_len]);
                    stageSegment(wg_dev, pool, crypto_q, mutable_buf[0..pkt_len], &local_batches, &touched_peers, &buf_cache, &buf_cache_count);
                }
            } else {
                if (n < 20) {
                    reader.resubmit(slot, tun_fd) catch {};
                    continue;
                }
                stageSegment(wg_dev, pool, crypto_q, data[0..n], &local_batches, &touched_peers, &buf_cache, &buf_cache_count);
            }

            // Resubmit read SQE for this slot
            reader.resubmit(slot, tun_fd) catch {};
        }

        // Flush partial batches for all touched peers
        for (0..MAX_PEERS) |slot_idx| {
            if (touched_peers[slot_idx]) {
                if (local_batches[slot_idx]) |batch_idx| {
                    dispatchBatch(wg_dev, pool, crypto_q, @intCast(slot_idx), batch_idx);
                    local_batches[slot_idx] = null;
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
/// Uses zero-copy GSO (iovec into pool buffers) with flush-and-continue;
/// falls back to sendmmsg only if the kernel rejects GSO.
fn flushPeerTxRing(
    peer: *lib.wireguard.Device.WgPeer,
    pool: *lib.net.Pipeline.DataPlanePool,
    udp_fd: posix.fd_t,
) void {
    const Pipeline = lib.net.Pipeline;
    const BatchUdp = lib.net.BatchUdp;

    // Track GSO availability — start optimistic, disable on first failure
    const GsoState = struct {
        var available: bool = true;
        var logged: bool = false;
    };

    // Zero-copy GSO sender — builds iovec array pointing into pool buffers
    var gso_tx = BatchUdp.ZeroCopyGSOSender{};
    // Sendmmsg fallback — only used if GSO fails
    var mmsg_tx = BatchUdp.BatchSender{};

    while (!peer.tx_ring.isEmpty()) {
        const head_idx = peer.tx_ring.peekHead();
        var head_batch = &pool.batches[head_idx];

        // Strict ROB: if next sequential batch isn't Ready, stop!
        if (head_batch.state.load(.acquire) != @intFromEnum(Pipeline.BatchState.Ready)) break;

        if (GsoState.available and head_batch.count > 1) {
            // ── Zero-copy GSO path ──
            for (0..head_batch.count) |i| {
                const pkt = &pool.buffers[head_batch.buf_indices[i]];
                if (pkt.len > 0) {
                    if (!gso_tx.append(pkt.data[0..pkt.len])) {
                        // Buffer full — flush current chunk, reset, continue
                        const result = gso_tx.sendGSO(udp_fd, peer.endpoint_addr, peer.endpoint_port);
                        if (result.bytes_sent == 0 and result.err != 0) {
                            // GSO syscall failed — fall through to sendmmsg
                            GsoState.available = false;
                            if (!GsoState.logged) {
                                GsoState.logged = true;
                                var err_buf: [128]u8 = undefined;
                                const msg = std.fmt.bufPrint(&err_buf, "  GSO failed: errno={d}, using sendmmsg fallback\n", .{result.err}) catch "  GSO failed\n";
                                _ = posix.write(2, msg) catch {};
                            }
                            break;
                        }
                        gso_tx.reset();
                        _ = gso_tx.append(pkt.data[0..pkt.len]);
                    }
                }
            }

            // Flush remaining GSO segments for this batch
            if (GsoState.available and gso_tx.used > 0) {
                const result = gso_tx.sendGSO(udp_fd, peer.endpoint_addr, peer.endpoint_port);
                if (result.bytes_sent == 0 and result.err != 0) {
                    GsoState.available = false;
                    if (!GsoState.logged) {
                        GsoState.logged = true;
                        var err_buf: [128]u8 = undefined;
                        const msg = std.fmt.bufPrint(&err_buf, "  GSO failed: errno={d}, using sendmmsg fallback\n", .{result.err}) catch "  GSO failed\n";
                        _ = posix.write(2, msg) catch {};
                    }
                }
                gso_tx.reset();
            }

            if (GsoState.available) {
                // GSO succeeded — free resources and advance
                pool.freeBuffers(head_batch.buf_indices[0..head_batch.count]);
                head_batch.state.store(@intFromEnum(Pipeline.BatchState.Empty), .release);
                pool.freeBatch(head_idx);
                peer.tx_ring.advanceHead();
                continue;
            }
            // If GSO just failed, fall through to sendmmsg for this batch
        }

        // ── sendmmsg fallback path ──
        for (0..head_batch.count) |i| {
            const pkt = &pool.buffers[head_batch.buf_indices[i]];
            if (pkt.len > 0) {
                mmsg_tx.queue(pkt.data[0..pkt.len], peer.endpoint_addr, peer.endpoint_port);
            }
        }

        if (mmsg_tx.count >= BatchUdp.BATCH_SIZE - Pipeline.BATCH_SIZE) {
            _ = mmsg_tx.flush(udp_fd);
        }

        pool.freeBuffers(head_batch.buf_indices[0..head_batch.count]);
        head_batch.state.store(@intFromEnum(Pipeline.BatchState.Empty), .release);
        pool.freeBatch(head_idx);
        peer.tx_ring.advanceHead();
    }

    // Flush any remaining queued packets
    if (mmsg_tx.count > 0) {
        _ = mmsg_tx.flush(udp_fd);
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
    var tun_buf: [Offload.VNET_HDR_LEN + 65535]u8 align(@alignOf(Offload.VirtioNetHdr)) = undefined;
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

/// Parallel decrypt worker: pulls encrypted transport packets from the DecryptQueue,
/// decrypts them using wg_dev.decryptTransport (thread-safe via replay_lock), and writes
/// plaintext to TUN. This parallelizes the download path across N cores.
///
/// Each worker has its own TUN queue fd for parallel writev calls.
fn decryptRxWorker(
    running: *const std.atomic.Value(bool),
    wg_dev: *lib.wireguard.Device.WgDevice,
    tun_dev_ptr: *const lib.net.Tun.TunDevice,
    tun_fd: posix.fd_t,
    decrypt_q: *lib.net.Pipeline.DecryptQueue,
    service_filter: *const lib.services.Policy.ServiceFilter,
    membership: *lib.discovery.Membership.MembershipTable,
) void {
    const Offload = lib.net.Offload;

    // Per-worker decrypt buffer
    var out_buf: [1500]u8 = undefined;

    while (running.load(.acquire)) {
        const result = decrypt_q.pop() orelse break; // null = closed

        const pkt = decrypt_q.getPacket(result.idx);
        if (wg_dev.decryptTransport(pkt, &out_buf)) |dec| {
            // Service filter: check port access before TUN write
            if (lib.services.Policy.parseTransportHeader(out_buf[0..dec.len])) |ti| {
                const peer = wg_dev.peers[dec.slot] orelse continue;
                const org_pk = if (membership.peers.getPtr(peer.identity_key)) |mp| mp.org_pubkey else null;
                if (!service_filter.check(peer.identity_key, org_pk, ti.proto, ti.dst_port)) continue;
            }

            // Write decrypted packet to TUN
            if (tun_dev_ptr.vnet_hdr) {
                var vhdr_bytes = std.mem.zeroes([Offload.VNET_HDR_LEN]u8);
                var iov = [_]posix.iovec_const{
                    .{ .base = &vhdr_bytes, .len = Offload.VNET_HDR_LEN },
                    .{ .base = out_buf[0..dec.len].ptr, .len = dec.len },
                };
                _ = posix.writev(tun_fd, &iov) catch {};
            } else {
                _ = posix.write(tun_fd, out_buf[0..dec.len]) catch {};
            }
        } else |_| {}
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
    decrypt_slots: *[64]usize,
    n_decrypted: *usize,
    service_filter: *const lib.services.Policy.ServiceFilter,
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
                    // Check service filter before buffering
                    const PolicyMod = lib.services.Policy;
                    if (PolicyMod.parseTransportHeader(decrypt_storage[n_decrypted.*][0..result.len])) |ti| {
                        if (wg_dev.peers[result.slot]) |peer| {
                            const org_pk = if (swim.membership.peers.getPtr(peer.identity_key)) |mp| mp.org_pubkey else null;
                            if (!service_filter.check(peer.identity_key, org_pk, ti.proto, ti.dst_port)) return;
                        }
                    }
                    decrypt_lens[n_decrypted.*] = result.len;
                    decrypt_slots[n_decrypted.*] = result.slot;
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
    service_filter: *const lib.services.Policy.ServiceFilter,
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

    // Set all TUN fds to non-blocking (only for legacy poll+read path).
    // io_uring manages its own waiting and needs blocking fds.
    const use_io_uring = lib.net.IoUring.isAvailable();
    if (!use_io_uring) {
        for (0..opened_workers) |w| {
            const flags = posix.fcntl(tun_fds[w], posix.F.GETFL, 0) catch continue;
            _ = posix.fcntl(tun_fds[w], posix.F.SETFL, flags | @as(usize, 0x800)) catch {};
        }
    }

    // Total thread pool
    const MAX_TOTAL_THREADS = MAX_WORKERS + MAX_ENCRYPT_WORKERS + MAX_RX_WORKERS;
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

        // Create dedicated GSO socket for data-plane sends (send-only, no bind).
        // This socket has IP_PMTUDISC_PROBE (required for >MTU GSO sendmsg)
        // so it's separate from the control-plane socket used for handshakes/SWIM.
        const Udp = lib.net.Udp;
        const gso_fd = blk: {
            const sock = Udp.UdpSocket.createGSOSender() catch {
                writeFormatted(stdout, "  warning: GSO socket failed, data-plane uses shared socket\n", .{}) catch {};
                break :blk udp_sock.fd;
            };
            writeFormatted(stdout, "  GSO send socket: fd={d} (IP_PMTUDISC_PROBE, SO_SNDBUF=256K)\n", .{sock.fd}) catch {};
            break :blk sock.fd;
        };

        // Log io_uring TUN reader choice (detection happened above)
        if (use_io_uring) {
            writeFormatted(stdout, "  io_uring: available, using ring-based TUN reader\n", .{}) catch {};
        } else {
            writeFormatted(stdout, "  io_uring: unavailable, using poll+read TUN reader\n", .{}) catch {};
        }

        // Parallel pipeline: TUN readers + encrypt workers
        for (0..opened_workers) |w| {
            const args = .{
                &swim.running,
                wg_dev,
                tun_fds[w],
                tun_dev.vnet_hdr,
                data_pool,
                crypto_queue,
            };
            const thread = if (use_io_uring)
                std.Thread.spawn(.{}, tunReaderIoUring, args)
            else
                std.Thread.spawn(.{}, tunReaderPipeline, args);

            threads[spawned] = thread catch {
                writeFormatted(stdout, "  warning: failed to spawn TUN reader {d}\n", .{w}) catch {};
                continue;
            };
            spawned += 1;
        }

        for (0..n_encrypt) |e| {
            threads[spawned] = std.Thread.spawn(.{}, cryptoWorkerPipeline, .{
                &swim.running,
                wg_dev,
                gso_fd,
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
    // Enable UDP GRO: kernel coalesces consecutive UDP segments into one 64KB buffer,
    // reducing recvmsg syscalls by ~40x compared to recvmmsg with individual buffers.
    udp_sock.enableGRO();

    // Enable busy-polling: kernel spins for 50μs inside poll() before sleeping,
    // reducing wake-up latency for high-throughput bursts.
    const SO_BUSY_POLL = 46;
    const busy_poll_us: u32 = 50; // microseconds
    posix.setsockopt(udp_sock.fd, posix.SOL.SOCKET, SO_BUSY_POLL, std.mem.asBytes(&busy_poll_us)) catch {};

    var gro_rx = BatchUdp.GROReceiver{};
    const MAX_DECRYPTED = 64;
    var decrypt_storage: [MAX_DECRYPTED][1500]u8 = undefined;
    var decrypt_lens: [MAX_DECRYPTED]usize = undefined;
    var decrypt_slots: [MAX_DECRYPTED]usize = undefined;

    while (swim.running.load(.acquire)) {
        var fds = [_]posix.pollfd{
            .{ .fd = udp_sock.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = posix.poll(&fds, 50) catch continue;

        if (fds[0].revents & posix.POLL.IN != 0) {
            var n_decrypted: usize = 0;

            // Drain loop: process all pending GRO batches before returning to poll()
            while (true) {
                const total_bytes = gro_rx.recvGRO(udp_sock.fd);
                if (total_bytes == 0) break; // EAGAIN — socket drained

                const sender = gro_rx.getSender();
                const seg_size: usize = if (gro_rx.segment_size > 0) gro_rx.segment_size else total_bytes;

                var offset: usize = 0;
                while (offset < total_bytes) {
                    const remaining = total_bytes - offset;
                    const pkt_len = @min(seg_size, remaining);
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
                        &decrypt_slots,
                        &n_decrypted,
                        service_filter,
                    );

                    offset += pkt_len;
                }

                // Flush decrypted packets to TUN if buffer is filling up
                if (n_decrypted >= MAX_DECRYPTED - 44) {
                    if (n_decrypted > 0) {
                        if (tun_dev.vnet_hdr) {
                            writeCoalescedToTun(&tun_dev, &decrypt_storage, &decrypt_lens, n_decrypted);
                        } else {
                            for (0..n_decrypted) |d| {
                                _ = posix.write(tun_dev.fd, decrypt_storage[d][0..decrypt_lens[d]]) catch {};
                            }
                        }
                        n_decrypted = 0;
                    }
                }
            }

            // Final flush of remaining decrypted packets
            if (n_decrypted > 0) {
                if (tun_dev.vnet_hdr) {
                    writeCoalescedToTun(&tun_dev, &decrypt_storage, &decrypt_lens, n_decrypted);
                } else {
                    for (0..n_decrypted) |d| {
                        _ = posix.write(tun_dev.fd, decrypt_storage[d][0..decrypt_lens[d]]) catch {};
                    }
                }
            }
        }

        swim.tickTimersOnly();
    }

    // Send leave announcement safely from the main thread
    swim.broadcastLeave();

    // Signal encrypt workers to stop, then wait for all threads
    if (n_encrypt > 0) {
        crypto_queue.close();
    }
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
        // Fallback for userspace WG mode — kernel doesn't know about the device
        try writeFormatted(stdout, "meshguard is running.\n  interface: mg0 (index {d})\n  mode: userspace\n", .{ifindex});

        // Show config info
        const config_dir = lib.config.Config.ensureConfigDir(allocator) catch null;
        if (config_dir) |dir| {
            defer allocator.free(dir);

            // Identity
            const kp = Identity.load(allocator, dir) catch null;
            if (kp) |k| {
                const pk = k.public_key.toBytes();
                try writeFormatted(stdout, "  public key: {x:0>2}{x:0>2}{x:0>2}{x:0>2}...{x:0>2}{x:0>2}\n", .{
                    pk[0], pk[1], pk[2], pk[3], pk[30], pk[31],
                });
                const mesh_ip = lib.wireguard.Ip.deriveFromPubkey(k.public_key);
                try writeFormatted(stdout, "  mesh IP: {d}.{d}.{d}.{d}\n", .{ mesh_ip[0], mesh_ip[1], mesh_ip[2], mesh_ip[3] });
            }

            // Authorized peers
            const peers = lib.identity.Trust.loadAuthorizedKeys(allocator, dir) catch null;
            if (peers) |p| {
                defer {
                    for (p) |peer| allocator.free(peer.name);
                    allocator.free(p);
                }
                try writeFormatted(stdout, "  peers trusted: {d}\n", .{p.len});
            }

            // Seeds from file
            const seeds_path = std.fs.path.join(allocator, &.{ dir, "seeds" }) catch null;
            if (seeds_path) |sp| {
                defer allocator.free(sp);
                const sf = std.fs.openFileAbsolute(sp, .{}) catch null;
                if (sf) |f| {
                    defer f.close();
                    var sbuf: [512]u8 = undefined;
                    const sread = f.readAll(&sbuf) catch 0;
                    if (sread > 0) {
                        const seeds_data = std.mem.trimRight(u8, sbuf[0..sread], "\n\r \t");
                        // Count lines
                        var seed_count: u32 = 0;
                        var rest: []const u8 = seeds_data;
                        while (rest.len > 0) {
                            const nl = std.mem.indexOfScalar(u8, rest, '\n');
                            const line = if (nl) |n| rest[0..n] else rest;
                            rest = if (nl) |n| rest[n + 1 ..] else rest[rest.len..];
                            if (std.mem.trimRight(u8, line, "\r \t").len > 0) seed_count += 1;
                        }
                        try writeFormatted(stdout, "  seeds: {d}\n", .{seed_count});
                    }
                }
            }
        }

        // Systemd uptime and memory
        {
            var child = std.process.Child.init(&.{
                "systemctl",                                     "show",       "meshguard",
                "--property=ActiveEnterTimestamp,MemoryCurrent", "--no-pager",
            }, allocator);
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Ignore;
            if (child.spawn()) |_| {} else |_| return;

            var out_buf: [512]u8 = undefined;
            const out_read = child.stdout.?.readAll(&out_buf) catch 0;
            _ = child.wait() catch {};

            if (out_read > 0) {
                const output = out_buf[0..out_read];

                // Parse ActiveEnterTimestamp
                if (std.mem.indexOf(u8, output, "ActiveEnterTimestamp=")) |pos| {
                    const line_start = pos + "ActiveEnterTimestamp=".len;
                    const line_end = std.mem.indexOfScalarPos(u8, output, line_start, '\n') orelse output.len;
                    const ts_str = std.mem.trimRight(u8, output[line_start..line_end], "\r \t");
                    if (ts_str.len > 0) {
                        try writeFormatted(stdout, "  started: {s}\n", .{ts_str});
                    }
                }

                // Parse MemoryCurrent
                if (std.mem.indexOf(u8, output, "MemoryCurrent=")) |pos| {
                    const line_start = pos + "MemoryCurrent=".len;
                    const line_end = std.mem.indexOfScalarPos(u8, output, line_start, '\n') orelse output.len;
                    const mem_str = std.mem.trimRight(u8, output[line_start..line_end], "\r \t");
                    const mem_bytes = std.fmt.parseInt(u64, mem_str, 10) catch 0;
                    if (mem_bytes > 0) {
                        const mb_whole = mem_bytes / (1024 * 1024);
                        const mb_frac = (mem_bytes * 10 / (1024 * 1024)) % 10;
                        try writeFormatted(stdout, "  memory: {d}.{d}M\n", .{ mb_whole, mb_frac });
                    }
                }
            }
        }
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

// ─── Service Access Control ───

const service_usage =
    \\meshguard service — manage service access policies
    \\
    \\USAGE:
    \\  meshguard service <command> [options]
    \\
    \\COMMANDS:
    \\  list                        List all service policies
    \\  allow <proto> <port>        Add an allow rule
    \\  deny <proto> <port>         Add a deny rule
    \\  default <allow|deny>        Set default action (when no rule matches)
    \\  show [peer-name]            Show effective policy for a peer (or global)
    \\  reset                       Remove all service policies
    \\
    \\OPTIONS:
    \\  --peer <name>               Target a specific peer (by alias or pubkey)
    \\  --org <name>                Target an org
    \\  (no flag)                   Target the global policy
    \\
    \\EXAMPLES:
    \\  meshguard service allow tcp 22              # Global: allow SSH
    \\  meshguard service deny all                  # Global: deny everything else
    \\  meshguard service allow --peer node-1 tcp 5432  # Peer: allow Postgres
    \\  meshguard service default deny              # Switch to default-deny
    \\  meshguard service list                      # Show all policies
    \\
;

fn cmdService(allocator: std.mem.Allocator, extra_args: []const []const u8) !void {
    const stdout = getStdOut();
    const stderr = getStdErr();

    const config_dir = try Config.ensureConfigDir(allocator);
    defer allocator.free(config_dir);

    if (extra_args.len == 0) {
        try stdout.writeAll(service_usage);
        return;
    }

    const subcmd = extra_args[0];

    if (std.mem.eql(u8, subcmd, "-h") or std.mem.eql(u8, subcmd, "--help") or std.mem.eql(u8, subcmd, "help")) {
        try stdout.writeAll(service_usage);
        return;
    }

    if (std.mem.eql(u8, subcmd, "list")) {
        try cmdServiceList(allocator, config_dir);
        return;
    }

    if (std.mem.eql(u8, subcmd, "default")) {
        if (extra_args.len < 2) {
            try stderr.writeAll("usage: meshguard service default <allow|deny>\n");
            std.process.exit(1);
        }
        try cmdServiceDefault(allocator, config_dir, extra_args[1]);
        return;
    }

    if (std.mem.eql(u8, subcmd, "show")) {
        const target = if (extra_args.len >= 2) extra_args[1] else null;
        try cmdServiceShow(allocator, config_dir, target);
        return;
    }

    if (std.mem.eql(u8, subcmd, "reset")) {
        try cmdServiceReset(allocator, config_dir);
        return;
    }

    if (std.mem.eql(u8, subcmd, "allow") or std.mem.eql(u8, subcmd, "deny")) {
        try cmdServiceAddRule(allocator, config_dir, extra_args);
        return;
    }

    try writeFormatted(stderr, "error: unknown service command '{s}'\n\n", .{subcmd});
    try stdout.writeAll(service_usage);
    std.process.exit(1);
}

fn ensureServicesDir(allocator: std.mem.Allocator, config_dir: []const u8) !void {
    const services_dir = try std.fs.path.join(allocator, &.{ config_dir, "services" });
    defer allocator.free(services_dir);
    std.fs.makeDirAbsolute(services_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const peer_dir = try std.fs.path.join(allocator, &.{ config_dir, "services", "peer" });
    defer allocator.free(peer_dir);
    std.fs.makeDirAbsolute(peer_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const org_dir = try std.fs.path.join(allocator, &.{ config_dir, "services", "org" });
    defer allocator.free(org_dir);
    std.fs.makeDirAbsolute(org_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

fn cmdServiceDefault(allocator: std.mem.Allocator, config_dir: []const u8, action: []const u8) !void {
    const stdout = getStdOut();
    const stderr = getStdErr();

    if (!std.mem.eql(u8, action, "allow") and !std.mem.eql(u8, action, "deny")) {
        try stderr.writeAll("error: default must be 'allow' or 'deny'\n");
        std.process.exit(1);
    }

    try ensureServicesDir(allocator, config_dir);

    const path = try std.fs.path.join(allocator, &.{ config_dir, "services", "default" });
    defer allocator.free(path);

    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(action);
    try file.writeAll("\n");

    try writeFormatted(stdout, "Default policy set to: {s}\n", .{action});
}

fn cmdServiceAddRule(allocator: std.mem.Allocator, config_dir: []const u8, args: []const []const u8) !void {
    const stdout = getStdOut();
    const stderr = getStdErr();

    // Parse: allow/deny [--peer <name>] [--org <name>] <proto> <port>
    const action = args[0]; // "allow" or "deny"
    var peer_target: ?[]const u8 = null;
    var org_target: ?[]const u8 = null;
    var proto_str: ?[]const u8 = null;
    var port_str: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--peer") and i + 1 < args.len) {
            i += 1;
            peer_target = args[i];
        } else if (std.mem.eql(u8, args[i], "--org") and i + 1 < args.len) {
            i += 1;
            org_target = args[i];
        } else if (proto_str == null) {
            proto_str = args[i];
        } else if (port_str == null) {
            port_str = args[i];
        }
    }

    if (proto_str == null) {
        try stderr.writeAll("usage: meshguard service allow|deny [--peer <name>] [--org <name>] <proto> [<port>]\n");
        std.process.exit(1);
    }

    // Build the rule line
    var rule_buf: [128]u8 = undefined;
    const rule_line = blk: {
        // "deny all" shorthand
        if (std.mem.eql(u8, proto_str.?, "all") and port_str == null) {
            break :blk std.fmt.bufPrint(&rule_buf, "{s} all\n", .{action}) catch unreachable;
        }
        if (port_str) |ps| {
            break :blk std.fmt.bufPrint(&rule_buf, "{s} {s} {s}\n", .{ action, proto_str.?, ps }) catch unreachable;
        }
        try stderr.writeAll("error: missing port (use a port number, range, or 'all')\n");
        std.process.exit(1);
    };

    // Validate the rule
    const PolicyMod = lib.services.Policy;
    _ = PolicyMod.parseRule(rule_line) catch {
        try stderr.writeAll("error: invalid rule syntax\n");
        std.process.exit(1);
    };

    try ensureServicesDir(allocator, config_dir);

    // Determine target file
    const policy_path = if (peer_target) |peer|
        try std.fmt.allocPrint(allocator, "{s}/services/peer/{s}.policy", .{ config_dir, peer })
    else if (org_target) |org|
        try std.fmt.allocPrint(allocator, "{s}/services/org/{s}.policy", .{ config_dir, org })
    else
        try std.fmt.allocPrint(allocator, "{s}/services/global.policy", .{config_dir});
    defer allocator.free(policy_path);

    // Append rule to file
    const file = std.fs.createFileAbsolute(policy_path, .{
        .truncate = false,
        .exclusive = false,
    }) catch |err| {
        try writeFormatted(stderr, "error: cannot open policy file: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer file.close();

    // Seek to end for append
    file.seekFromEnd(0) catch {};
    file.writeAll(rule_line) catch |err| {
        try writeFormatted(stderr, "error: cannot write rule: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    // Print confirmation
    const target_desc: []const u8 = if (peer_target) |p| p else if (org_target) |o| o else "global";
    const scope: []const u8 = if (peer_target != null) "peer" else if (org_target != null) "org" else "global";
    try writeFormatted(stdout, "Rule added ({s} '{s}'): {s}", .{ scope, target_desc, rule_line });
}

fn cmdServiceList(allocator: std.mem.Allocator, config_dir: []const u8) !void {
    const stdout = getStdOut();

    const services_dir = try std.fs.path.join(allocator, &.{ config_dir, "services" });
    defer allocator.free(services_dir);

    // Check if services/ exists
    std.fs.accessAbsolute(services_dir, .{}) catch {
        try stdout.writeAll("No service policies configured (default: allow all)\n");
        return;
    };

    // Default action
    const default_path = try std.fs.path.join(allocator, &.{ services_dir, "default" });
    defer allocator.free(default_path);
    const default_action = blk: {
        const file = std.fs.openFileAbsolute(default_path, .{}) catch break :blk "allow";
        defer file.close();
        var buf: [16]u8 = undefined;
        const n = file.readAll(&buf) catch break :blk "allow";
        const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");
        if (std.mem.eql(u8, trimmed, "deny")) break :blk "deny";
        break :blk "allow";
    };
    try writeFormatted(stdout, "Default: {s}\n\n", .{default_action});

    // Global policy
    const global_path = try std.fs.path.join(allocator, &.{ services_dir, "global.policy" });
    defer allocator.free(global_path);
    try printPolicyFile(stdout, global_path, "Global");

    // Peer policies
    const peer_dir = try std.fs.path.join(allocator, &.{ services_dir, "peer" });
    defer allocator.free(peer_dir);
    try printPoliciesInDir(stdout, allocator, peer_dir, "Peer");

    // Org policies
    const org_dir = try std.fs.path.join(allocator, &.{ services_dir, "org" });
    defer allocator.free(org_dir);
    try printPoliciesInDir(stdout, allocator, org_dir, "Org");
}

fn printPolicyFile(stdout: std.fs.File, path: []const u8, label: []const u8) !void {
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return;
    if (n == 0) return;

    try writeFormatted(stdout, "[{s}]\n", .{label});
    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#') continue;
        try writeFormatted(stdout, "  {s}\n", .{trimmed});
    }
    try stdout.writeAll("\n");
}

fn printPoliciesInDir(stdout: std.fs.File, allocator: std.mem.Allocator, dir_path: []const u8, scope: []const u8) !void {
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".policy")) continue;

        const name = entry.name[0 .. entry.name.len - 7]; // strip .policy
        const file_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, entry.name });
        defer allocator.free(file_path);

        var label_buf: [128]u8 = undefined;
        const label = std.fmt.bufPrint(&label_buf, "{s}: {s}", .{ scope, name }) catch continue;
        try printPolicyFile(stdout, file_path, label);
    }
}

fn cmdServiceShow(allocator: std.mem.Allocator, config_dir: []const u8, target: ?[]const u8) !void {
    const stdout = getStdOut();

    const PolicyMod = lib.services.Policy;
    var filter = PolicyMod.ServiceFilter.loadFromDir(config_dir);
    filter.resolveAliases(config_dir);
    filter.resolveOrgNames(config_dir);

    if (target) |name| {
        try writeFormatted(stdout, "Effective policy for '{s}':\n\n", .{name});

        // Try to resolve peer pubkey from alias
        const ak_path = try std.fmt.allocPrint(allocator, "{s}/authorized_keys/{s}.pub", .{ config_dir, name });
        defer allocator.free(ak_path);

        var peer_pk: [32]u8 = .{0} ** 32;
        var found_peer = false;
        if (std.fs.openFileAbsolute(ak_path, .{})) |file| {
            defer file.close();
            var pk_buf: [64]u8 = undefined;
            const n = file.readAll(&pk_buf) catch 0;
            if (n > 0) {
                const trimmed = std.mem.trim(u8, pk_buf[0..n], " \t\r\n");
                _ = std.base64.standard.Decoder.decode(&peer_pk, trimmed) catch {};
                found_peer = true;
            }
        } else |_| {}

        // Test common ports
        const test_ports = [_]struct { port: u16, name: []const u8 }{
            .{ .port = 22, .name = "SSH" },
            .{ .port = 80, .name = "HTTP" },
            .{ .port = 443, .name = "HTTPS" },
            .{ .port = 3306, .name = "MySQL" },
            .{ .port = 5432, .name = "PostgreSQL" },
            .{ .port = 6379, .name = "Redis" },
            .{ .port = 8080, .name = "Alt HTTP" },
            .{ .port = 8443, .name = "Alt HTTPS" },
            .{ .port = 27017, .name = "MongoDB" },
        };

        const pk: [32]u8 = if (found_peer) peer_pk else .{0} ** 32;
        try writeFormatted(stdout, "  {s:<6} {s:<14} {s}\n", .{ "PORT", "SERVICE", "ACCESS" });
        try writeFormatted(stdout, "  {s:<6} {s:<14} {s}\n", .{ "----", "-------", "------" });
        for (test_ports) |tp| {
            const tcp_ok = filter.check(pk, null, .tcp, tp.port);
            try writeFormatted(stdout, "  {d:<6} {s:<14} {s}\n", .{
                @as(usize, tp.port),
                tp.name,
                if (tcp_ok) @as([]const u8, "✓ allow") else @as([]const u8, "✗ deny"),
            });
        }
    } else {
        // Show summary
        try writeFormatted(stdout, "Default: {s}\n", .{
            if (filter.default_action == .allow) @as([]const u8, "allow") else @as([]const u8, "deny"),
        });
        try writeFormatted(stdout, "Global policy: {s}\n", .{
            if (filter.global != null) @as([]const u8, "yes") else @as([]const u8, "no"),
        });
        try writeFormatted(stdout, "Peer policies: {d}\n", .{@as(usize, filter.peer_count)});
        try writeFormatted(stdout, "Org policies: {d}\n", .{@as(usize, filter.org_count)});
    }
}

fn cmdServiceReset(allocator: std.mem.Allocator, config_dir: []const u8) !void {
    const stdout = getStdOut();
    const stderr = getStdErr();

    const services_dir = try std.fs.path.join(allocator, &.{ config_dir, "services" });
    defer allocator.free(services_dir);

    // Delete everything under services/
    std.fs.deleteTreeAbsolute(services_dir) catch |err| {
        if (err == error.FileNotFound) {
            try stdout.writeAll("No service policies to reset.\n");
            return;
        }
        try writeFormatted(stderr, "error: cannot remove services/: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    try stdout.writeAll("Service policies reset (default: allow all)\n");
}

// ─── Config Show ───

fn cmdConfigShow(allocator: std.mem.Allocator) !void {
    const stdout = getStdOut();
    const stderr = getStdErr();

    const config_dir = Config.defaultConfigDir(allocator) catch {
        try stderr.writeAll("error: cannot determine config directory\n");
        std.process.exit(1);
    };
    defer allocator.free(config_dir);

    try stdout.writeAll("meshguard v" ++ version ++ " — node configuration\n\n");
    try writeFormatted(stdout, "  config dir: {s}/\n", .{config_dir});

    // ─── Identity ───
    const has_identity = blk: {
        if (Identity.load(allocator, config_dir)) |kp| {
            try stdout.writeAll("\n\x1b[1m─── Identity ───────────────────────────────────\x1b[0m\n");

            // Ed25519 public key (base64)
            var pk_b64: [44]u8 = undefined;
            const pub_b64 = std.base64.standard.Encoder.encode(&pk_b64, &kp.public_key.toBytes());
            try writeFormatted(stdout, "  public key (Ed25519):   {s}\n", .{pub_b64});

            // Derive WG X25519 public key from Ed25519 secret key
            const sk_bytes = kp.secret_key.seed();
            var hash: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(&sk_bytes, &hash, .{});
            var wg_private_key: [32]u8 = hash[0..32].*;
            wg_private_key[0] &= 248;
            wg_private_key[31] &= 127;
            wg_private_key[31] |= 64;

            if (std.crypto.dh.X25519.recoverPublicKey(wg_private_key)) |wg_pub| {
                var wg_b64: [44]u8 = undefined;
                const wg_pub_b64 = std.base64.standard.Encoder.encode(&wg_b64, &wg_pub);
                try writeFormatted(stdout, "  public key (WG X25519): {s}\n", .{wg_pub_b64});
            } else |_| {}

            // Mesh IP
            const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(kp.public_key.toBytes()) catch unreachable;
            const mesh_ip = lib.wireguard.Ip.deriveFromPubkey(pub_key);
            var ip_buf: [15]u8 = undefined;
            const ip_str = lib.wireguard.Ip.formatIp(mesh_ip, &ip_buf);
            try writeFormatted(stdout, "  mesh IP:                {s}\n", .{ip_str});

            break :blk true;
        } else |_| {
            break :blk false;
        }
    };

    if (!has_identity) {
        try stdout.writeAll("\n  ⚠ No identity found. Run 'meshguard keygen' to create one.\n");
    }

    // ─── Org Membership (node.cert) ───
    const cert_path = std.fs.path.join(allocator, &.{ config_dir, "node.cert" }) catch null;
    defer if (cert_path) |p| allocator.free(p);

    if (cert_path) |cp| {
        if (lib.identity.Org.loadCertificate(allocator, cp)) |cert| {
            try stdout.writeAll("\n\x1b[1m─── Org Membership ─────────────────────────────\x1b[0m\n");

            var org_b64: [44]u8 = undefined;
            const org_pub_b64 = std.base64.standard.Encoder.encode(&org_b64, &cert.org_pubkey);
            try writeFormatted(stdout, "  org public key: {s}\n", .{org_pub_b64});

            const node_name = cert.getName();
            try writeFormatted(stdout, "  node name:      {s}\n", .{node_name});

            const domain = lib.identity.Org.deriveOrgDomain(cert.org_pubkey);
            var domain_buf: [64]u8 = undefined;
            const mesh_domain = lib.identity.Org.formatMeshDomain(node_name, domain, &domain_buf);
            try writeFormatted(stdout, "  mesh domain:    {s}\n", .{mesh_domain});

            try writeFormatted(stdout, "  issued at:      {d}\n", .{cert.issued_at});
            if (cert.expires_at == 0) {
                try stdout.writeAll("  expires:        never\n");
            } else {
                try writeFormatted(stdout, "  expires:        {d}\n", .{cert.expires_at});
            }

            if (!cert.isValid()) {
                try stdout.writeAll("  ⚠ certificate is EXPIRED or INVALID\n");
            }
        } else |_| {}
    }

    // ─── Org Admin (org/org.pub) ───
    if (lib.identity.Org.loadOrgKeyPair(allocator, config_dir)) |org_kp| {
        try stdout.writeAll("\n\x1b[1m─── Org Admin ──────────────────────────────────\x1b[0m\n");

        var org_pk_b64: [44]u8 = undefined;
        const org_pk_str = std.base64.standard.Encoder.encode(&org_pk_b64, &org_kp.public_key.toBytes());
        try writeFormatted(stdout, "  org public key: {s}\n", .{org_pk_str});

        const org_domain = lib.identity.Org.deriveOrgDomain(org_kp.public_key.toBytes());
        try writeFormatted(stdout, "  org domain:     {s}.mesh\n", .{org_domain});
    } else |_| {}

    // ─── Trusted Peers ───
    const peers = lib.identity.Trust.loadAuthorizedKeys(allocator, config_dir) catch &.{};
    defer {
        for (peers) |peer| {
            allocator.free(peer.name);
        }
        allocator.free(peers);
    }

    if (peers.len > 0) {
        try stdout.writeAll("\n");
        try writeFormatted(stdout, "\x1b[1m─── Trusted Peers ({d}) ──────────────────────────\x1b[0m\n", .{peers.len});
        for (peers) |peer| {
            var peer_b64: [44]u8 = undefined;
            const peer_str = std.base64.standard.Encoder.encode(&peer_b64, &peer.public_key.toBytes());
            try writeFormatted(stdout, "  • {s: <12} {s}\n", .{ peer.name, peer_str });
        }
    }

    // ─── Trusted Orgs ───
    const orgs = lib.identity.Trust.loadTrustedOrgs(allocator, config_dir) catch &.{};
    defer {
        for (orgs) |org| {
            allocator.free(org.name);
        }
        allocator.free(orgs);
    }

    if (orgs.len > 0) {
        try stdout.writeAll("\n");
        try writeFormatted(stdout, "\x1b[1m─── Trusted Orgs ({d}) ───────────────────────────\x1b[0m\n", .{orgs.len});
        for (orgs) |org| {
            var org_b64_buf: [44]u8 = undefined;
            const org_str = std.base64.standard.Encoder.encode(&org_b64_buf, &org.public_key);
            const org_dom = lib.identity.Org.deriveOrgDomain(org.public_key);
            try writeFormatted(stdout, "  • {s: <12} {s}  ({s}.mesh)\n", .{ org.name, org_str, org_dom });
        }
    }

    // ─── Vouched Nodes ───
    const vouch_dir = std.fs.path.join(allocator, &.{ config_dir, "vouched" }) catch null;
    defer if (vouch_dir) |vd| allocator.free(vd);

    if (vouch_dir) |vd| {
        if (std.fs.openDirAbsolute(vd, .{ .iterate = true })) |dir| {
            var vouch_count: usize = 0;
            var iter = dir.iterate();
            while (iter.next() catch null) |entry| {
                if (std.mem.endsWith(u8, entry.name, ".vouch")) vouch_count += 1;
            }
            if (vouch_count > 0) {
                try stdout.writeAll("\n");
                try writeFormatted(stdout, "\x1b[1m─── Vouched Nodes ({d}) ──────────────────────────\x1b[0m\n", .{vouch_count});
                try writeFormatted(stdout, "  {d} pending vouch(es)\n", .{vouch_count});
            }
        } else |_| {}
    }

    try stdout.writeAll("\n");
}

/// Compare two semver strings "X.Y.Z" — returns true if `remote` is strictly newer than `current`.
fn isNewerVersion(current: []const u8, remote: []const u8) bool {
    const cur = parseSemver(current) orelse return false;
    const rem = parseSemver(remote) orelse return false;
    if (rem[0] != cur[0]) return rem[0] > cur[0];
    if (rem[1] != cur[1]) return rem[1] > cur[1];
    return rem[2] > cur[2];
}

fn parseSemver(s: []const u8) ?[3]u32 {
    var parts: [3]u32 = .{ 0, 0, 0 };
    var rest = s;
    for (0..3) |i| {
        const dot = std.mem.indexOfScalar(u8, rest, '.');
        const part = if (dot) |d| rest[0..d] else rest;
        parts[i] = std.fmt.parseInt(u32, part, 10) catch return null;
        rest = if (dot) |d| rest[d + 1 ..] else rest[rest.len..];
    }
    return parts;
}

fn cmdUpgrade(allocator: std.mem.Allocator) !void {
    const stdout = getStdOut();
    const stderr = getStdErr();

    const current = version;
    try writeFormatted(stdout, "meshguard upgrade\n  current version: {s}\n", .{current});

    // Query GitHub API for latest release tag
    try stdout.writeAll("  checking for updates...\n");

    const api_tmp = "/tmp/meshguard-api-response";
    {
        var api_curl = std.process.Child.init(&.{
            "curl",                                                          "-fsSL", "-o", api_tmp,
            "https://api.github.com/repos/igorls/meshguard/releases/latest",
        }, allocator);
        api_curl.stderr_behavior = .Ignore;
        api_curl.stdout_behavior = .Ignore;
        const api_term = api_curl.spawnAndWait() catch {
            try stderr.writeAll("error: failed to query GitHub API (is curl installed?)\n");
            std.process.exit(1);
        };
        if (api_term.Exited != 0) {
            try stderr.writeAll("error: failed to fetch latest release info from GitHub\n");
            try stderr.writeAll("  hint: check internet connectivity\n");
            std.process.exit(1);
        }
    }

    // Parse tag_name from JSON response
    const api_file = std.fs.openFileAbsolute(api_tmp, .{}) catch {
        try stderr.writeAll("error: could not read API response\n");
        std.process.exit(1);
    };
    defer api_file.close();
    defer std.fs.deleteFileAbsolute(api_tmp) catch {};

    var api_buf: [8192]u8 = undefined;
    const api_len = api_file.readAll(&api_buf) catch 0;
    if (api_len == 0) {
        try stderr.writeAll("error: empty API response\n");
        std.process.exit(1);
    }
    const api_data = api_buf[0..api_len];

    // Find "tag_name" in JSON — handle optional whitespace after colon
    const tag_key = "\"tag_name\"";
    const tag_key_pos = std.mem.indexOf(u8, api_data, tag_key) orelse {
        try stderr.writeAll("error: could not parse release tag from GitHub API\n");
        std.process.exit(1);
    };
    // Skip past the key, colon, whitespace, and opening quote
    var tag_scan = tag_key_pos + tag_key.len;
    while (tag_scan < api_data.len and (api_data[tag_scan] == ':' or api_data[tag_scan] == ' ' or api_data[tag_scan] == '"')) : (tag_scan += 1) {}
    // Now tag_scan points to the first char of the version string
    // But we went one past the opening quote, so back up: actually we skipped the quote too
    // Find the closing quote
    const tag_end = std.mem.indexOfScalarPos(u8, api_data, tag_scan, '"') orelse {
        try stderr.writeAll("error: malformed tag in API response\n");
        std.process.exit(1);
    };
    const tag = api_data[tag_scan..tag_end]; // e.g. "v0.3.1"

    // Strip 'v' prefix for comparison
    const latest = if (tag.len > 0 and tag[0] == 'v') tag[1..] else tag;
    try writeFormatted(stdout, "  latest version:  {s}\n", .{latest});

    if (std.mem.eql(u8, latest, current)) {
        try stdout.writeAll("  ✓ already up to date\n");
        return;
    }

    // Simple semver comparison to prevent downgrades
    if (!isNewerVersion(current, latest)) {
        try writeFormatted(stdout, "  ✓ already up to date (local {s} >= remote {s})\n", .{ current, latest });
        return;
    }

    // Download binary
    const download_path = "/tmp/meshguard-upgrade";
    var url_buf: [256]u8 = undefined;
    const download_url = std.fmt.bufPrint(&url_buf, "https://github.com/igorls/meshguard/releases/download/{s}/meshguard-linux-amd64", .{tag}) catch {
        try stderr.writeAll("error: URL too long\n");
        std.process.exit(1);
    };

    try writeFormatted(stdout, "\n  downloading {s}...\n", .{tag});
    {
        var dl_curl = std.process.Child.init(&.{
            "curl", "-fSL", "-o", download_path, download_url,
        }, allocator);
        dl_curl.stderr_behavior = .Pipe;
        dl_curl.stdout_behavior = .Ignore;
        const dl_term = dl_curl.spawnAndWait() catch {
            try stderr.writeAll("error: failed to download release\n");
            std.process.exit(1);
        };
        if (dl_term.Exited != 0) {
            try writeFormatted(stderr, "error: download failed (exit {d})\n", .{dl_term.Exited});
            std.process.exit(1);
        }
    }

    // Make downloaded binary executable
    {
        var chmod = std.process.Child.init(&.{ "chmod", "+x", download_path }, allocator);
        chmod.stderr_behavior = .Ignore;
        chmod.stdout_behavior = .Ignore;
        _ = chmod.spawnAndWait() catch {};
    }

    // Verify downloaded binary
    try stdout.writeAll("  verifying download...\n");
    {
        var verify = std.process.Child.init(&.{ download_path, "version" }, allocator);
        verify.stdout_behavior = .Pipe;
        verify.stderr_behavior = .Ignore;
        if (verify.spawn()) |_| {} else |_| {
            try stderr.writeAll("error: downloaded binary is not executable\n");
            std.process.exit(1);
        }
        var ver_buf: [128]u8 = undefined;
        const ver_len = verify.stdout.?.readAll(&ver_buf) catch 0;
        _ = verify.wait() catch {};
        if (ver_len > 0) {
            const ver_str = std.mem.trimRight(u8, ver_buf[0..ver_len], "\n\r \t");
            try writeFormatted(stdout, "  downloaded: {s}\n", .{ver_str});
        }
    }

    // Determine install path
    const install_path = "/usr/local/bin/meshguard";

    // Stop service if running
    try stdout.writeAll("\n  stopping meshguard service...\n");
    {
        var stop = std.process.Child.init(&.{ "systemctl", "stop", "meshguard" }, allocator);
        stop.stderr_behavior = .Ignore;
        stop.stdout_behavior = .Ignore;
        _ = stop.spawnAndWait() catch {};
    }

    // Brief pause for port release
    const ts = std.os.linux.timespec{ .sec = 1, .nsec = 0 };
    _ = std.os.linux.nanosleep(&ts, null);

    // Swap binary: rm old, copy new
    try stdout.writeAll("  installing new binary...\n");
    std.fs.deleteFileAbsolute(install_path) catch {};
    {
        var cp = std.process.Child.init(&.{ "cp", download_path, install_path }, allocator);
        cp.stderr_behavior = .Ignore;
        cp.stdout_behavior = .Ignore;
        const cp_term = cp.spawnAndWait() catch {
            try stderr.writeAll("error: failed to install binary\n");
            std.process.exit(1);
        };
        if (cp_term.Exited != 0) {
            try stderr.writeAll("error: cp failed — check permissions (run with sudo)\n");
            std.process.exit(1);
        }
    }
    {
        var chmod = std.process.Child.init(&.{ "chmod", "+x", install_path }, allocator);
        chmod.stderr_behavior = .Ignore;
        chmod.stdout_behavior = .Ignore;
        _ = chmod.spawnAndWait() catch {};
    }

    // Restart service
    try stdout.writeAll("  restarting meshguard service...\n");
    {
        var restart = std.process.Child.init(&.{ "systemctl", "start", "meshguard" }, allocator);
        restart.stderr_behavior = .Ignore;
        restart.stdout_behavior = .Ignore;
        const restart_term = restart.spawnAndWait() catch {
            try stderr.writeAll("warning: could not restart service\n");
            return;
        };
        if (restart_term.Exited == 0) {
            try stdout.writeAll("  ✓ meshguard service restarted\n");
        } else {
            try stderr.writeAll("  warning: service restart failed — start manually\n");
        }
    }

    // Cleanup
    std.fs.deleteFileAbsolute(download_path) catch {};

    try stdout.writeAll("\n  ✓ upgrade complete\n");
    try writeFormatted(stdout, "  {s} → {s}\n", .{ current, latest });
}
