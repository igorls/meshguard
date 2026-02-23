//! Trust management for meshguard.
//!
//! Manages the authorized_keys/ directory — the set of Ed25519 public keys
//! that this node is willing to peer with. Adding/removing keys to this
//! directory controls mesh membership.

const std = @import("std");
const Keys = @import("keys.zig");

pub const AuthorizedPeer = struct {
    name: []const u8,
    public_key: Keys.PublicKey,
};

/// Result of adding an authorized key.
pub const AddResult = enum {
    added,
    updated_name,
    already_exists,
    name_conflict,
};

/// Information about an existing key found during dedup scanning.
pub const ExistingKeyInfo = struct {
    name: []const u8,
    key_matches: bool,
};

/// Validate a key input and return the base64 key string and auto-derived name.
/// Returns a user-friendly error message on failure, or null on success.
pub fn validateKey(key_or_path: []const u8, key_b64_out: *[44]u8, pk_bytes_out: *[32]u8) ?[]const u8 {
    var key_b64: []const u8 = undefined;
    var file_buf: [256]u8 = undefined; // Must outlive key_b64 slice

    if (std.fs.path.isAbsolute(key_or_path) or std.mem.endsWith(u8, key_or_path, ".pub")) {
        const file = std.fs.cwd().openFile(key_or_path, .{}) catch {
            return "file not found or cannot be opened";
        };
        defer file.close();
        const read = file.readAll(&file_buf) catch {
            return "failed to read key file";
        };
        key_b64 = std.mem.trimRight(u8, file_buf[0..read], "\n\r ");
    } else {
        key_b64 = key_or_path;
    }

    // Validate base64 encoding
    std.base64.standard.Decoder.decode(pk_bytes_out, key_b64) catch {
        return "invalid base64 encoding — check that the key is complete and correct";
    };

    // Validate it's a valid Ed25519 public key
    _ = std.crypto.sign.Ed25519.PublicKey.fromBytes(pk_bytes_out.*) catch {
        return "invalid Ed25519 public key";
    };

    // Copy validated b64 to output buffer
    @memcpy(key_b64_out[0..key_b64.len], key_b64);
    if (key_b64.len < 44) @memset(key_b64_out[key_b64.len..], 0);

    return null;
}

/// Scan authorized_keys/ for an existing entry matching the given key content.
/// Returns the name of the existing entry if found, null otherwise.
pub fn findExistingByKey(allocator: std.mem.Allocator, config_dir: []const u8, target_b64: []const u8) !?[]const u8 {
    const auth_dir = try ensureAuthorizedKeysDir(allocator, config_dir);
    defer allocator.free(auth_dir);

    const dir = std.fs.openDirAbsolute(auth_dir, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".pub")) continue;

        const file_path = try std.fs.path.join(allocator, &.{ auth_dir, entry.name });
        defer allocator.free(file_path);

        const file = std.fs.openFileAbsolute(file_path, .{}) catch continue;
        defer file.close();

        var buf: [256]u8 = undefined;
        const read = file.readAll(&buf) catch continue;
        const existing_b64 = std.mem.trimRight(u8, buf[0..read], "\n\r ");

        if (std.mem.eql(u8, existing_b64, target_b64)) {
            return try allocator.dupe(u8, std.fs.path.stem(entry.name));
        }
    }
    return null;
}

/// Check if a name already exists in authorized_keys/ and whether the key matches.
pub fn checkNameConflict(allocator: std.mem.Allocator, config_dir: []const u8, name: []const u8, target_b64: []const u8) !?ExistingKeyInfo {
    const auth_dir = try ensureAuthorizedKeysDir(allocator, config_dir);
    defer allocator.free(auth_dir);

    const dest_name = try std.fmt.allocPrint(allocator, "{s}.pub", .{name});
    defer allocator.free(dest_name);

    const dest_path = try std.fs.path.join(allocator, &.{ auth_dir, dest_name });
    defer allocator.free(dest_path);

    const file = std.fs.openFileAbsolute(dest_path, .{}) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer file.close();

    var buf: [256]u8 = undefined;
    const read = try file.readAll(&buf);
    const existing_b64 = std.mem.trimRight(u8, buf[0..read], "\n\r ");

    return ExistingKeyInfo{
        .name = name,
        .key_matches = std.mem.eql(u8, existing_b64, target_b64),
    };
}

/// Add a public key to the authorized_keys directory.
/// `key_or_path` can be a base64 key string or a path to a .pub file.
/// `peer_name` optionally overrides the derived filename.
pub fn addAuthorizedKey(allocator: std.mem.Allocator, config_dir: []const u8, key_b64: []const u8, name: []const u8) !void {
    const auth_dir = try ensureAuthorizedKeysDir(allocator, config_dir);
    defer allocator.free(auth_dir);

    const dest_name = try std.fmt.allocPrint(allocator, "{s}.pub", .{name});
    defer allocator.free(dest_name);

    const dest_path = try std.fs.path.join(allocator, &.{ auth_dir, dest_name });
    defer allocator.free(dest_path);

    const file = try std.fs.createFileAbsolute(dest_path, .{});
    defer file.close();
    try file.writeAll(key_b64);
    try file.writeAll("\n");
}

/// Remove an old key file when renaming (dedup).
pub fn removeKeyFile(allocator: std.mem.Allocator, config_dir: []const u8, name: []const u8) !void {
    const auth_dir = try ensureAuthorizedKeysDir(allocator, config_dir);
    defer allocator.free(auth_dir);

    const del_name = try std.fmt.allocPrint(allocator, "{s}.pub", .{name});
    defer allocator.free(del_name);

    const del_path = try std.fs.path.join(allocator, &.{ auth_dir, del_name });
    defer allocator.free(del_path);

    std.fs.deleteFileAbsolute(del_path) catch {};
}

/// Remove a public key from the authorized_keys directory.
/// `key_or_name` can be a key name (filename stem) or base64 key.
pub fn removeAuthorizedKey(allocator: std.mem.Allocator, config_dir: []const u8, key_or_name: []const u8) !void {
    const auth_dir = try ensureAuthorizedKeysDir(allocator, config_dir);
    defer allocator.free(auth_dir);

    // Try to delete by name first
    const pub_name = try std.fmt.allocPrint(allocator, "{s}.pub", .{key_or_name});
    defer allocator.free(pub_name);

    const del_path = try std.fs.path.join(allocator, &.{ auth_dir, pub_name });
    defer allocator.free(del_path);

    std.fs.deleteFileAbsolute(del_path) catch |err| {
        if (err == error.FileNotFound) {
            // Try matching by key content
            try removeByKeyContent(allocator, auth_dir, key_or_name);
            return;
        }
        return err;
    };
}

/// Load all authorized peers from the authorized_keys/ directory.
pub fn loadAuthorizedKeys(allocator: std.mem.Allocator, config_dir: []const u8) ![]AuthorizedPeer {
    const auth_dir = try ensureAuthorizedKeysDir(allocator, config_dir);
    defer allocator.free(auth_dir);

    // Use a fixed buffer to collect peers, then allocate the final slice
    var temp_peers: [64]AuthorizedPeer = undefined;
    var temp_names: [64][]const u8 = undefined;
    var count: usize = 0;

    const dir = std.fs.openDirAbsolute(auth_dir, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) return try allocator.alloc(AuthorizedPeer, 0);
        return err;
    };

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".pub")) continue;
        if (count >= 64) break;

        const file_path = try std.fs.path.join(allocator, &.{ auth_dir, entry.name });
        defer allocator.free(file_path);

        const file = std.fs.openFileAbsolute(file_path, .{}) catch continue;
        defer file.close();

        var buf: [256]u8 = undefined;
        const read = file.readAll(&buf) catch continue;
        const key_b64 = std.mem.trimRight(u8, buf[0..read], "\n\r ");

        var pk_bytes: [32]u8 = undefined;
        std.base64.standard.Decoder.decode(&pk_bytes, key_b64) catch continue;
        const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(pk_bytes) catch continue;

        const name = try allocator.dupe(u8, std.fs.path.stem(entry.name));
        temp_peers[count] = .{ .name = name, .public_key = pk };
        temp_names[count] = name;
        count += 1;
    }

    const result = try allocator.alloc(AuthorizedPeer, count);
    @memcpy(result, temp_peers[0..count]);
    return result;
}

/// Check if a public key is in the authorized set.
pub fn isAuthorized(allocator: std.mem.Allocator, config_dir: []const u8, public_key: Keys.PublicKey) !bool {
    const peers = try loadAuthorizedKeys(allocator, config_dir);
    defer {
        for (peers) |peer| {
            allocator.free(peer.name);
        }
        allocator.free(peers);
    }

    for (peers) |peer| {
        if (std.mem.eql(u8, &peer.public_key.toBytes(), &public_key.toBytes())) {
            return true;
        }
    }
    return false;
}

// ─── Internal helpers ───

fn ensureAuthorizedKeysDir(allocator: std.mem.Allocator, config_dir: []const u8) ![]const u8 {
    const auth_dir = try std.fs.path.join(allocator, &.{ config_dir, "authorized_keys" });
    std.fs.makeDirAbsolute(auth_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
    return auth_dir;
}

fn removeByKeyContent(allocator: std.mem.Allocator, auth_dir: []const u8, target_b64: []const u8) !void {
    const dir = try std.fs.openDirAbsolute(auth_dir, .{ .iterate = true });

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".pub")) continue;

        const file_path = try std.fs.path.join(allocator, &.{ auth_dir, entry.name });
        defer allocator.free(file_path);

        const file = std.fs.openFileAbsolute(file_path, .{}) catch continue;
        defer file.close();

        var buf: [256]u8 = undefined;
        const read = file.readAll(&buf) catch continue;
        const key_b64 = std.mem.trimRight(u8, buf[0..read], "\n\r ");

        if (std.mem.eql(u8, key_b64, target_b64)) {
            try std.fs.deleteFileAbsolute(file_path);
            return;
        }
    }

    return error.FileNotFound;
}

test "add and load authorized key" {
    // This test uses a tmp directory to avoid touching real config
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Generate a key and add it
    const kp = Keys.generate();
    var pk_buf: [44]u8 = undefined;
    const pk_b64 = std.base64.standard.Encoder.encode(&pk_buf, &kp.public_key.toBytes());

    try addAuthorizedKey(allocator, tmp_path, pk_b64, "test-peer");

    // Load and verify
    const peers = try loadAuthorizedKeys(allocator, tmp_path);
    defer {
        for (peers) |peer| {
            allocator.free(peer.name);
        }
        allocator.free(peers);
    }

    try std.testing.expectEqual(peers.len, 1);
    try std.testing.expectEqualSlices(u8, &peers[0].public_key.toBytes(), &kp.public_key.toBytes());
}
