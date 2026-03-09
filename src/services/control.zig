//! meshguard control socket — Unix domain socket API for querying daemon state.
//!
//! Allows external programs (e.g. WormDB, monitoring agents) to query the
//! live state of the meshguard daemon without shelling out to `meshguard status`.
//!
//! Protocol: newline-delimited text commands, JSON responses.
//!
//! Commands:
//!   PEERS\n     → JSON array of alive peers with mesh IPs
//!   STATUS\n    → JSON object with daemon status summary
//!
//! Default socket path: /run/meshguard/meshguard.sock
//! Fallback (non-root): ~/.config/meshguard/meshguard.sock

const std = @import("std");
const Membership = @import("../discovery/membership.zig");
const Ip = @import("../wireguard/ip.zig");

pub const DEFAULT_SOCKET_PATH = "/run/meshguard/meshguard.sock";
pub const FALLBACK_SOCKET_PATH_SUFFIX = "meshguard/meshguard.sock";

pub const ControlSocket = struct {
    server: ?std.posix.socket_t,
    socket_path: []const u8,
    socket_path_owned: bool,
    membership: *Membership.MembershipTable,
    our_pubkey: [32]u8,
    our_mesh_ip: [4]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        membership: *Membership.MembershipTable,
        our_pubkey: [32]u8,
        our_mesh_ip: [4]u8,
        custom_path: ?[]const u8,
    ) ControlSocket {
        const path = custom_path orelse blk: {
            // Try /run/meshguard first (systemd convention), fall back to XDG config
            if (std.fs.makeDirAbsolute("/run/meshguard")) |_| {
                break :blk DEFAULT_SOCKET_PATH;
            } else |_| {
                // Fallback: ~/.config/meshguard/meshguard.sock
                const config_dir = std.fs.getAppDataDir(allocator, "meshguard") catch
                    break :blk DEFAULT_SOCKET_PATH;
                defer allocator.free(config_dir);
                const sock_path = std.fs.path.join(allocator, &.{ config_dir, "meshguard.sock" }) catch
                    break :blk DEFAULT_SOCKET_PATH;
                // Ensure parent dir exists
                std.fs.makeDirAbsolute(config_dir) catch {};
                return .{
                    .server = null,
                    .socket_path = sock_path,
                    .socket_path_owned = true,
                    .membership = membership,
                    .our_pubkey = our_pubkey,
                    .our_mesh_ip = our_mesh_ip,
                };
            }
        };

        return .{
            .server = null,
            .socket_path = path,
            .socket_path_owned = false,
            .membership = membership,
            .our_pubkey = our_pubkey,
            .our_mesh_ip = our_mesh_ip,
        };
    }

    pub fn listen(self: *ControlSocket) !void {
        // Unix domain sockets are not available on Windows
        if (comptime @import("builtin").os.tag == .windows) {
            return;
        }

        // Remove stale socket file
        std.fs.deleteFileAbsolute(self.socket_path) catch {};

        const addr = try std.net.Address.initUnix(self.socket_path);
        const sock = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, 0);
        errdefer std.posix.close(sock);

        try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
        try std.posix.listen(sock, 4);

        // Make socket accessible to non-root users
        std.posix.fchmodat(std.fs.cwd().fd, self.socket_path, 0o666, 0) catch {};

        self.server = sock;
    }


    /// Poll for and handle one incoming connection. Non-blocking.
    /// Returns true if a client was serviced.
    pub fn poll(self: *ControlSocket) bool {
        const sock = self.server orelse return false;

        const client = std.posix.accept(sock, null, null, std.posix.SOCK.NONBLOCK) catch return false;
        defer std.posix.close(client);

        self.handleClient(client);
        return true;
    }

    fn handleClient(self: *ControlSocket, client: std.posix.socket_t) void {
        var buf: [64]u8 = undefined;
        const n = std.posix.read(client, &buf) catch return;
        if (n == 0) return;

        const cmd = std.mem.trimRight(u8, buf[0..n], "\r\n \t");

        if (std.mem.eql(u8, cmd, "PEERS")) {
            self.handlePeers(client);
        } else if (std.mem.eql(u8, cmd, "STATUS")) {
            self.handleStatus(client);
        } else {
            _ = std.posix.write(client, "{\"error\":\"unknown command\"}\n") catch {};
        }
    }

    fn handlePeers(self: *ControlSocket, client: std.posix.socket_t) void {
        // Build JSON response in a fixed buffer
        var buf: [8192]u8 = undefined;
        var pos: usize = 0;

        // Start array
        buf[pos] = '[';
        pos += 1;

        var first = true;
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (peer.state != .alive) continue;

            if (!first) {
                buf[pos] = ',';
                pos += 1;
            }
            first = false;

            // Format: {"pubkey":"hex...","mesh_ip":"10.99.X.Y","state":"alive"}
            const written = std.fmt.bufPrint(buf[pos..], "{{\"pubkey\":\"{x}\",\"mesh_ip\":\"{d}.{d}.{d}.{d}\",\"state\":\"alive\"}}", .{
                peer.pubkey,
                peer.mesh_ip[0],
                peer.mesh_ip[1],
                peer.mesh_ip[2],
                peer.mesh_ip[3],
            }) catch return;
            pos += written.len;

            // Prevent buffer overflow
            if (pos > buf.len - 256) break;
        }

        buf[pos] = ']';
        pos += 1;
        buf[pos] = '\n';
        pos += 1;

        _ = std.posix.write(client, buf[0..pos]) catch {};
    }

    fn handleStatus(self: *ControlSocket, client: std.posix.socket_t) void {
        var alive: usize = 0;
        var suspected: usize = 0;
        var dead: usize = 0;

        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            switch (entry.value_ptr.state) {
                .alive => alive += 1,
                .suspected => suspected += 1,
                .dead => dead += 1,
                .left => {},
            }
        }

        var buf: [512]u8 = undefined;
        const written = std.fmt.bufPrint(&buf, "{{\"running\":true,\"pubkey\":\"{x}\",\"mesh_ip\":\"{d}.{d}.{d}.{d}\",\"peers\":{{\"alive\":{d},\"suspected\":{d},\"dead\":{d}}}}}\n", .{
            self.our_pubkey,
            self.our_mesh_ip[0],
            self.our_mesh_ip[1],
            self.our_mesh_ip[2],
            self.our_mesh_ip[3],
            alive,
            suspected,
            dead,
        }) catch return;

        _ = std.posix.write(client, written) catch {};
    }

    pub fn deinit(self: *ControlSocket, allocator: std.mem.Allocator) void {
        if (self.server) |sock| {
            std.posix.close(sock);
            self.server = null;
        }
        // Clean up socket file
        std.fs.deleteFileAbsolute(self.socket_path) catch {};
        if (self.socket_path_owned) {
            allocator.free(self.socket_path);
        }
    }
};
