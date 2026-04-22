//! meshguard control socket — cross-platform IPC for querying daemon state.
//!
//! On Linux: Unix domain socket at /run/meshguard/meshguard.sock
//! On Windows: Named pipe at \\.\pipe\meshguard
//!
//! Protocol: newline-delimited text commands, JSON responses.
//!
//! Commands:
//!   PEERS\n     → JSON array of alive peers with mesh IPs
//!   STATUS\n    → JSON object with daemon status summary

const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
const posix = std.posix;
const Config = @import("../config.zig").Config;
const Membership = @import("../discovery/membership.zig");
const Ip = @import("../wireguard/ip.zig");

fn linuxSocket(domain: u32, sock_type: u32, protocol: u32) !std.posix.socket_t {
    const fd = std.c.socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
    switch (std.posix.errno(fd)) {
        .SUCCESS => return fd,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn closeSocket(fd: posix.socket_t) void {
    _ = std.c.close(fd);
}

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn deleteFileAbsolute(path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(zio(), path) catch {};
}

const UnixSocketAddress = struct {
    addr: posix.sockaddr.un,
    len: posix.socklen_t,
};

fn initUnixSocketAddress(path: []const u8) !UnixSocketAddress {
    var addr = std.mem.zeroes(posix.sockaddr.un);
    if (path.len >= addr.path.len) return error.NameTooLong;

    addr.family = posix.AF.UNIX;
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;

    return .{
        .addr = addr,
        .len = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1),
    };
}

fn writeSocket(fd: posix.socket_t, data: []const u8) void {
    _ = std.c.write(fd, data.ptr, data.len);
}

// ─── Windows-only imports ───
const win = if (is_windows) struct {
    const windows = std.os.windows;
    const kernel32 = windows.kernel32;
    const HANDLE = windows.HANDLE;
    const BOOL = windows.BOOL;
    const DWORD = windows.DWORD;
    const LPCWSTR = [*:0]const u16;

    // Functions not in Zig 0.15 std — declare as extern
    extern "kernel32" fn CreateNamedPipeW(lpName: LPCWSTR, dwOpenMode: DWORD, dwPipeMode: DWORD, nMaxInstances: DWORD, nOutBufferSize: DWORD, nInBufferSize: DWORD, nDefaultTimeOut: DWORD, lpSecurityAttributes: ?*anyopaque) callconv(.winapi) HANDLE;
    extern "kernel32" fn ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;
    extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: HANDLE) callconv(.winapi) BOOL;
    extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
    extern "kernel32" fn GetLastError() callconv(.winapi) windows.Win32Error;
    extern "kernel32" fn ReadFile(hFile: HANDLE, lpBuffer: ?*anyopaque, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;
    extern "kernel32" fn WriteFile(hFile: HANDLE, lpBuffer: ?*const anyopaque, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;
    extern "kernel32" fn FlushFileBuffers(hFile: HANDLE) callconv(.winapi) BOOL;
} else struct {};

pub const DEFAULT_SOCKET_PATH = if (is_windows) "\\\\.\\pipe\\meshguard" else "/run/meshguard/meshguard.sock";
pub const FALLBACK_SOCKET_PATH_SUFFIX = "meshguard/meshguard.sock";

pub const ControlSocket = struct {
    /// On Linux: Unix domain socket fd. On Windows: HANDLE to named pipe.
    server: if (is_windows) ?std.os.windows.HANDLE else ?posix.socket_t,
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
            if (comptime is_windows) {
                break :blk DEFAULT_SOCKET_PATH;
            } else {
                // Try /run/meshguard first (systemd convention), fall back to XDG config
                if (std.Io.Dir.cwd().createDirPath(zio(), "/run/meshguard")) |_| {
                    break :blk DEFAULT_SOCKET_PATH;
                } else |_| {
                    // Fallback: ~/.config/meshguard/meshguard.sock
                    const config_dir = Config.defaultConfigDir(allocator) catch
                        break :blk DEFAULT_SOCKET_PATH;
                    defer allocator.free(config_dir);
                    const sock_path = std.fs.path.join(allocator, &.{ config_dir, "meshguard.sock" }) catch
                        break :blk DEFAULT_SOCKET_PATH;
                    // Ensure parent dir exists
                    std.Io.Dir.cwd().createDirPath(zio(), config_dir) catch {};
                    return .{
                        .server = null,
                        .socket_path = sock_path,
                        .socket_path_owned = true,
                        .membership = membership,
                        .our_pubkey = our_pubkey,
                        .our_mesh_ip = our_mesh_ip,
                    };
                }
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
        if (comptime is_windows) {
            try self.listenWindows();
        } else {
            try self.listenUnix();
        }
    }

    fn listenUnix(self: *ControlSocket) !void {
        // Remove stale socket file
        deleteFileAbsolute(self.socket_path);

        const addr = try initUnixSocketAddress(self.socket_path);
        const sock = try linuxSocket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer closeSocket(sock);

        if (std.c.bind(sock, @ptrCast(&addr.addr), addr.len) != 0) {
            return error.BindFailed;
        }
        if (std.c.listen(sock, 4) != 0) {
            return error.ListenFailed;
        }

        // Make socket accessible to non-root users
        if (self.socket_path.len < 256) {
            var path_buf = std.mem.zeroes([256:0]u8);
            @memcpy(path_buf[0..self.socket_path.len], self.socket_path);
            _ = std.c.fchmodat(posix.AT.FDCWD, &path_buf, 0o666, 0);
        }

        self.server = sock;
    }

    fn listenWindows(self: *ControlSocket) !void {
        if (comptime !is_windows) return;

        const pipe_name = std.unicode.utf8ToUtf16LeStringLiteral("\\\\.\\pipe\\meshguard");

        // PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
        const pipe_handle = win.CreateNamedPipeW(
            pipe_name,
            0x00000003 | 0x00080000, // PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
            0x00000000 | 0x00000000, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
            1, // max instances
            4096, // out buffer
            4096, // in buffer
            0, // default timeout
            null, // default security
        );

        if (pipe_handle == win.windows.INVALID_HANDLE_VALUE) {
            return error.NamedPipeCreateFailed;
        }

        self.server = pipe_handle;
    }

    /// Poll for and handle one incoming connection. Non-blocking.
    /// Returns true if a client was serviced.
    pub fn poll(self: *ControlSocket) bool {
        if (comptime is_windows) {
            return self.pollWindows();
        } else {
            return self.pollUnix();
        }
    }

    fn pollUnix(self: *ControlSocket) bool {
        const sock = self.server orelse return false;
        const client = if (comptime is_linux)
            std.c.accept4(sock, null, null, @intCast(posix.SOCK.NONBLOCK))
        else
            std.c.accept(sock, null, null);
        if (client < 0) return false;
        defer closeSocket(client);
        self.handleClientUnix(client);
        return true;
    }

    fn pollWindows(self: *ControlSocket) bool {
        if (comptime !is_windows) return false;

        const pipe = self.server orelse return false;

        // Try to connect a client (non-blocking)
        const connected = win.ConnectNamedPipe(pipe, null);
            if (connected == @as(win.BOOL, @enumFromInt(0))) {
            const err = win.GetLastError();
            // ERROR_PIPE_CONNECTED (535) means client already connected
            if (err != @as(win.windows.Win32Error, @enumFromInt(535)) and
                err != @as(win.windows.Win32Error, @enumFromInt(232)))
            { // ERROR_NO_DATA (232)
                return false;
            }
        }

        // Read command from pipe
        var buf: [64]u8 = undefined;
        var bytes_read: win.DWORD = 0;
        const read_ok = win.ReadFile(pipe, @ptrCast(&buf), buf.len, &bytes_read, null);
            if (read_ok == @as(win.BOOL, @enumFromInt(0)) or bytes_read == 0) {
            _ = win.DisconnectNamedPipe(pipe);
            return false;
        }

        const cmd = std.mem.trimEnd(u8, buf[0..bytes_read], "\r\n \t");

        // Generate response
        var resp_buf: [8192]u8 = undefined;
        var resp_len: usize = 0;

        if (std.mem.eql(u8, cmd, "PEERS")) {
            resp_len = self.formatPeers(&resp_buf);
        } else if (std.mem.eql(u8, cmd, "STATUS")) {
            var status_buf: [512]u8 = undefined;
            resp_len = self.formatStatus(&status_buf);
            if (resp_len > 0) @memcpy(resp_buf[0..resp_len], status_buf[0..resp_len]);
        } else {
            const err_msg = "{\"error\":\"unknown command\"}\n";
            @memcpy(resp_buf[0..err_msg.len], err_msg);
            resp_len = err_msg.len;
        }

        // Write response
        if (resp_len > 0) {
            var bytes_written: win.DWORD = 0;
            _ = win.WriteFile(pipe, @ptrCast(resp_buf[0..resp_len].ptr), @intCast(resp_len), &bytes_written, null);
            _ = win.FlushFileBuffers(pipe);
        }

        // Disconnect client so next client can connect
        _ = win.DisconnectNamedPipe(pipe);
        return true;
    }

    fn handleClientUnix(self: *ControlSocket, client: posix.socket_t) void {
        var buf: [64]u8 = undefined;
        const n = posix.read(client, &buf) catch return;
        if (n == 0) return;

        const cmd = std.mem.trimEnd(u8, buf[0..n], "\r\n \t");

        if (std.mem.eql(u8, cmd, "PEERS")) {
            var resp_buf: [8192]u8 = undefined;
            const resp_len = self.formatPeers(&resp_buf);
            if (resp_len > 0) {
                writeSocket(client, resp_buf[0..resp_len]);
            }
        } else if (std.mem.eql(u8, cmd, "STATUS")) {
            var resp_buf: [512]u8 = undefined;
            const resp_len = self.formatStatus(&resp_buf);
            if (resp_len > 0) {
                writeSocket(client, resp_buf[0..resp_len]);
            }
        } else {
            writeSocket(client, "{\"error\":\"unknown command\"}\n");
        }
    }

    // ─── Shared response formatters ───

    fn formatPeers(self: *ControlSocket, buf: *[8192]u8) usize {
        var pos: usize = 0;
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

            const pubkey_hex = std.fmt.bytesToHex(peer.pubkey, .lower);
            const written = std.fmt.bufPrint(buf[pos..], "{{\"pubkey\":\"{s}\",\"mesh_ip\":\"{d}.{d}.{d}.{d}\",\"state\":\"alive\"}}", .{
                &pubkey_hex,
                peer.mesh_ip[0],
                peer.mesh_ip[1],
                peer.mesh_ip[2],
                peer.mesh_ip[3],
            }) catch return 0;
            pos += written.len;

            if (pos > buf.len - 256) break;
        }

        buf[pos] = ']';
        pos += 1;
        buf[pos] = '\n';
        pos += 1;
        return pos;
    }

    fn formatStatus(self: *ControlSocket, buf: *[512]u8) usize {
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

        const our_pubkey_hex = std.fmt.bytesToHex(self.our_pubkey, .lower);
        const written = std.fmt.bufPrint(buf, "{{\"running\":true,\"pubkey\":\"{s}\",\"mesh_ip\":\"{d}.{d}.{d}.{d}\",\"peers\":{{\"alive\":{d},\"suspected\":{d},\"dead\":{d}}}}}\n", .{
            &our_pubkey_hex,
            self.our_mesh_ip[0],
            self.our_mesh_ip[1],
            self.our_mesh_ip[2],
            self.our_mesh_ip[3],
            alive,
            suspected,
            dead,
        }) catch return 0;

        return written.len;
    }

    pub fn deinit(self: *ControlSocket, allocator: std.mem.Allocator) void {
        if (comptime is_windows) {
            if (self.server) |pipe| {
                _ = win.CloseHandle(pipe);
                self.server = null;
            }
        } else {
            if (self.server) |sock| {
                closeSocket(sock);
                self.server = null;
            }
            // Clean up socket file
            deleteFileAbsolute(self.socket_path);
        }
        if (self.socket_path_owned) {
            allocator.free(self.socket_path);
        }
    }
};
