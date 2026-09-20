//! meshguard control socket — cross-platform IPC for daemon queries and messaging.
//!
//! On Linux: Unix domain socket at /run/meshguard/meshguard.sock
//! On Windows: Named pipe at \\.\pipe\meshguard
//! Override both listener bind and CLI connect with MESHGUARD_CONTROL_PATH
//! (no fallback to the default socket when the env var is set).
//!
//! Protocol: newline-delimited text commands, JSON responses.
//!
//! Commands:
//!   PEERS\n                       → JSON array of alive peers with mesh IPs
//!   STATUS\n                      → JSON object with daemon status summary
//!   STOP\n                        → request graceful daemon shutdown
//!   MSGS\n                        → JSON object with queued legacy message count and previews
//!   RECV [timeout_ms]\n           → Pops oldest *legacy* message; returns JSON
//!   SEND <pubkey> <msg>\n         → Encrypts unframed 0x50/Noise plaintext and sends
//!   APPSEND <pubkey> <ch> <msg>\n → Encrypts MGAPP1-framed 0x50/Noise plaintext and sends
//!   APPRECV <channel>\n           → Pops oldest message from that application channel only
//!   APPINFO\n                     → {"protocol":1,"maxPayload":<conservative framed max>}

const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
const has_getpeereid = builtin.os.tag == .macos or builtin.os.tag == .freebsd;
const posix = std.posix;
const Config = @import("../config.zig").Config;
const Membership = @import("../discovery/membership.zig");
const Ip = @import("../wireguard/ip.zig");
const messages = @import("../protocol/messages.zig");
const X25519 = std.crypto.dh.X25519;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const crypto = @import("../wireguard/crypto.zig");
const Relay = @import("../nat/relay.zig");
const app_channel = @import("../protocol/app_channel.zig");

const unix_peer = if (has_getpeereid) struct {
    extern "c" fn getpeereid(socket: c_int, euid: *std.c.uid_t, egid: *std.c.gid_t) c_int;
} else struct {};

fn linuxSocket(domain: u32, sock_type: u32, protocol: u32) !std.posix.socket_t {
    const fd = std.c.socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
    switch (std.posix.errno(fd)) {
        .SUCCESS => return fd,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn setNonBlocking(fd: posix.socket_t) !void {
    const flags = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    switch (posix.errno(flags)) {
        .SUCCESS => {},
        else => return error.SocketSetupFailed,
    }

    const rc = posix.system.fcntl(
        fd,
        posix.F.SETFL,
        @as(usize, @intCast(flags)) | @as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK")),
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.SocketSetupFailed,
    }
}

fn closeSocket(fd: posix.socket_t) void {
    _ = std.c.close(fd);
}

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowUnixSecs() i64 {
    return @intCast(std.Io.Timestamp.now(zio(), .real).toSeconds());
}

fn nowMilliSecs() i64 {
    return @intCast(std.Io.Timestamp.now(zio(), .real).toMilliseconds());
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

fn readSocket(fd: posix.socket_t, out: []u8) !usize {
    const n = std.c.read(fd, out.ptr, out.len);
    return switch (std.posix.errno(n)) {
        .SUCCESS => @intCast(n),
        else => |err| std.posix.unexpectedErrno(err),
    };
}

// ─── Windows-only imports ───
const win = if (is_windows) struct {
    const windows = std.os.windows;
    const kernel32 = windows.kernel32;
    const HANDLE = windows.HANDLE;
    const BOOL = windows.BOOL;
    const DWORD = windows.DWORD;
    const LPCWSTR = [*:0]const u16;

    extern "kernel32" fn CreateNamedPipeW(lpName: LPCWSTR, dwOpenMode: DWORD, dwPipeMode: DWORD, nMaxInstances: DWORD, nOutBufferSize: DWORD, nInBufferSize: DWORD, nDefaultTimeOut: DWORD, lpSecurityAttributes: ?*anyopaque) callconv(.winapi) HANDLE;
    extern "kernel32" fn ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;
    extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: HANDLE) callconv(.winapi) BOOL;
    extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
    extern "kernel32" fn GetLastError() callconv(.winapi) windows.Win32Error;
    extern "kernel32" fn ReadFile(hFile: HANDLE, lpBuffer: ?*anyopaque, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;
    extern "kernel32" fn WriteFile(hFile: HANDLE, lpBuffer: ?*const anyopaque, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;
    extern "kernel32" fn FlushFileBuffers(hFile: HANDLE) callconv(.winapi) BOOL;
    extern "kernel32" fn CreateFileW(lpFileName: LPCWSTR, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: ?HANDLE) callconv(.winapi) HANDLE;
    extern "kernel32" fn WaitNamedPipeW(lpNamedPipeName: LPCWSTR, nTimeOut: DWORD) callconv(.winapi) BOOL;
} else struct {};

pub const DEFAULT_SOCKET_PATH = if (is_windows) "\\\\.\\pipe\\meshguard" else "/run/meshguard/meshguard.sock";
pub const FALLBACK_SOCKET_PATH_SUFFIX = "meshguard/meshguard.sock";
pub const CONTROL_PATH_ENV = "MESHGUARD_CONTROL_PATH";

pub const MAX_QUEUED_MESSAGES: usize = 64;
pub const MAX_MESSAGE_PAYLOAD: usize = 1024;
pub const MAX_APP_CHANNELS: usize = 8;
pub const MAX_APP_QUEUED_MESSAGES: usize = MAX_QUEUED_MESSAGES;

pub const QueuedMessage = struct {
    sender_pubkey: [32]u8,
    data: [MAX_MESSAGE_PAYLOAD]u8,
    len: usize,
    timestamp: i64,
};

const AppChannelQueue = struct {
    name: [app_channel.MAX_CHANNEL_LEN]u8 = undefined,
    name_len: usize = 0,
    queue: [MAX_APP_QUEUED_MESSAGES]QueuedMessage = undefined,
    queue_head: usize = 0,
    queue_tail: usize = 0,
    queue_count: usize = 0,
    in_use: bool = false,

    fn nameSlice(self: *const AppChannelQueue) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const SendDatagramFn = *const fn (ctx: *anyopaque, data: []const u8, ep: messages.Endpoint) bool;
pub const TickFn = *const fn (ctx: *anyopaque) void;

pub fn appendJsonEscaped(buf: []u8, pos: *usize, str: []const u8) bool {
    for (str) |c| {
        switch (c) {
            '"' => {
                if (pos.* + 2 > buf.len) return false;
                buf[pos.*] = '\\';
                buf[pos.* + 1] = '"';
                pos.* += 2;
            },
            '\\' => {
                if (pos.* + 2 > buf.len) return false;
                buf[pos.*] = '\\';
                buf[pos.* + 1] = '\\';
                pos.* += 2;
            },
            '\n' => {
                if (pos.* + 2 > buf.len) return false;
                buf[pos.*] = '\\';
                buf[pos.* + 1] = 'n';
                pos.* += 2;
            },
            '\r' => {
                if (pos.* + 2 > buf.len) return false;
                buf[pos.*] = '\\';
                buf[pos.* + 1] = 'r';
                pos.* += 2;
            },
            '\t' => {
                if (pos.* + 2 > buf.len) return false;
                buf[pos.*] = '\\';
                buf[pos.* + 1] = 't';
                pos.* += 2;
            },
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                if (pos.* + 6 > buf.len) return false;
                _ = std.fmt.bufPrint(buf[pos.*..], "\\u{x:0>4}", .{c}) catch return false;
                pos.* += 6;
            },
            else => {
                if (pos.* >= buf.len) return false;
                buf[pos.*] = c;
                pos.* += 1;
            },
        }
    }
    return true;
}

pub fn parsePubkey(input: []const u8) ?[32]u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 64) {
        var out: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, trimmed) catch return null;
        return out;
    }
    if (trimmed.len == 43 or trimmed.len == 44) {
        var out: [32]u8 = undefined;
        if (std.base64.standard.Decoder.decode(&out, trimmed)) |_| {
            return out;
        } else |_| {}
        if (std.base64.url_safe_no_pad.Decoder.decode(&out, trimmed)) |_| {
            return out;
        } else |_| {}
        if (std.base64.url_safe.Decoder.decode(&out, trimmed)) |_| {
            return out;
        } else |_| {}
    }
    return null;
}

pub fn findJsonStringField(json: []const u8, field: []const u8) ?[]const u8 {
    var in_string = false;
    var escape = false;
    var depth: usize = 0;
    var i: usize = 0;

    while (i < json.len) : (i += 1) {
        const c = json[i];
        if (escape) {
            escape = false;
            continue;
        }
        if (c == '\\' and in_string) {
            escape = true;
            continue;
        }
        if (c == '"') {
            in_string = !in_string;
            if (in_string and depth == 1) {
                const key_start = i + 1;
                var j = key_start;
                var key_escape = false;
                while (j < json.len) : (j += 1) {
                    if (key_escape) {
                        key_escape = false;
                        continue;
                    }
                    if (json[j] == '\\') {
                        key_escape = true;
                        continue;
                    }
                    if (json[j] == '"') break;
                }
                if (j < json.len) {
                    const key = json[key_start..j];
                    i = j;
                    in_string = false;

                    var k = j + 1;
                    while (k < json.len and (json[k] == ' ' or json[k] == '\t' or json[k] == '\r' or json[k] == '\n')) : (k += 1) {}
                    if (k < json.len and json[k] == ':') {
                        k += 1;
                        while (k < json.len and (json[k] == ' ' or json[k] == '\t' or json[k] == '\r' or json[k] == '\n')) : (k += 1) {}
                        if (std.mem.eql(u8, key, field)) {
                            if (k < json.len and json[k] == '"') {
                                const val_start = k + 1;
                                var v = val_start;
                                var val_esc = false;
                                while (v < json.len) : (v += 1) {
                                    if (val_esc) {
                                        val_esc = false;
                                        continue;
                                    }
                                    if (json[v] == '\\') {
                                        val_esc = true;
                                        continue;
                                    }
                                    if (json[v] == '"') return json[val_start..v];
                                }
                                return null;
                            } else {
                                const val_start = k;
                                var v = val_start;
                                while (v < json.len) : (v += 1) {
                                    const vc = json[v];
                                    if (vc == ',' or vc == '}' or vc == ']' or vc == ' ' or vc == '\t' or vc == '\r' or vc == '\n') break;
                                }
                                if (v > val_start) return json[val_start..v];
                                return null;
                            }
                        }
                    }
                }
            }
            continue;
        }
        if (!in_string) {
            if (c == '{' or c == '[') {
                depth += 1;
            } else if (c == '}' or c == ']') {
                if (depth > 0) depth -= 1;
            }
        }
    }
    return null;
}

pub fn unescapeJsonString(input: []const u8, out: []u8) usize {
    var in_idx: usize = 0;
    var out_idx: usize = 0;
    while (in_idx < input.len and out_idx < out.len) {
        if (input[in_idx] == '\\' and in_idx + 1 < input.len) {
            in_idx += 1;
            switch (input[in_idx]) {
                'n' => out[out_idx] = '\n',
                'r' => out[out_idx] = '\r',
                't' => out[out_idx] = '\t',
                '"' => out[out_idx] = '"',
                '\\' => out[out_idx] = '\\',
                else => out[out_idx] = input[in_idx],
            }
            in_idx += 1;
            out_idx += 1;
        } else {
            out[out_idx] = input[in_idx];
            in_idx += 1;
            out_idx += 1;
        }
    }
    return out_idx;
}

const ResolvedPath = struct {
    path: []const u8,
    owned: bool,
};

pub fn validateControlPath(path: []const u8) !void {
    if (std.mem.trim(u8, path, " \t\r\n").len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidControlPath;
}

pub fn controlPathFromEnv(allocator: std.mem.Allocator) !?[]u8 {
    const path = try Config.getEnvVarOwned(allocator, CONTROL_PATH_ENV);
    if (path) |p| {
        errdefer allocator.free(p);
        try validateControlPath(p);
        return p;
    }
    return null;
}

fn resolveListenPath(allocator: std.mem.Allocator, custom_path: ?[]const u8) !ResolvedPath {
    if (custom_path) |p| {
        try validateControlPath(p);
        return .{ .path = p, .owned = false };
    }

    if (try controlPathFromEnv(allocator)) |env_path| {
        if (std.fs.path.dirname(env_path)) |dir| {
            if (dir.len > 0) {
                std.Io.Dir.cwd().createDirPath(zio(), dir) catch {};
            }
        }
        return .{ .path = env_path, .owned = true };
    }

    if (comptime is_windows) {
        return .{ .path = DEFAULT_SOCKET_PATH, .owned = false };
    }

    // Try /run/meshguard first (systemd convention), fall back to XDG config
    if (std.Io.Dir.cwd().createDirPath(zio(), "/run/meshguard")) |_| {
        return .{ .path = DEFAULT_SOCKET_PATH, .owned = false };
    } else |_| {
        const config_dir = Config.defaultConfigDir(allocator) catch
            return .{ .path = DEFAULT_SOCKET_PATH, .owned = false };
        defer allocator.free(config_dir);
        const sock_path = std.fs.path.join(allocator, &.{ config_dir, "meshguard.sock" }) catch
            return .{ .path = DEFAULT_SOCKET_PATH, .owned = false };
        std.Io.Dir.cwd().createDirPath(zio(), config_dir) catch {};
        return .{ .path = sock_path, .owned = true };
    }
}

pub const ControlSocket = struct {
    /// On Linux: Unix domain socket fd. On Windows: HANDLE to named pipe.
    server: if (is_windows) ?std.os.windows.HANDLE else ?posix.socket_t,
    socket_path: []const u8,
    socket_path_owned: bool,
    membership: *Membership.MembershipTable,
    our_pubkey: [32]u8,
    our_mesh_ip: [4]u8,
    stop_flag: ?*std.atomic.Value(bool) = null,
    our_wg_private: [32]u8,

    // In-memory incoming legacy message queue (unframed / non-MGAPP1 plaintext)
    queue: [MAX_QUEUED_MESSAGES]QueuedMessage = undefined,
    queue_head: usize = 0,
    queue_tail: usize = 0,
    queue_count: usize = 0,
    queue_lock: std.Io.Mutex = .init,

    // Isolated per-channel application queues. Overflow drops the oldest
    // message on *that channel only* (same bound as MAX_QUEUED_MESSAGES).
    app_channels: [MAX_APP_CHANNELS]AppChannelQueue = @splat(.{}),

    // External hooks for datagram dispatch and event loop pump
    send_fn: ?SendDatagramFn = null,
    send_ctx: ?*anyopaque = null,
    tick_fn: ?TickFn = null,
    tick_ctx: ?*anyopaque = null,

    pub fn init(
        allocator: std.mem.Allocator,
        membership: *Membership.MembershipTable,
        our_pubkey: [32]u8,
        our_mesh_ip: [4]u8,
        our_wg_private: [32]u8,
        custom_path: ?[]const u8,
    ) !ControlSocket {
        const resolved = try resolveListenPath(allocator, custom_path);
        return .{
            .server = null,
            .socket_path = resolved.path,
            .socket_path_owned = resolved.owned,
            .membership = membership,
            .our_pubkey = our_pubkey,
            .our_mesh_ip = our_mesh_ip,
            .stop_flag = null,
            .our_wg_private = our_wg_private,
            .queue = undefined,
            .queue_head = 0,
            .queue_tail = 0,
            .queue_count = 0,
            .queue_lock = .init,
            .send_fn = null,
            .send_ctx = null,
            .tick_fn = null,
            .tick_ctx = null,
        };
    }

    pub fn setStopFlag(self: *ControlSocket, stop_flag: *std.atomic.Value(bool)) void {
        self.stop_flag = stop_flag;
    }

    /// Demux incoming decrypted 0x50 plaintext.
    /// MGAPP1 frames go to the matching application channel (reject, no truncate).
    /// Unframed / non-MGAPP1 plaintext stays on the legacy queue (truncate as before).
    pub fn pushMessage(self: *ControlSocket, sender: [32]u8, data: []const u8) bool {
        if (app_channel.looksLikeAppFrame(data)) {
            const frame = app_channel.parse(data) catch return false;
            return self.pushAppMessage(sender, frame.channel, frame.payload);
        }
        return self.pushLegacyMessage(sender, data);
    }

    fn pushLegacyMessage(self: *ControlSocket, sender: [32]u8, data: []const u8) bool {
        self.queue_lock.lockUncancelable(zio());
        defer self.queue_lock.unlock(zio());

        if (self.queue_count >= MAX_QUEUED_MESSAGES) {
            // Drop oldest
            self.queue_head = (self.queue_head + 1) % MAX_QUEUED_MESSAGES;
            self.queue_count -= 1;
        }

        const slot = self.queue_tail;
        const copy_len = @min(data.len, MAX_MESSAGE_PAYLOAD);
        @memcpy(self.queue[slot].data[0..copy_len], data[0..copy_len]);
        self.queue[slot].sender_pubkey = sender;
        self.queue[slot].len = copy_len;
        self.queue[slot].timestamp = nowUnixSecs();

        self.queue_tail = (self.queue_tail + 1) % MAX_QUEUED_MESSAGES;
        self.queue_count += 1;
        return true;
    }

    fn enqueueLocked(q: []QueuedMessage, head: *usize, tail: *usize, count: *usize, cap: usize, sender: [32]u8, data: []const u8) void {
        if (count.* >= cap) {
            head.* = (head.* + 1) % cap;
            count.* -= 1;
        }
        const slot = tail.*;
        @memcpy(q[slot].data[0..data.len], data);
        q[slot].sender_pubkey = sender;
        q[slot].len = data.len;
        q[slot].timestamp = nowUnixSecs();
        tail.* = (tail.* + 1) % cap;
        count.* += 1;
    }

    fn findAppChannel(self: *ControlSocket, name: []const u8) ?*AppChannelQueue {
        for (&self.app_channels) |*ch| {
            if (ch.in_use and std.mem.eql(u8, ch.nameSlice(), name)) return ch;
        }
        return null;
    }

    fn findOrCreateAppChannel(self: *ControlSocket, name: []const u8) ?*AppChannelQueue {
        if (self.findAppChannel(name)) |ch| return ch;
        for (&self.app_channels) |*ch| {
            if (!ch.in_use) {
                @memcpy(ch.name[0..name.len], name);
                ch.name_len = name.len;
                ch.queue_head = 0;
                ch.queue_tail = 0;
                ch.queue_count = 0;
                ch.in_use = true;
                return ch;
            }
        }
        return null;
    }

    pub fn pushAppMessage(self: *ControlSocket, sender: [32]u8, channel: []const u8, data: []const u8) bool {
        if (!app_channel.isValidChannel(channel)) return false;
        if (data.len == 0 or data.len > MAX_MESSAGE_PAYLOAD) return false;

        self.queue_lock.lockUncancelable(zio());
        defer self.queue_lock.unlock(zio());

        const ch = self.findOrCreateAppChannel(channel) orelse return false;
        enqueueLocked(
            &ch.queue,
            &ch.queue_head,
            &ch.queue_tail,
            &ch.queue_count,
            MAX_APP_QUEUED_MESSAGES,
            sender,
            data,
        );
        return true;
    }

    pub fn popAppMessage(self: *ControlSocket, channel: []const u8) ?QueuedMessage {
        self.queue_lock.lockUncancelable(zio());
        defer self.queue_lock.unlock(zio());

        const ch = self.findAppChannel(channel) orelse return null;
        if (ch.queue_count == 0) return null;

        const msg = ch.queue[ch.queue_head];
        ch.queue_head = (ch.queue_head + 1) % MAX_APP_QUEUED_MESSAGES;
        ch.queue_count -= 1;
        // Reuse drained slots without evicting another channel's queued messages.
        if (ch.queue_count == 0) ch.in_use = false;
        return msg;
    }

    pub fn getAppMessageCount(self: *ControlSocket, channel: []const u8) usize {
        self.queue_lock.lockUncancelable(zio());
        defer self.queue_lock.unlock(zio());
        const ch = self.findAppChannel(channel) orelse return 0;
        return ch.queue_count;
    }

    pub fn popMessage(self: *ControlSocket) ?QueuedMessage {
        self.queue_lock.lockUncancelable(zio());
        defer self.queue_lock.unlock(zio());

        if (self.queue_count == 0) return null;

        const msg = self.queue[self.queue_head];
        self.queue_head = (self.queue_head + 1) % MAX_QUEUED_MESSAGES;
        self.queue_count -= 1;
        return msg;
    }

    pub fn getMessageCount(self: *ControlSocket) usize {
        self.queue_lock.lockUncancelable(zio());
        defer self.queue_lock.unlock(zio());
        return self.queue_count;
    }

    pub fn setSendHandler(self: *ControlSocket, ctx: *anyopaque, send_fn: SendDatagramFn) void {
        self.send_ctx = ctx;
        self.send_fn = send_fn;
    }

    pub fn setTickHandler(self: *ControlSocket, ctx: *anyopaque, tick_fn: TickFn) void {
        self.tick_ctx = ctx;
        self.tick_fn = tick_fn;
    }

    pub fn listen(self: *ControlSocket) !void {
        if (comptime is_windows) {
            try self.listenWindows();
        } else {
            try self.listenUnix();
        }
    }

    fn listenUnix(self: *ControlSocket) !void {
        deleteFileAbsolute(self.socket_path);

        const addr = try initUnixSocketAddress(self.socket_path);
        const sock_type = if (comptime is_linux)
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK
        else
            posix.SOCK.STREAM;
        const sock = try linuxSocket(posix.AF.UNIX, sock_type, 0);
        errdefer closeSocket(sock);
        if (comptime !is_linux) {
            try setNonBlocking(sock);
        }

        if (std.c.bind(sock, @ptrCast(&addr.addr), addr.len) != 0) {
            return error.BindFailed;
        }
        if (std.c.listen(sock, 64) != 0) {
            return error.ListenFailed;
        }

        if (self.socket_path.len < 256) {
            var path_buf = std.mem.zeroes([256:0]u8);
            @memcpy(path_buf[0..self.socket_path.len], self.socket_path);
            _ = std.c.fchmodat(posix.AT.FDCWD, &path_buf, 0o666, 0);
        }

        self.server = sock;
    }

    fn listenWindows(self: *ControlSocket) !void {
        if (comptime !is_windows) return;

        const thread = try std.Thread.spawn(.{}, controlThreadWindows, .{self});
        thread.detach();
    }

    fn controlThreadWindows(self: *ControlSocket) void {
        var name_buf: [512]u16 = undefined;
        const pipe_name = windowsPipeNameZ(self.socket_path, &name_buf) catch return;

        while (true) {
            if (self.stop_flag) |flag| {
                if (!flag.load(.acquire)) break;
            }

            const pipe_handle = win.CreateNamedPipeW(
                pipe_name,
                0x00000003, // PIPE_ACCESS_DUPLEX
                0x00000000, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                255, // PIPE_UNLIMITED_INSTANCES
                4096, // out buffer
                4096, // in buffer
                5000, // default timeout
                null, // default security
            );

            if (pipe_handle == win.windows.INVALID_HANDLE_VALUE) {
                std.Io.sleep(zio(), std.Io.Duration.fromNanoseconds(100 * std.time.ns_per_ms), .awake) catch {};
                continue;
            }

            const connected = win.ConnectNamedPipe(pipe_handle, null);
            if (connected == @as(win.BOOL, @enumFromInt(0))) {
                const err = win.GetLastError();
                if (err != @as(win.windows.Win32Error, @enumFromInt(535))) { // ERROR_PIPE_CONNECTED
                    _ = win.CloseHandle(pipe_handle);
                    continue;
                }
            }

            var buf: [2048]u8 = undefined;
            var bytes_read: win.DWORD = 0;
            const read_ok = win.ReadFile(pipe_handle, @ptrCast(&buf), buf.len, &bytes_read, null);
            if (read_ok != @as(win.BOOL, @enumFromInt(0)) and bytes_read > 0) {
                const cmd = std.mem.trimEnd(u8, buf[0..bytes_read], "\r\n \t");
                var resp_buf: [8192]u8 = undefined;
                const resp_len = self.formatCommandResponse(cmd, &resp_buf, true);
                if (resp_len > 0) {
                    var bytes_written: win.DWORD = 0;
                    _ = win.WriteFile(pipe_handle, @ptrCast(resp_buf[0..resp_len].ptr), @intCast(resp_len), &bytes_written, null);
                    _ = win.FlushFileBuffers(pipe_handle);
                }
            }

            _ = win.DisconnectNamedPipe(pipe_handle);
            _ = win.CloseHandle(pipe_handle);
        }
    }

    pub fn poll(self: *ControlSocket) bool {
        if (comptime is_windows) {
            return self.pollWindows();
        } else {
            return self.pollUnix();
        }
    }

    fn pollUnix(self: *ControlSocket) bool {
        const sock = self.server orelse return false;
        var handled = false;
        while (true) {
            const client = std.c.accept(sock, null, null);
            if (client < 0) break;
            defer closeSocket(client);
            self.handleClientUnix(client);
            handled = true;
            if (comptime !is_linux) break;
        }
        return handled;
    }

    fn pollWindows(self: *ControlSocket) bool {
        _ = self;
        return false;
    }

    fn handleClientUnix(self: *ControlSocket, client: posix.socket_t) void {
        var fds = [_]posix.pollfd{.{
            .fd = client,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        const ready = posix.poll(&fds, 1000) catch return;
        if (ready == 0 or (fds[0].revents & posix.POLL.IN) == 0) return;

        var buf: [2048]u8 = undefined;
        const n = posix.read(client, &buf) catch return;
        if (n == 0) return;

        const cmd = std.mem.trimEnd(u8, buf[0..n], "\r\n \t");
        var resp_buf: [8192]u8 = undefined;
        const stop_authorized = std.mem.eql(u8, cmd, "STOP") and stopAuthorizedUnix(client);
        const resp_len = self.formatCommandResponse(cmd, &resp_buf, stop_authorized);
        if (resp_len > 0) {
            writeSocket(client, resp_buf[0..resp_len]);
        }
    }

    pub fn formatCommandResponse(self: *ControlSocket, cmd_raw: []const u8, buf: []u8, stop_authorized: bool) usize {
        const cmd = std.mem.trim(u8, cmd_raw, " \t\r\n");

        if (std.mem.eql(u8, cmd, "PEERS")) {
            return self.formatPeers(buf);
        } else if (std.mem.eql(u8, cmd, "STATUS")) {
            return self.formatStatus(buf);
        } else if (std.mem.eql(u8, cmd, "STOP")) {
            if (!stop_authorized) {
                const msg = "{\"ok\":false,\"error\":\"unauthorized\"}\n";
                @memcpy(buf[0..msg.len], msg);
                return msg.len;
            }
            if (self.stop_flag) |flag| {
                flag.store(false, .release);
                const msg = "{\"ok\":true,\"stopping\":true}\n";
                @memcpy(buf[0..msg.len], msg);
                return msg.len;
            }
            const msg = "{\"ok\":false,\"error\":\"stop not supported\"}\n";
            @memcpy(buf[0..msg.len], msg);
            return msg.len;
        } else if (std.mem.eql(u8, cmd, "MSGS")) {
            return self.formatMsgs(buf);
        } else if (std.mem.eql(u8, cmd, "RECV") or std.mem.startsWith(u8, cmd, "RECV ")) {
            var timeout_ms: u32 = 0;
            if (cmd.len > 4) {
                const arg = std.mem.trim(u8, cmd[4..], " \t\r\n");
                timeout_ms = std.fmt.parseInt(u32, arg, 10) catch 0;
            }
            return self.handleRecv(timeout_ms, buf);
        } else if (std.mem.startsWith(u8, cmd, "SEND ")) {
            return self.handleSend(cmd[5..], buf);
        } else if (std.mem.eql(u8, cmd, "APPINFO")) {
            return formatAppInfo(buf);
        } else if (std.mem.eql(u8, cmd, "APPRECV") or std.mem.startsWith(u8, cmd, "APPRECV ")) {
            const channel = if (cmd.len > 7) std.mem.trim(u8, cmd[7..], " \t\r\n") else "";
            return self.handleAppRecv(channel, buf);
        } else if (std.mem.startsWith(u8, cmd, "APPSEND ")) {
            return self.handleAppSend(cmd["APPSEND ".len..], buf);
        } else {
            return formatError(buf, "unknown command");
        }
    }

    pub fn handleCommand(self: *ControlSocket, cmd_raw: []const u8, resp_buf: []u8) usize {
        return self.formatCommandResponse(cmd_raw, resp_buf, true);
    }

    fn formatError(buf: []u8, msg: []const u8) usize {
        var pos: usize = 0;
        const pre = "{\"error\":\"";
        if (pos + pre.len > buf.len) return 0;
        @memcpy(buf[pos..][0..pre.len], pre);
        pos += pre.len;

        if (!appendJsonEscaped(buf, &pos, msg)) return 0;

        const post = "\"}\n";
        if (pos + post.len > buf.len) return 0;
        @memcpy(buf[pos..][0..post.len], post);
        pos += post.len;
        return pos;
    }

    fn formatQueuedMessage(msg: QueuedMessage, resp_buf: []u8) usize {
        var pos: usize = 0;
        const prefix = "{\"ok\":true,\"sender\":\"";
        @memcpy(resp_buf[pos..][0..prefix.len], prefix);
        pos += prefix.len;

        const hex = std.fmt.bytesToHex(msg.sender_pubkey, .lower);
        @memcpy(resp_buf[pos..][0..hex.len], &hex);
        pos += hex.len;

        const data_pre = "\",\"data\":\"";
        @memcpy(resp_buf[pos..][0..data_pre.len], data_pre);
        pos += data_pre.len;

        if (!appendJsonEscaped(resp_buf, &pos, msg.data[0..msg.len])) {
            return formatError(resp_buf, "response buffer overflow");
        }

        const suffix = std.fmt.bufPrint(resp_buf[pos..], "\",\"timestamp\":{d}}}\n", .{msg.timestamp}) catch {
            return formatError(resp_buf, "response formatting error");
        };
        pos += suffix.len;
        return pos;
    }

    fn formatEmptyRecv(resp_buf: []u8) usize {
        const empty_msg = "{\"empty\":true}\n";
        const len = @min(empty_msg.len, resp_buf.len);
        @memcpy(resp_buf[0..len], empty_msg[0..len]);
        return len;
    }

    fn handleRecv(self: *ControlSocket, timeout_ms: u32, resp_buf: []u8) usize {
        _ = timeout_ms;
        if (self.popMessage()) |msg| {
            return formatQueuedMessage(msg, resp_buf);
        }
        return formatEmptyRecv(resp_buf);
    }

    fn formatAppInfo(resp_buf: []u8) usize {
        const written = std.fmt.bufPrint(resp_buf, "{{\"protocol\":{d},\"maxPayload\":{d}}}\n", .{
            app_channel.PROTOCOL_VERSION,
            app_channel.MAX_APP_PAYLOAD,
        }) catch return formatError(resp_buf, "response formatting error");
        return written.len;
    }

    fn handleAppRecv(self: *ControlSocket, channel: []const u8, resp_buf: []u8) usize {
        if (channel.len == 0) {
            return formatError(resp_buf, "missing channel in APPRECV command");
        }
        if (!app_channel.isValidChannel(channel)) {
            return formatError(resp_buf, "invalid channel name");
        }
        if (self.popAppMessage(channel)) |msg| {
            return formatQueuedMessage(msg, resp_buf);
        }
        return formatEmptyRecv(resp_buf);
    }

    fn handleAppSend(self: *ControlSocket, rest: []const u8, resp_buf: []u8) usize {
        const trimmed = std.mem.trim(u8, rest, " \t\r\n");
        const key_space = std.mem.indexOf(u8, trimmed, " ") orelse {
            return formatError(resp_buf, "missing channel in APPSEND command");
        };

        const dest_key_str = trimmed[0..key_space];
        const after_key = std.mem.trim(u8, trimmed[key_space + 1 ..], " \t");
        const chan_space = std.mem.indexOf(u8, after_key, " ") orelse {
            return formatError(resp_buf, "missing payload in APPSEND command");
        };

        const channel = after_key[0..chan_space];
        const payload = std.mem.trim(u8, after_key[chan_space + 1 ..], " \t\r\n");

        if (!app_channel.isValidChannel(channel)) {
            return formatError(resp_buf, "invalid channel name");
        }
        if (payload.len == 0) {
            return formatError(resp_buf, "empty payload");
        }

        var frame_buf: [app_channel.MAX_PLAINTEXT]u8 = undefined;
        const frame = app_channel.encode(channel, payload, &frame_buf) catch |err| switch (err) {
            error.InvalidChannel => return formatError(resp_buf, "invalid channel name"),
            error.EmptyPayload => return formatError(resp_buf, "empty payload"),
            error.Oversize => return formatError(resp_buf, "payload exceeds maximum application frame length"),
        };

        const dest_key = parsePubkey(dest_key_str) orelse {
            return formatError(resp_buf, "invalid destination public key");
        };
        return self.encryptAndSend(dest_key, frame, resp_buf);
    }

    fn formatMsgs(self: *ControlSocket, resp_buf: []u8) usize {
        self.queue_lock.lockUncancelable(zio());
        defer self.queue_lock.unlock(zio());

        var pos: usize = 0;
        const header = std.fmt.bufPrint(resp_buf, "{{\"count\":{d},\"messages\":[", .{self.queue_count}) catch return 0;
        pos += header.len;

        var idx = self.queue_head;
        var i: usize = 0;
        while (i < self.queue_count) : (i += 1) {
            if (i > 0) {
                if (pos >= resp_buf.len) break;
                resp_buf[pos] = ',';
                pos += 1;
            }
            const m = &self.queue[idx];
            const hex = std.fmt.bytesToHex(m.sender_pubkey, .lower);
            const entry = std.fmt.bufPrint(resp_buf[pos..], "{{\"sender\":\"{s}\",\"len\":{d},\"timestamp\":{d}}}", .{
                &hex,
                m.len,
                m.timestamp,
            }) catch break;
            pos += entry.len;
            idx = (idx + 1) % MAX_QUEUED_MESSAGES;
        }

        const footer = "]}\n";
        if (pos + footer.len <= resp_buf.len) {
            @memcpy(resp_buf[pos..][0..footer.len], footer);
            pos += footer.len;
        }
        return pos;
    }

    fn handleSend(self: *ControlSocket, rest: []const u8, resp_buf: []u8) usize {
        const trimmed = std.mem.trim(u8, rest, " \t\r\n");
        const space_idx = std.mem.indexOf(u8, trimmed, " ") orelse {
            return formatError(resp_buf, "missing payload in SEND command");
        };

        const dest_key_str = trimmed[0..space_idx];
        const payload = std.mem.trim(u8, trimmed[space_idx + 1 ..], " \t\r\n");

        if (payload.len == 0) {
            return formatError(resp_buf, "empty payload");
        }
        if (payload.len > MAX_MESSAGE_PAYLOAD) {
            return formatError(resp_buf, "payload exceeds maximum length (1024 bytes)");
        }

        const dest_key = parsePubkey(dest_key_str) orelse {
            return formatError(resp_buf, "invalid destination public key");
        };

        return self.encryptAndSend(dest_key, payload, resp_buf);
    }

    fn encryptAndSend(self: *ControlSocket, dest_key: [32]u8, payload: []const u8, resp_buf: []u8) usize {
        if (payload.len > MAX_MESSAGE_PAYLOAD) {
            return formatError(resp_buf, "payload exceeds maximum length (1024 bytes)");
        }

        const peer = self.membership.peers.get(dest_key) orelse {
            return formatError(resp_buf, "peer not found in membership table");
        };

        const relay_opt = Relay.selectRelayForPair(&self.membership.peers, self.our_pubkey, dest_key);

        if (peer.state != .alive and peer.state != .suspected and relay_opt == null) {
            return formatError(resp_buf, "peer is not active");
        }

        const peer_wg = peer.wg_pubkey orelse {
            return formatError(resp_buf, "peer wireguard key not known yet");
        };

        const peer_ep = peer.gossip_endpoint orelse peer.public_endpoint;
        if (peer_ep == null and relay_opt == null) {
            return formatError(resp_buf, "peer endpoint not known");
        }

        var msg_buf: [1 + 32 + 32 + 12 + MAX_MESSAGE_PAYLOAD + 16]u8 = undefined;
        msg_buf[0] = 0x50;
        @memcpy(msg_buf[1..33], &dest_key);
        @memcpy(msg_buf[33..65], &self.our_pubkey);

        var nonce: [12]u8 = undefined;
        zio().random(&nonce);
        @memcpy(msg_buf[65..77], &nonce);

        const shared = X25519.scalarmult(self.our_wg_private, peer_wg) catch {
            return formatError(resp_buf, "key exchange computation failed");
        };
        const key_result = crypto.kdf2(shared, "meshguard-app-v1");
        const enc_key = key_result.key;

        var tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(
            msg_buf[77..][0..payload.len],
            &tag,
            payload,
            &self.our_pubkey,
            nonce,
            enc_key,
        );
        @memcpy(msg_buf[77 + payload.len ..][0..16], &tag);

        const total_len = 77 + payload.len + 16;
        const send_fn = self.send_fn orelse {
            return formatError(resp_buf, "daemon sender not configured");
        };

        var sent_direct = false;
        if (peer_ep) |ep| {
            sent_direct = send_fn(self.send_ctx.?, msg_buf[0..total_len], ep);
        }
        var sent_relay = false;

        if (peer.nat_type != .public or !sent_direct) {
            if (relay_opt) |relay| {
                if (relay.gossip_endpoint orelse relay.public_endpoint) |relay_ep| {
                    if (!std.mem.eql(u8, &relay.pubkey, &dest_key)) {
                        sent_relay = send_fn(self.send_ctx.?, msg_buf[0..total_len], relay_ep);
                    }
                }
            }
        }

        if (!sent_direct and !sent_relay) {
            return formatError(resp_buf, "udp transmission failed");
        }

        const ok_msg = "{\"ok\":true}\n";
        const len = @min(ok_msg.len, resp_buf.len);
        @memcpy(resp_buf[0..len], ok_msg[0..len]);
        return len;
    }

    fn formatPeers(self: *ControlSocket, buf: []u8) usize {
        var pos: usize = 0;
        if (pos >= buf.len) return 0;
        buf[pos] = '[';
        pos += 1;

        var first = true;
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (peer.state != .alive) continue;

            if (!first) {
                if (pos >= buf.len) break;
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

        if (pos + 2 > buf.len) return 0;
        buf[pos] = ']';
        pos += 1;
        buf[pos] = '\n';
        pos += 1;
        return pos;
    }

    fn formatStatus(self: *ControlSocket, buf: []u8) usize {
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
        const written = std.fmt.bufPrint(buf, "{{\"running\":true,\"pubkey\":\"{s}\",\"mesh_ip\":\"{d}.{d}.{d}.{d}\",\"peers\":{{\"alive\":{d},\"suspected\":{d},\"dead\":{d}}},\"queued_msgs\":{d}}}\n", .{
            &our_pubkey_hex,
            self.our_mesh_ip[0],
            self.our_mesh_ip[1],
            self.our_mesh_ip[2],
            self.our_mesh_ip[3],
            alive,
            suspected,
            dead,
            self.queue_count,
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
            deleteFileAbsolute(self.socket_path);
        }
        if (self.socket_path_owned) {
            allocator.free(self.socket_path);
        }
    }
};

fn peerUidCanStop(peer_uid: std.c.uid_t, daemon_uid: std.c.uid_t) bool {
    return peer_uid == 0 or peer_uid == daemon_uid;
}

fn stopAuthorizedUnix(client: posix.socket_t) bool {
    if (comptime is_windows) return false;

    if (comptime is_linux) {
        const LinuxPeerCred = extern struct {
            pid: std.c.pid_t,
            uid: std.c.uid_t,
            gid: std.c.gid_t,
        };

        var cred: LinuxPeerCred = undefined;
        var len: std.c.socklen_t = @sizeOf(LinuxPeerCred);
        if (std.c.getsockopt(client, std.os.linux.SOL.SOCKET, std.os.linux.SO.PEERCRED, &cred, &len) != 0) {
            return false;
        }
        if (len < @sizeOf(LinuxPeerCred)) return false;
        return peerUidCanStop(cred.uid, std.c.geteuid());
    }

    if (comptime has_getpeereid) {
        var uid: std.c.uid_t = undefined;
        var gid: std.c.gid_t = undefined;
        if (unix_peer.getpeereid(@intCast(client), &uid, &gid) != 0) {
            return false;
        }
        return peerUidCanStop(uid, std.c.geteuid());
    }

    return false;
}

pub fn request(allocator: std.mem.Allocator, command_raw: []const u8, out: []u8) !usize {
    const command = std.mem.trimEnd(u8, command_raw, "\r\n");
    if (command.len == 0 or std.mem.indexOfAny(u8, command, "\r\n") != null) {
        return error.InvalidCommand;
    }

    if (try controlPathFromEnv(allocator)) |env_path| {
        defer allocator.free(env_path);
        const result = if (comptime is_windows)
            requestWindows(env_path, command, out)
        else
            requestUnixPath(env_path, command, out);
        return result catch |err| switch (err) {
            // Do not let status/down fall through to the default kernel device.
            error.ControlSocketUnavailable => error.ExplicitControlSocketUnavailable,
            else => err,
        };
    }

    if (comptime is_windows) {
        return requestWindows(DEFAULT_SOCKET_PATH, command, out);
    } else {
        return requestUnixDefault(allocator, command, out);
    }
}

fn requestUnixDefault(allocator: std.mem.Allocator, command: []const u8, out: []u8) !usize {
    if (requestUnixPath(DEFAULT_SOCKET_PATH, command, out)) |n| {
        return n;
    } else |err| switch (err) {
        error.ControlSocketUnavailable => {},
        else => return err,
    }

    const config_dir = Config.defaultConfigDir(allocator) catch return error.ControlSocketUnavailable;
    defer allocator.free(config_dir);
    const fallback_path = try std.fs.path.join(allocator, &.{ config_dir, "meshguard.sock" });
    defer allocator.free(fallback_path);

    return requestUnixPath(fallback_path, command, out) catch |err| switch (err) {
        error.ControlSocketUnavailable => error.ControlSocketUnavailable,
        else => err,
    };
}

fn requestUnixPath(path: []const u8, command: []const u8, out: []u8) !usize {
    const addr = initUnixSocketAddress(path) catch return error.ControlSocketUnavailable;
    const sock = try linuxSocket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer closeSocket(sock);

    if (std.c.connect(sock, @ptrCast(&addr.addr), addr.len) != 0) {
        return error.ControlSocketUnavailable;
    }

    writeSocket(sock, command);
    writeSocket(sock, "\n");

    var poll_timeout: i32 = 1000;
    if (std.mem.startsWith(u8, command, "RECV")) {
        const trimmed = std.mem.trim(u8, command[4..], " \t");
        if (std.fmt.parseInt(u32, trimmed, 10)) |to| {
            poll_timeout = @intCast(to + 1000);
        } else |_| {
            poll_timeout = 6000;
        }
    }

    var fds = [_]posix.pollfd{.{
        .fd = sock,
        .events = posix.POLL.IN,
        .revents = 0,
    }};
    const ready = posix.poll(&fds, poll_timeout) catch return error.ControlSocketUnavailable;
    if (ready == 0 or (fds[0].revents & posix.POLL.IN) == 0) {
        return error.ControlSocketUnavailable;
    }

    const n = readSocket(sock, out) catch return error.ReadFailed;
    if (n == 0) return error.ReadFailed;
    if (n == out.len) return error.ResponseTooLarge;
    return n;
}

fn windowsPipeNameZ(path: []const u8, buf: []u16) ![:0]u16 {
    if (path.len == 0 or buf.len < 2) return error.NameTooLong;
    const n = try std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], path);
    buf[n] = 0;
    return buf[0..n :0];
}

fn requestWindows(path: []const u8, command: []const u8, out: []u8) !usize {
    if (comptime !is_windows) unreachable;

    var name_buf: [512]u16 = undefined;
    const pipe_name = windowsPipeNameZ(path, &name_buf) catch return error.ControlSocketUnavailable;
    var attempts: usize = 0;
    var handle: win.HANDLE = win.windows.INVALID_HANDLE_VALUE;
    while (attempts < 50) : (attempts += 1) {
        handle = win.CreateFileW(
            pipe_name,
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            0,
            null,
            3, // OPEN_EXISTING
            0x00000080, // FILE_ATTRIBUTE_NORMAL
            null,
        );
        if (handle != win.windows.INVALID_HANDLE_VALUE) break;

        const err = win.GetLastError();
        if (err == @as(win.windows.Win32Error, @enumFromInt(231))) { // ERROR_PIPE_BUSY
            _ = win.WaitNamedPipeW(pipe_name, 500);
        } else {
            const waited = win.WaitNamedPipeW(pipe_name, 500);
            if (waited == @as(win.BOOL, @enumFromInt(0))) {
                std.Io.sleep(zio(), std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
            }
        }
    }
    if (handle == win.windows.INVALID_HANDLE_VALUE) {
        return error.ControlSocketUnavailable;
    }
    defer _ = win.CloseHandle(handle);

    var bytes_written: win.DWORD = 0;
    if (win.WriteFile(handle, @ptrCast(command.ptr), @intCast(command.len), &bytes_written, null) == @as(win.BOOL, @enumFromInt(0))) {
        return error.WriteFailed;
    }
    if (win.WriteFile(handle, @ptrCast("\n".ptr), 1, &bytes_written, null) == @as(win.BOOL, @enumFromInt(0))) {
        return error.WriteFailed;
    }

    var bytes_read: win.DWORD = 0;
    if (win.ReadFile(handle, @ptrCast(out.ptr), @intCast(out.len), &bytes_read, null) == @as(win.BOOL, @enumFromInt(0))) {
        return error.ReadFailed;
    }
    if (bytes_read == 0) return error.ReadFailed;
    if (bytes_read == out.len) return error.ResponseTooLarge;
    return @intCast(bytes_read);
}

pub const sendControlCommand = request;

test "control STOP response toggles stop flag" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();

    var control = try ControlSocket.init(allocator, &membership, [_]u8{0x42} ** 32, .{ 10, 99, 1, 2 }, [_]u8{0} ** 32, "test.sock");

    var running = std.atomic.Value(bool).init(true);
    control.setStopFlag(&running);

    var buf: [8192]u8 = undefined;
    const n = control.formatCommandResponse("STOP", &buf, true);
    try std.testing.expectEqualStrings("{\"ok\":true,\"stopping\":true}\n", buf[0..n]);
    try std.testing.expect(!running.load(.acquire));
}

test "control STOP rejects unauthorized peers" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();

    var control = try ControlSocket.init(allocator, &membership, [_]u8{0x42} ** 32, .{ 10, 99, 1, 2 }, [_]u8{0} ** 32, "test.sock");

    var running = std.atomic.Value(bool).init(true);
    control.setStopFlag(&running);

    var buf: [8192]u8 = undefined;
    const n = control.formatCommandResponse("STOP", &buf, false);
    try std.testing.expectEqualStrings("{\"ok\":false,\"error\":\"unauthorized\"}\n", buf[0..n]);
    try std.testing.expect(running.load(.acquire));
}

test "control STOP allows same uid or root" {
    try std.testing.expect(peerUidCanStop(1000, 1000));
    try std.testing.expect(peerUidCanStop(0, 1000));
    try std.testing.expect(!peerUidCanStop(1001, 1000));
}

test "control STATUS response includes peer counts" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();

    var control = try ControlSocket.init(allocator, &membership, [_]u8{0x24} ** 32, .{ 10, 99, 3, 4 }, [_]u8{0} ** 32, "test.sock");

    var buf: [8192]u8 = undefined;
    const n = control.formatCommandResponse("STATUS", &buf, false);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "\"running\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "\"mesh_ip\":\"10.99.3.4\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "\"alive\":0") != null);
}

test "ControlSocket message queue push and pop" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), control.getMessageCount());

    const sender = [_]u8{0xaa} ** 32;
    try std.testing.expect(control.pushMessage(sender, "hello meshguard"));
    try std.testing.expectEqual(@as(usize, 1), control.getMessageCount());

    const popped = control.popMessage();
    try std.testing.expect(popped != null);
    try std.testing.expectEqualSlices(u8, &sender, &popped.?.sender_pubkey);
    try std.testing.expectEqualStrings("hello meshguard", popped.?.data[0..popped.?.len]);
    try std.testing.expectEqual(@as(usize, 0), control.getMessageCount());

    try std.testing.expect(control.popMessage() == null);
}

test "ControlSocket message queue overflow drops oldest" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    var i: usize = 0;
    while (i < MAX_QUEUED_MESSAGES + 5) : (i += 1) {
        var buf: [16]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "msg-{d}", .{i}) catch unreachable;
        _ = control.pushMessage([_]u8{@intCast(i % 255)} ** 32, msg);
    }

    try std.testing.expectEqual(MAX_QUEUED_MESSAGES, control.getMessageCount());

    // Oldest 5 dropped (0, 1, 2, 3, 4), so first popped should be msg-5
    const popped = control.popMessage();
    try std.testing.expect(popped != null);
    try std.testing.expectEqualStrings("msg-5", popped.?.data[0..popped.?.len]);
}

test "ControlSocket parsePubkey" {
    // 64-char hex
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const pk1 = parsePubkey(hex);
    try std.testing.expect(pk1 != null);
    try std.testing.expectEqual(@as(u8, 0x01), pk1.?[0]);
    try std.testing.expectEqual(@as(u8, 0xef), pk1.?[31]);

    // Base64 standard (44 chars)
    var b64_buf: [44]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, &pk1.?);
    const pk2 = parsePubkey(b64);
    try std.testing.expect(pk2 != null);
    try std.testing.expectEqualSlices(u8, &pk1.?, &pk2.?);

    // Invalid length / chars
    try std.testing.expect(parsePubkey("short") == null);
    try std.testing.expect(parsePubkey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg") == null);
}

test "ControlSocket handleCommand MSGS and RECV empty" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    var resp_buf: [1024]u8 = undefined;

    const len_msgs = control.handleCommand("MSGS", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..len_msgs], "\"count\":0") != null);

    const len_recv = control.handleCommand("RECV 0", &resp_buf);
    try std.testing.expectEqualStrings("{\"empty\":true}\n", resp_buf[0..len_recv]);
}

test "ControlSocket handleCommand RECV with queued message" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const sender = [_]u8{0x42} ** 32;
    _ = control.pushMessage(sender, "hello \"agent\"\nnew line");

    var resp_buf: [1024]u8 = undefined;
    const len = control.handleCommand("RECV", &resp_buf);
    const resp = resp_buf[0..len];

    try std.testing.expect(std.mem.indexOf(u8, resp, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "42424242") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "hello \\\"agent\\\"\\nnew line") != null);
}

test "findJsonStringField ignores nested fields inside string values" {
    const json = "{\"command\":\"curl http://host -d '{\\\"id\\\": 999}'\", \"id\":\"real_task_42\", \"num\":123}";

    const cmd = findJsonStringField(json, "command");
    try std.testing.expect(cmd != null);
    try std.testing.expectEqualStrings("curl http://host -d '{\\\"id\\\": 999}'", cmd.?);

    // Crucial check: top-level id is found, NOT the nested id inside command!
    const id = findJsonStringField(json, "id");
    try std.testing.expect(id != null);
    try std.testing.expectEqualStrings("real_task_42", id.?);

    const num = findJsonStringField(json, "num");
    try std.testing.expect(num != null);
    try std.testing.expectEqualStrings("123", num.?);

    const nonexistent = findJsonStringField(json, "nonexistent");
    try std.testing.expect(nonexistent == null);
}

test "unescapeJsonString decodes escapes correctly" {
    const raw = "hello\\nworld\\r\\t\\\"test\\\\";
    var buf: [64]u8 = undefined;
    const len = unescapeJsonString(raw, &buf);
    try std.testing.expectEqualStrings("hello\nworld\r\t\"test\\", buf[0..len]);
}

test "ControlSocket handleSend falls back to public_endpoint" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    const peer_pk = [_]u8{0x77} ** 32;
    const peer_wg = [_]u8{0x88} ** 32;
    const pub_ep = messages.Endpoint.initV4(.{ 192, 168, 1, 50 }, 51820);

    try membership.upsert(.{
        .pubkey = peer_pk,
        .name = "",
        .state = .alive,
        .gossip_endpoint = null, // gossip endpoint is null!
        .public_endpoint = pub_ep, // but public endpoint is known!
        .wg_pubkey = peer_wg,
        .mesh_ip = .{ 10, 99, 0, 77 },
        .mesh_ip6 = .{0} ** 16,
        .wg_port = 51830,
        .lamport = 1,
        .last_seen_ns = 1,
        .suspected_at_ns = null,
        .last_rtt_ns = null,
        .handshake_complete = false,
    });

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const DummySender = struct {
        sent: bool = false,
        sent_to: ?messages.Endpoint = null,

        fn send(ctx_ptr: *anyopaque, data: []const u8, ep: messages.Endpoint) bool {
            _ = data;
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            self.sent = true;
            self.sent_to = ep;
            return true;
        }
    };

    var dummy = DummySender{};
    control.setSendHandler(&dummy, DummySender.send);

    var resp_buf: [512]u8 = undefined;
    const pk_hex = std.fmt.bytesToHex(peer_pk, .lower);
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "SEND {s} test-payload", .{&pk_hex}) catch unreachable;

    const len = control.handleCommand(cmd, &resp_buf);
    const resp = resp_buf[0..len];

    // Must succeed (fallback to public_endpoint), not fail with "peer gossip endpoint not known"
    try std.testing.expectEqualStrings("{\"ok\":true}\n", resp);
    try std.testing.expect(dummy.sent);
    try std.testing.expectEqual(pub_ep.port, dummy.sent_to.?.port);
}

test "explicit invalid listener paths fail before default resolution" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();
    for ([_][]const u8{ "", " \t", "candidate\x00.sock" }) |path| {
        try std.testing.expectError(error.InvalidControlPath, ControlSocket.init(
            allocator,
            &membership,
            [_]u8{1} ** 32,
            .{ 10, 99, 0, 1 },
            [_]u8{2} ** 32,
            path,
        ));
    }
    const resolved = try resolveListenPath(allocator, "candidate.sock");
    try std.testing.expectEqualStrings("candidate.sock", resolved.path);
    try std.testing.expect(!resolved.owned);
}

test "drained app channels release capacity without evicting other queued messages" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();
    var control = try ControlSocket.init(allocator, &membership, [_]u8{1} ** 32, .{ 10, 99, 0, 1 }, [_]u8{2} ** 32, "dummy.sock");
    defer control.deinit(allocator);
    const sender = [_]u8{3} ** 32;
    try std.testing.expect(!control.pushMessage(sender, "MGAPP1 meshrooms-v1 "));
    try std.testing.expect(!control.pushAppMessage(sender, "meshrooms-v1", ""));
    try std.testing.expectEqual(@as(usize, 0), control.getMessageCount());
    for (0..MAX_APP_CHANNELS) |i| {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "channel-{d}", .{i});
        try std.testing.expect(control.pushAppMessage(sender, name, "retained"));
    }
    try std.testing.expect(!control.pushAppMessage(sender, "overflow", "full"));
    _ = control.popAppMessage("channel-0").?;
    for (0..MAX_APP_CHANNELS * 2) |i| {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "replacement-{d}", .{i});
        try std.testing.expect(control.pushAppMessage(sender, name, "new"));
        const msg = control.popAppMessage(name).?;
        try std.testing.expectEqualStrings("new", msg.data[0..msg.len]);
        try std.testing.expect(control.popAppMessage(name) == null);
    }
    for (1..MAX_APP_CHANNELS) |i| {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "channel-{d}", .{i});
        const msg = control.popAppMessage(name).?;
        try std.testing.expectEqualStrings("retained", msg.data[0..msg.len]);
    }
}

test "APPINFO reports honest framed maxPayload" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    var resp_buf: [256]u8 = undefined;
    const len = control.handleCommand("APPINFO", &resp_buf);
    try std.testing.expectEqualStrings("{\"protocol\":1,\"maxPayload\":952}\n", resp_buf[0..len]);
}

test "legacy RECV never sees MGAPP1 frames and APPRECV never sees legacy" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const sender = [_]u8{0x11} ** 32;
    try std.testing.expect(control.pushMessage(sender, "legacy-hello"));
    try std.testing.expect(control.pushMessage(sender, "MGAPP1 meshrooms-v1 room-hello"));

    try std.testing.expectEqual(@as(usize, 1), control.getMessageCount());
    try std.testing.expectEqual(@as(usize, 1), control.getAppMessageCount("meshrooms-v1"));

    var resp_buf: [1024]u8 = undefined;
    const recv_len = control.handleCommand("RECV", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..recv_len], "legacy-hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..recv_len], "MGAPP1") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..recv_len], "room-hello") == null);

    const recv_empty = control.handleCommand("RECV", &resp_buf);
    try std.testing.expectEqualStrings("{\"empty\":true}\n", resp_buf[0..recv_empty]);

    const app_len = control.handleCommand("APPRECV meshrooms-v1", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..app_len], "room-hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..app_len], "legacy-hello") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..app_len], "MGAPP1") == null);

    const app_empty = control.handleCommand("APPRECV meshrooms-v1", &resp_buf);
    try std.testing.expectEqualStrings("{\"empty\":true}\n", resp_buf[0..app_empty]);

    const msgs_len = control.handleCommand("MSGS", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..msgs_len], "\"count\":0") != null);
}

test "application channels A and B are isolated" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const sender = [_]u8{0x22} ** 32;
    try std.testing.expect(control.pushMessage(sender, "MGAPP1 chan-a alpha"));
    try std.testing.expect(control.pushMessage(sender, "MGAPP1 chan-b beta"));

    var resp_buf: [1024]u8 = undefined;
    const a_len = control.handleCommand("APPRECV chan-a", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..a_len], "alpha") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..a_len], "beta") == null);

    try std.testing.expectEqual(@as(usize, 0), control.getAppMessageCount("chan-a"));
    try std.testing.expectEqual(@as(usize, 1), control.getAppMessageCount("chan-b"));

    const b_len = control.handleCommand("APPRECV chan-b", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..b_len], "beta") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..b_len], "alpha") == null);
}

test "application queue overflow drops oldest on that channel only" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const sender_a = [_]u8{0x33} ** 32;
    const sender_b = [_]u8{0x44} ** 32;
    try std.testing.expect(control.pushMessage(sender_b, "MGAPP1 chan-b keep-me"));
    try std.testing.expect(control.pushMessage(sender_a, "legacy-keep"));

    var i: usize = 0;
    while (i < MAX_APP_QUEUED_MESSAGES + 5) : (i += 1) {
        var frame_buf: [64]u8 = undefined;
        const frame = std.fmt.bufPrint(&frame_buf, "MGAPP1 chan-a msg-{d}", .{i}) catch unreachable;
        try std.testing.expect(control.pushMessage(sender_a, frame));
    }

    try std.testing.expectEqual(MAX_APP_QUEUED_MESSAGES, control.getAppMessageCount("chan-a"));
    try std.testing.expectEqual(@as(usize, 1), control.getAppMessageCount("chan-b"));
    try std.testing.expectEqual(@as(usize, 1), control.getMessageCount());

    var resp_buf: [1024]u8 = undefined;
    const first = control.handleCommand("APPRECV chan-a", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..first], "msg-5") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..first], "msg-0") == null);

    const other = control.handleCommand("APPRECV chan-b", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..other], "keep-me") != null);

    const legacy = control.handleCommand("RECV", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..legacy], "legacy-keep") != null);
}

test "invalid channel names are rejected by IPC and demux" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const sender = [_]u8{0x55} ** 32;
    try std.testing.expect(!control.pushMessage(sender, "MGAPP1 BAD payload"));
    try std.testing.expect(!control.pushMessage(sender, "MGAPP1 has/slash payload"));
    try std.testing.expectEqual(@as(usize, 0), control.getMessageCount());

    var resp_buf: [512]u8 = undefined;
    const recv_bad = control.handleCommand("APPRECV BAD", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..recv_bad], "invalid channel name") != null);

    const send_bad = control.handleCommand("APPSEND 11" ++ "11" ** 31 ++ " BAD hello", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..send_bad], "invalid channel name") != null);
}

test "oversize and malformed MGAPP1 frames are rejected without truncate" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        [_]u8{2} ** 32,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const sender = [_]u8{0x66} ** 32;
    try std.testing.expect(!control.pushMessage(sender, "MGAPP1 "));
    try std.testing.expect(!control.pushMessage(sender, "MGAPP1 meshrooms-v1"));
    try std.testing.expect(!control.pushMessage(sender, "MGAPP1  payload"));

    var oversize: [MAX_MESSAGE_PAYLOAD + 32]u8 = undefined;
    const prefix = "MGAPP1 meshrooms-v1 ";
    @memcpy(oversize[0..prefix.len], prefix);
    @memset(oversize[prefix.len..], 'x');
    try std.testing.expect(!control.pushMessage(sender, &oversize));
    try std.testing.expectEqual(@as(usize, 0), control.getAppMessageCount("meshrooms-v1"));
    try std.testing.expectEqual(@as(usize, 0), control.getMessageCount());

    // Unframed oversize still truncates onto the legacy queue (preserved behavior).
    var legacy_big: [MAX_MESSAGE_PAYLOAD + 8]u8 = undefined;
    @memset(&legacy_big, 'y');
    try std.testing.expect(control.pushMessage(sender, &legacy_big));
    const popped = control.popMessage();
    try std.testing.expect(popped != null);
    try std.testing.expectEqual(MAX_MESSAGE_PAYLOAD, popped.?.len);
}

test "APPSEND frames plaintext before the 0x50 encrypt path" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 10);
    defer membership.deinit();

    const peer_pk = [_]u8{0x77} ** 32;
    const peer_wg = [_]u8{0x88} ** 32;
    const our_wg = [_]u8{2} ** 32;
    const pub_ep = messages.Endpoint.initV4(.{ 192, 168, 1, 50 }, 51820);

    try membership.upsert(.{
        .pubkey = peer_pk,
        .name = "",
        .state = .alive,
        .gossip_endpoint = null,
        .public_endpoint = pub_ep,
        .wg_pubkey = peer_wg,
        .mesh_ip = .{ 10, 99, 0, 77 },
        .mesh_ip6 = .{0} ** 16,
        .wg_port = 51830,
        .lamport = 1,
        .last_seen_ns = 1,
        .suspected_at_ns = null,
        .last_rtt_ns = null,
        .handshake_complete = false,
    });

    var control = try ControlSocket.init(
        allocator,
        &membership,
        [_]u8{1} ** 32,
        .{ 10, 99, 0, 1 },
        our_wg,
        "dummy.sock",
    );
    defer control.deinit(allocator);

    const DummySender = struct {
        sent: bool = false,
        packet: [2048]u8 = undefined,
        packet_len: usize = 0,

        fn send(ctx_ptr: *anyopaque, data: []const u8, ep: messages.Endpoint) bool {
            _ = ep;
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            self.sent = true;
            const n = @min(data.len, self.packet.len);
            @memcpy(self.packet[0..n], data[0..n]);
            self.packet_len = n;
            return true;
        }
    };

    var dummy = DummySender{};
    control.setSendHandler(&dummy, DummySender.send);

    var resp_buf: [512]u8 = undefined;
    const pk_hex = std.fmt.bytesToHex(peer_pk, .lower);
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "APPSEND {s} meshrooms-v1 hello rooms", .{&pk_hex}) catch unreachable;
    const len = control.handleCommand(cmd, &resp_buf);
    try std.testing.expectEqualStrings("{\"ok\":true}\n", resp_buf[0..len]);
    try std.testing.expect(dummy.sent);
    try std.testing.expect(dummy.packet_len > 93);
    try std.testing.expectEqual(@as(u8, 0x50), dummy.packet[0]);

    const pkt = dummy.packet[0..dummy.packet_len];
    const payload_len = pkt.len - 77 - 16;
    const ciphertext = pkt[77..][0..payload_len];
    const tag: [16]u8 = pkt[77 + payload_len ..][0..16].*;
    const nonce: [12]u8 = pkt[65..77].*;
    const sender_pubkey = pkt[33..65];

    const shared = X25519.scalarmult(our_wg, peer_wg) catch unreachable;
    const key_result = crypto.kdf2(shared, "meshguard-app-v1");
    var plaintext: [1024]u8 = undefined;
    ChaCha20Poly1305.decrypt(
        plaintext[0..payload_len],
        ciphertext,
        tag,
        sender_pubkey,
        nonce,
        key_result.key,
    ) catch unreachable;
    try std.testing.expectEqualStrings("MGAPP1 meshrooms-v1 hello rooms", plaintext[0..payload_len]);

    try std.testing.expect(control.pushMessage(peer_pk, plaintext[0..payload_len]));
    try std.testing.expectEqual(@as(usize, 0), control.getMessageCount());
    const app_len = control.handleCommand("APPRECV meshrooms-v1", &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp_buf[0..app_len], "hello rooms") != null);
    const legacy_empty = control.handleCommand("RECV", &resp_buf);
    try std.testing.expectEqualStrings("{\"empty\":true}\n", resp_buf[0..legacy_empty]);
}
