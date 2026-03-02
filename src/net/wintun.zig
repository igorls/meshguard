//! Wintun adapter wrapper for Windows — mirrors the TunDevice API.
//!
//! Dynamically loads wintun.dll at runtime via LoadLibraryW/GetProcAddress.
//! This allows the meshguard binary to work for non-daemon commands even
//! when wintun.dll is not present.
//!
//! Wintun provides a ring-buffer based packet I/O API:
//!   - WintunReceivePacket returns a pointer into the ring buffer
//!   - Caller must copy data and call WintunReleaseReceivePacket
//!   - WintunAllocateSendPacket + WintunSendPacket for outbound
//!
//! Reference: https://git.zx2c4.com/wintun/tree/api/wintun.h

const std = @import("std");
const windows = std.os.windows;

// ─── Windows Types ───

const HANDLE = windows.HANDLE;
const HMODULE = windows.HMODULE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const BYTE = u8;
const LPCWSTR = [*:0]const u16;

// Opaque handles
const WINTUN_ADAPTER_HANDLE = *opaque {};
const WINTUN_SESSION_HANDLE = *opaque {};

// Ring buffer capacity: 4 MiB (matches wireguard-go default)
const RING_CAPACITY: DWORD = 0x400000;

// Max IP packet size
const MAX_IP_PACKET_SIZE: DWORD = 0xFFFF;

// ─── Wintun Function Types ───

const WintunCreateAdapterFn = *const fn (
    name: LPCWSTR,
    tunnel_type: LPCWSTR,
    requested_guid: ?*const windows.GUID,
) callconv(.winapi) ?WINTUN_ADAPTER_HANDLE;

const WintunCloseAdapterFn = *const fn (
    adapter: WINTUN_ADAPTER_HANDLE,
) callconv(.winapi) void;

const WintunStartSessionFn = *const fn (
    adapter: WINTUN_ADAPTER_HANDLE,
    capacity: DWORD,
) callconv(.winapi) ?WINTUN_SESSION_HANDLE;

const WintunEndSessionFn = *const fn (
    session: WINTUN_SESSION_HANDLE,
) callconv(.winapi) void;

const WintunGetReadWaitEventFn = *const fn (
    session: WINTUN_SESSION_HANDLE,
) callconv(.winapi) HANDLE;

const WintunReceivePacketFn = *const fn (
    session: WINTUN_SESSION_HANDLE,
    packet_size: *DWORD,
) callconv(.winapi) ?[*]const BYTE;

const WintunReleaseReceivePacketFn = *const fn (
    session: WINTUN_SESSION_HANDLE,
    packet: [*]const BYTE,
) callconv(.winapi) void;

const WintunAllocateSendPacketFn = *const fn (
    session: WINTUN_SESSION_HANDLE,
    packet_size: DWORD,
) callconv(.winapi) ?[*]BYTE;

const WintunSendPacketFn = *const fn (
    session: WINTUN_SESSION_HANDLE,
    packet: [*]const BYTE,
) callconv(.winapi) void;

// ─── Wintun API Table ───

const WintunApi = struct {
    dll: HMODULE,
    createAdapter: WintunCreateAdapterFn,
    closeAdapter: WintunCloseAdapterFn,
    startSession: WintunStartSessionFn,
    endSession: WintunEndSessionFn,
    getReadWaitEvent: WintunGetReadWaitEventFn,
    receivePacket: WintunReceivePacketFn,
    releaseReceivePacket: WintunReleaseReceivePacketFn,
    allocateSendPacket: WintunAllocateSendPacketFn,
    sendPacket: WintunSendPacketFn,
};

fn loadWintunApi() !WintunApi {
    const dll_name = std.unicode.utf8ToUtf16LeStringLiteral("wintun.dll");
    const dll = windows.kernel32.LoadLibraryW(dll_name) orelse
        return error.WintunDllNotFound;
    errdefer _ = windows.kernel32.FreeLibrary(dll);

    return .{
        .dll = dll,
        .createAdapter = @ptrCast(getProcOrError(dll, "WintunCreateAdapter") orelse return error.WintunApiMissing),
        .closeAdapter = @ptrCast(getProcOrError(dll, "WintunCloseAdapter") orelse return error.WintunApiMissing),
        .startSession = @ptrCast(getProcOrError(dll, "WintunStartSession") orelse return error.WintunApiMissing),
        .endSession = @ptrCast(getProcOrError(dll, "WintunEndSession") orelse return error.WintunApiMissing),
        .getReadWaitEvent = @ptrCast(getProcOrError(dll, "WintunGetReadWaitEvent") orelse return error.WintunApiMissing),
        .receivePacket = @ptrCast(getProcOrError(dll, "WintunReceivePacket") orelse return error.WintunApiMissing),
        .releaseReceivePacket = @ptrCast(getProcOrError(dll, "WintunReleaseReceivePacket") orelse return error.WintunApiMissing),
        .allocateSendPacket = @ptrCast(getProcOrError(dll, "WintunAllocateSendPacket") orelse return error.WintunApiMissing),
        .sendPacket = @ptrCast(getProcOrError(dll, "WintunSendPacket") orelse return error.WintunApiMissing),
    };
}

fn getProcOrError(dll: HMODULE, name: [*:0]const u8) ?windows.FARPROC {
    return windows.kernel32.GetProcAddress(dll, name);
}

// ─── WintunDevice ───

pub const WintunDevice = struct {
    api: WintunApi,
    adapter: WINTUN_ADAPTER_HANDLE,
    session: WINTUN_SESSION_HANDLE,
    read_event: HANDLE,
    name: [16]u8,
    name_len: usize,
    vnet_hdr: bool = false, // always false — Wintun doesn't use virtio headers

    /// Open (create) a Wintun adapter and start a session.
    /// Requires administrator privileges.
    pub fn open(name: []const u8) !WintunDevice {
        const api = try loadWintunApi();
        errdefer _ = windows.kernel32.FreeLibrary(api.dll);

        // Convert adapter name to wide string
        var wide_name: [128]u16 = undefined;
        const wide_len = nameToWide(name, &wide_name);
        wide_name[wide_len] = 0;
        const name_ptr: LPCWSTR = @ptrCast(&wide_name);

        // Tunnel type (shown in Device Manager)
        const tunnel_type = std.unicode.utf8ToUtf16LeStringLiteral("MeshGuard");

        // Create the adapter
        const adapter = api.createAdapter(name_ptr, tunnel_type, null) orelse
            return error.WintunCreateFailed;
        errdefer api.closeAdapter(adapter);

        // Start a session with 4 MiB ring buffer
        const session = api.startSession(adapter, RING_CAPACITY) orelse
            return error.WintunSessionFailed;
        errdefer api.endSession(session);

        // Get the read-wait event handle for efficient blocking
        const read_event = api.getReadWaitEvent(session);

        // Store name
        var stored_name: [16]u8 = .{0} ** 16;
        const copy_len = @min(name.len, 15);
        @memcpy(stored_name[0..copy_len], name[0..copy_len]);

        return .{
            .api = api,
            .adapter = adapter,
            .session = session,
            .read_event = read_event,
            .name = stored_name,
            .name_len = copy_len,
        };
    }

    /// Read an IP packet from the Wintun adapter.
    /// Returns the number of bytes copied, or 0 if no data available.
    pub fn read(self: *WintunDevice, buf: []u8) !usize {
        var packet_size: DWORD = 0;
        const packet_ptr = self.api.receivePacket(self.session, &packet_size);

        if (packet_ptr) |ptr| {
            // Copy packet data to caller's buffer
            const copy_len = @min(packet_size, @as(DWORD, @intCast(buf.len)));
            @memcpy(buf[0..copy_len], ptr[0..copy_len]);
            self.api.releaseReceivePacket(self.session, ptr);
            return copy_len;
        }

        // No packet available — check if it's just empty or a real error
        const last_error = windows.kernel32.GetLastError();
        if (last_error == .NO_MORE_ITEMS) {
            return 0; // Ring buffer empty, not an error
        } else if (last_error == .HANDLE_EOF) {
            return error.WintunSessionClosed;
        } else {
            return 0; // Treat other errors as no-data
        }
    }

    /// Write an IP packet to the Wintun adapter (inject into OS network stack).
    pub fn write(self: *WintunDevice, data: []const u8) !void {
        if (data.len == 0 or data.len > MAX_IP_PACKET_SIZE) return;

        const packet_ptr = self.api.allocateSendPacket(
            self.session,
            @intCast(data.len),
        );

        if (packet_ptr) |ptr| {
            @memcpy(ptr[0..data.len], data);
            self.api.sendPacket(self.session, ptr);
        } else {
            const last_error = windows.kernel32.GetLastError();
            if (last_error == .HANDLE_EOF) {
                return error.WintunSessionClosed;
            }
            // Buffer full — drop packet (matches WireGuard behavior)
        }
    }

    /// Block until a packet is available or timeout expires.
    /// Returns true if data is ready to read.
    pub fn pollRead(self: *WintunDevice, timeout_ms: i32) !bool {
        const timeout: DWORD = if (timeout_ms < 0) windows.INFINITE else @intCast(timeout_ms);
        const result = windows.kernel32.WaitForSingleObject(self.read_event, timeout);
        return result == windows.WAIT_OBJECT_0;
    }

    /// Set the MTU on the Wintun adapter via netsh.
    pub fn setMtu(self: *const WintunDevice, mtu: u32) !void {
        _ = mtu;
        _ = self;
        // MTU is set via wincfg.setMtu() using netsh
        // This is a no-op here; caller should use wincfg directly
    }

    /// No-op on Windows — Wintun doesn't support GSO/GRO offloads.
    pub fn enableOffload(self: *WintunDevice) void {
        _ = self;
    }

    /// Get the interface name as a slice.
    pub fn getName(self: *const WintunDevice) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Close the Wintun session and adapter, free the DLL.
    pub fn close(self: *WintunDevice) void {
        self.api.endSession(self.session);
        self.api.closeAdapter(self.adapter);
        _ = windows.kernel32.FreeLibrary(self.api.dll);
    }
};

// ─── Helpers ───

fn nameToWide(name: []const u8, out: []u16) usize {
    var i: usize = 0;
    while (i < name.len and i < out.len - 1) : (i += 1) {
        out[i] = @intCast(name[i]);
    }
    return i;
}
