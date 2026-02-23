///! Shared netlink socket abstraction for meshguard.
///!
///! Provides a low-level netlink socket client with NLA (Netlink Attribute)
///! helpers for building properly-aligned TLV messages. Used by both
///! rtnetlink.zig (NETLINK_ROUTE) and netlink.zig (NETLINK_GENERIC).
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

/// Netlink Attribute header (mirrors struct nlattr from linux/netlink.h)
pub const nlattr = extern struct {
    len: u16,
    type: u16,
};

/// Generic netlink message header (mirrors struct genlmsghdr)
pub const genlmsghdr = extern struct {
    cmd: u8,
    version: u8,
    reserved: u16 = 0,
};

/// IFLA_INFO sub-attributes for link info
pub const IFLA_INFO = enum(u16) {
    UNSPEC = 0,
    KIND = 1,
    DATA = 2,
    XSTATS = 3,
    SLAVE_KIND = 4,
    SLAVE_DATA = 5,
    _,
};

/// Generic netlink controller commands
pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;

/// Controller attribute types
pub const CTRL_ATTR = enum(u16) {
    UNSPEC = 0,
    FAMILY_ID = 1,
    FAMILY_NAME = 2,
    VERSION = 3,
    HDRSIZE = 4,
    MAXATTR = 5,
    OPS = 6,
    MCAST_GROUPS = 7,
    POLICY = 8,
    OP_POLICY = 9,
    OP = 10,
    _,
};

/// WireGuard generic netlink commands
pub const WG_CMD_GET_DEVICE: u8 = 0;
pub const WG_CMD_SET_DEVICE: u8 = 1;

/// WireGuard device attributes
pub const WGDEVICE_A = enum(u16) {
    UNSPEC = 0,
    IFINDEX = 1,
    IFNAME = 2,
    PRIVATE_KEY = 3,
    PUBLIC_KEY = 4,
    FLAGS = 5,
    LISTEN_PORT = 6,
    FWMARK = 7,
    PEERS = 8,
    _,
};

/// WireGuard peer attributes
pub const WGPEER_A = enum(u16) {
    UNSPEC = 0,
    PUBLIC_KEY = 1,
    PRESHARED_KEY = 2,
    FLAGS = 3,
    ENDPOINT = 4,
    PERSISTENT_KEEPALIVE_INTERVAL = 5,
    LAST_HANDSHAKE_TIME = 6,
    RX_BYTES = 7,
    TX_BYTES = 8,
    ALLOWEDIPS = 9,
    PROTOCOL_VERSION = 10,
    _,
};

/// WireGuard allowed IP attributes
pub const WGALLOWEDIP_A = enum(u16) {
    UNSPEC = 0,
    FAMILY = 1,
    IPADDR = 2,
    CIDR_MASK = 3,
    _,
};

/// WireGuard peer flags
pub const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
pub const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;

/// WireGuard device flags
pub const WGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;

/// ifaddrmsg for RTM_NEWADDR/RTM_DELADDR
pub const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

/// IFF flags for interface up/down
pub const IFF_UP: c_uint = 1;

// NLA alignment
const NLA_ALIGNTO: u16 = 4;

fn nlaAlign(len: u16) u16 {
    return (len + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1);
}

fn nlmsgAlign(len: u32) u32 {
    return (len + 3) & ~@as(u32, 3);
}

/// A buffer for building netlink messages.
pub const MessageBuilder = struct {
    buf: [8192]u8 align(4) = undefined,
    pos: u32 = 0,

    /// Initialize with a netlink message header.
    pub fn init(msg_type: u16, flags: u16, seq: u32) MessageBuilder {
        var self = MessageBuilder{};
        // Write nlmsghdr placeholder (will be patched at finish)
        const hdr = self.headerPtr();
        hdr.* = .{
            .len = @sizeOf(linux.nlmsghdr),
            .type = @enumFromInt(msg_type),
            .flags = flags,
            .seq = seq,
            .pid = 0,
        };
        self.pos = @sizeOf(linux.nlmsghdr);
        return self;
    }

    /// Get pointer to the nlmsghdr at the start of the buffer.
    pub fn headerPtr(self: *MessageBuilder) *linux.nlmsghdr {
        return @ptrCast(@alignCast(self.buf[0..@sizeOf(linux.nlmsghdr)]));
    }

    /// Append raw bytes (with padding to 4-byte alignment).
    pub fn appendRaw(self: *MessageBuilder, data: []const u8) void {
        const aligned_pos = nlmsgAlign(self.pos);
        // Zero padding bytes
        if (aligned_pos > self.pos) {
            @memset(self.buf[self.pos..aligned_pos], 0);
        }
        @memcpy(self.buf[aligned_pos..][0..data.len], data);
        self.pos = aligned_pos + @as(u32, @intCast(data.len));
    }

    /// Append a fixed-size struct.
    pub fn appendStruct(self: *MessageBuilder, comptime T: type, val: T) void {
        self.appendRaw(std.mem.asBytes(&val));
    }

    /// Add an NLA attribute with raw data payload.
    pub fn addAttr(self: *MessageBuilder, attr_type: u16, data: []const u8) void {
        const hdr_size: u16 = @sizeOf(nlattr);
        const total_len: u16 = hdr_size + @as(u16, @intCast(data.len));
        const aligned_total = nlaAlign(total_len);

        // Align current position
        const aligned_pos = nlmsgAlign(self.pos);
        if (aligned_pos > self.pos) {
            @memset(self.buf[self.pos..aligned_pos], 0);
        }

        // Write NLA header
        const nla_hdr: *nlattr = @ptrCast(@alignCast(self.buf[aligned_pos..][0..@sizeOf(nlattr)]));
        nla_hdr.* = .{ .len = total_len, .type = attr_type };

        // Write payload
        @memcpy(self.buf[aligned_pos + hdr_size ..][0..data.len], data);

        // Zero padding
        const payload_end = aligned_pos + total_len;
        const padded_end = aligned_pos + aligned_total;
        if (padded_end > payload_end) {
            @memset(self.buf[payload_end..padded_end], 0);
        }

        self.pos = aligned_pos + aligned_total;
    }

    /// Add a u16 NLA attribute.
    pub fn addAttrU16(self: *MessageBuilder, attr_type: u16, value: u16) void {
        self.addAttr(attr_type, std.mem.asBytes(&value));
    }

    /// Add a u32 NLA attribute.
    pub fn addAttrU32(self: *MessageBuilder, attr_type: u16, value: u32) void {
        self.addAttr(attr_type, std.mem.asBytes(&value));
    }

    /// Add a string NLA attribute (null-terminated).
    pub fn addAttrStr(self: *MessageBuilder, attr_type: u16, str: []const u8) void {
        // Need null terminator
        const hdr_size: u16 = @sizeOf(nlattr);
        const str_len: u16 = @intCast(str.len + 1); // +1 for null
        const total_len: u16 = hdr_size + str_len;
        const aligned_total = nlaAlign(total_len);

        const aligned_pos = nlmsgAlign(self.pos);
        if (aligned_pos > self.pos) {
            @memset(self.buf[self.pos..aligned_pos], 0);
        }

        const nla_hdr: *nlattr = @ptrCast(@alignCast(self.buf[aligned_pos..][0..@sizeOf(nlattr)]));
        nla_hdr.* = .{ .len = total_len, .type = attr_type };

        @memcpy(self.buf[aligned_pos + hdr_size ..][0..str.len], str);
        self.buf[aligned_pos + hdr_size + @as(u32, @intCast(str.len))] = 0; // null terminator

        const payload_end = aligned_pos + total_len;
        const padded_end = aligned_pos + aligned_total;
        if (padded_end > payload_end) {
            @memset(self.buf[payload_end..padded_end], 0);
        }

        self.pos = aligned_pos + aligned_total;
    }

    /// Begin a nested NLA attribute. Returns the offset to patch later with endNested().
    pub fn beginNested(self: *MessageBuilder, attr_type: u16) u32 {
        const aligned_pos = nlmsgAlign(self.pos);
        if (aligned_pos > self.pos) {
            @memset(self.buf[self.pos..aligned_pos], 0);
        }

        const offset = aligned_pos;
        // Write placeholder NLA header
        const nla_hdr: *nlattr = @ptrCast(@alignCast(self.buf[aligned_pos..][0..@sizeOf(nlattr)]));
        nla_hdr.* = .{ .len = 0, .type = attr_type | (1 << 15) }; // NLA_F_NESTED
        self.pos = aligned_pos + @sizeOf(nlattr);
        return offset;
    }

    /// End a nested NLA attribute, patching the length.
    pub fn endNested(self: *MessageBuilder, offset: u32) void {
        const nla_hdr: *nlattr = @ptrCast(@alignCast(self.buf[offset..][0..@sizeOf(nlattr)]));
        nla_hdr.len = @intCast(self.pos - offset);
    }

    /// Finalize the message: patch the nlmsghdr length field.
    pub fn finish(self: *MessageBuilder) []const u8 {
        const hdr = self.headerPtr();
        hdr.len = self.pos;
        return self.buf[0..self.pos];
    }
};

/// Netlink socket wrapper.
pub const NetlinkSocket = struct {
    fd: posix.fd_t,
    seq: u32 = 1,

    pub const Error = error{
        SocketCreateFailed,
        BindFailed,
        SendFailed,
        RecvFailed,
        NetlinkError,
        UnexpectedResponse,
        FamilyNotFound,
    } || posix.SendError || posix.RecvFromError;

    /// Open a netlink socket for the given protocol (e.g. NETLINK.ROUTE, NETLINK.GENERIC).
    pub fn open(protocol: u32) !NetlinkSocket {
        const fd = posix.socket(
            linux.AF.NETLINK,
            @intCast(linux.SOCK.RAW | linux.SOCK.CLOEXEC),
            protocol,
        ) catch return error.SocketCreateFailed;

        // Bind to kernel
        var addr = linux.sockaddr.nl{
            .pid = 0,
            .groups = 0,
        };

        posix.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl)) catch return error.BindFailed;

        return NetlinkSocket{ .fd = fd };
    }

    /// Close the socket.
    pub fn close(self: *NetlinkSocket) void {
        posix.close(self.fd);
    }

    /// Get next sequence number.
    pub fn nextSeq(self: *NetlinkSocket) u32 {
        const s = self.seq;
        self.seq += 1;
        return s;
    }

    /// Send a message and wait for ACK. Returns error on NLMSG_ERROR with non-zero error.
    pub fn sendAndAck(self: *NetlinkSocket, msg: []const u8) !void {
        _ = posix.send(self.fd, msg, 0) catch return error.SendFailed;

        var resp_buf: [8192]u8 align(4) = undefined;
        const n = posix.recv(self.fd, &resp_buf, 0) catch return error.RecvFailed;

        if (n < @sizeOf(linux.nlmsghdr)) return error.UnexpectedResponse;

        const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(resp_buf[0..@sizeOf(linux.nlmsghdr)]));

        if (resp_hdr.type == .ERROR) {
            // nlmsgerr: error code follows the nlmsghdr
            if (n < @sizeOf(linux.nlmsghdr) + 4) return error.UnexpectedResponse;
            const err_code: *const i32 = @ptrCast(@alignCast(resp_buf[@sizeOf(linux.nlmsghdr)..][0..4]));
            if (err_code.* != 0) {
                return error.NetlinkError;
            }
            // err_code == 0 means ACK
            return;
        }

        // Some responses are not errors (e.g. dump responses)
    }

    /// Send a message and return the raw response buffer + length.
    pub fn sendAndRecv(self: *NetlinkSocket, msg: []const u8, resp_buf: []u8) !usize {
        _ = posix.send(self.fd, msg, 0) catch return error.SendFailed;
        return posix.recv(self.fd, resp_buf, 0) catch return error.RecvFailed;
    }
};

// ─── Tests ───

test "MessageBuilder NLA alignment" {
    var b = MessageBuilder.init(0, 0, 1);

    // After init, pos should be sizeof(nlmsghdr)
    try std.testing.expectEqual(b.pos, @as(u32, @sizeOf(linux.nlmsghdr)));

    // Add a small attribute (3-byte payload → should be padded to 4)
    b.addAttr(1, &[_]u8{ 0xAA, 0xBB, 0xCC });

    // nlattr header = 4 bytes, payload = 3 bytes, padding = 1 byte → total 8
    const expected_pos = @as(u32, @sizeOf(linux.nlmsghdr)) + 8;
    try std.testing.expectEqual(b.pos, expected_pos);
}

test "MessageBuilder nested attributes" {
    var b = MessageBuilder.init(0, 0, 1);

    const nest_offset = b.beginNested(1);
    b.addAttrU16(2, 42);
    b.endNested(nest_offset);

    const msg = b.finish();
    try std.testing.expect(msg.len > @sizeOf(linux.nlmsghdr));
}
