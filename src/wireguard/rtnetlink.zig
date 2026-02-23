///! RTNETLINK operations for meshguard.
///!
///! Handles interface creation/deletion and IP address assignment
///! using the NETLINK_ROUTE protocol family.
const std = @import("std");
const linux = std.os.linux;
const nl = @import("nlsocket.zig");

/// Create a WireGuard network interface.
pub fn createWgInterface(name: []const u8) !void {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.ROUTE);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        @intFromEnum(linux.NetlinkMessageType.RTM_NEWLINK),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL,
        sock.nextSeq(),
    );

    // ifinfomsg
    b.appendStruct(linux.ifinfomsg, .{
        .family = 0, // AF_UNSPEC
        .__pad1 = 0,
        .type = 0,
        .index = 0,
        .flags = 0,
        .change = 0,
    });

    // IFLA_IFNAME
    b.addAttrStr(@intFromEnum(linux.IFLA.IFNAME), name);

    // IFLA_LINKINFO (nested)
    const linkinfo_off = b.beginNested(@intFromEnum(linux.IFLA.LINKINFO));
    {
        // IFLA_INFO_KIND = "wireguard"
        b.addAttrStr(@intFromEnum(nl.IFLA_INFO.KIND), "wireguard");
    }
    b.endNested(linkinfo_off);

    const msg = b.finish();
    try sock.sendAndAck(msg);
}

/// Delete a network interface by name.
pub fn deleteInterface(name: []const u8) !void {
    const ifindex = try getInterfaceIndex(name);

    var sock = try nl.NetlinkSocket.open(linux.NETLINK.ROUTE);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        @intFromEnum(linux.NetlinkMessageType.RTM_DELLINK),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        sock.nextSeq(),
    );

    b.appendStruct(linux.ifinfomsg, .{
        .family = 0,
        .__pad1 = 0,
        .type = 0,
        .index = @intCast(ifindex),
        .flags = 0,
        .change = 0,
    });

    const msg = b.finish();
    try sock.sendAndAck(msg);
}

/// Get the interface index for a given interface name.
pub fn getInterfaceIndex(name: []const u8) !u32 {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.ROUTE);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        @intFromEnum(linux.NetlinkMessageType.RTM_GETLINK),
        linux.NLM_F_REQUEST,
        sock.nextSeq(),
    );

    b.appendStruct(linux.ifinfomsg, .{
        .family = 0,
        .__pad1 = 0,
        .type = 0,
        .index = 0,
        .flags = 0,
        .change = 0,
    });

    // Filter by name
    b.addAttrStr(@intFromEnum(linux.IFLA.IFNAME), name);

    const msg = b.finish();

    var resp_buf: [8192]u8 align(4) = undefined;
    const n = try sock.sendAndRecv(msg, &resp_buf);

    if (n < @sizeOf(linux.nlmsghdr)) return error.UnexpectedResponse;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(resp_buf[0..@sizeOf(linux.nlmsghdr)]));

    if (resp_hdr.type == .ERROR) {
        return error.NetlinkError;
    }

    // Parse ifinfomsg from response
    const ifinfo_offset = @sizeOf(linux.nlmsghdr);
    if (n < ifinfo_offset + @sizeOf(linux.ifinfomsg)) return error.UnexpectedResponse;

    const ifinfo: *const linux.ifinfomsg = @ptrCast(@alignCast(resp_buf[ifinfo_offset..][0..@sizeOf(linux.ifinfomsg)]));

    if (ifinfo.index == 0) return error.UnexpectedResponse;

    return @intCast(ifinfo.index);
}

/// Add an IPv4 address to an interface.
pub fn addAddress(ifindex: u32, ip: [4]u8, prefix_len: u8) !void {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.ROUTE);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        @intFromEnum(linux.NetlinkMessageType.RTM_NEWADDR),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_REPLACE,
        sock.nextSeq(),
    );

    // ifaddrmsg
    b.appendStruct(nl.ifaddrmsg, .{
        .family = linux.AF.INET,
        .prefixlen = prefix_len,
        .flags = 0,
        .scope = 0, // RT_SCOPE_UNIVERSE
        .index = ifindex,
    });

    // IFA_LOCAL
    b.addAttr(@intFromEnum(linux.IFA.LOCAL), &ip);

    // IFA_ADDRESS
    b.addAttr(@intFromEnum(linux.IFA.ADDRESS), &ip);

    const msg = b.finish();
    try sock.sendAndAck(msg);
}

/// Bring an interface up or down.
pub fn setInterfaceUp(ifindex: u32, up: bool) !void {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.ROUTE);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        @intFromEnum(linux.NetlinkMessageType.RTM_SETLINK),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        sock.nextSeq(),
    );

    b.appendStruct(linux.ifinfomsg, .{
        .family = 0,
        .__pad1 = 0,
        .type = 0,
        .index = @intCast(ifindex),
        .flags = if (up) nl.IFF_UP else 0,
        .change = nl.IFF_UP, // Only change the UP flag
    });

    const msg = b.finish();
    try sock.sendAndAck(msg);
}

/// Add an IPv4 route: dst/prefix_len via interface ifindex.
pub fn addRoute(ifindex: u32, dst: [4]u8, prefix_len: u8) !void {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.ROUTE);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        @intFromEnum(linux.NetlinkMessageType.RTM_NEWROUTE),
        linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_REPLACE,
        sock.nextSeq(),
    );

    // rtmsg structure (12 bytes)
    const rtm = extern struct {
        family: u8, // AF_INET = 2
        dst_len: u8, // Destination prefix length
        src_len: u8, // Source prefix length
        tos: u8,
        table: u8, // RT_TABLE_MAIN = 254
        protocol: u8, // RTPROT_BOOT = 3
        scope: u8, // RT_SCOPE_LINK = 253
        rt_type: u8, // RTN_UNICAST = 1
        flags: u32,
    };

    b.appendStruct(rtm, .{
        .family = linux.AF.INET,
        .dst_len = prefix_len,
        .src_len = 0,
        .tos = 0,
        .table = 254, // RT_TABLE_MAIN
        .protocol = 3, // RTPROT_BOOT
        .scope = 253, // RT_SCOPE_LINK
        .rt_type = 1, // RTN_UNICAST
        .flags = 0,
    });

    // RTA_DST = 1
    b.addAttr(1, &dst);

    // RTA_OIF = 4 (output interface)
    var oif_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &oif_bytes, ifindex, .little);
    b.addAttr(4, &oif_bytes);

    const msg = b.finish();
    try sock.sendAndAck(msg);
}
