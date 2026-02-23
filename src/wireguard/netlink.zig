///! WireGuard generic netlink client for meshguard.
///!
///! Communicates with the WireGuard kernel module via NETLINK_GENERIC
///! to set private keys, listen ports, and manage peers.
const std = @import("std");
const linux = std.os.linux;
const nl = @import("nlsocket.zig");

/// WireGuard device configuration.
pub const DeviceConfig = struct {
    ifname: []const u8,
    private_key: [32]u8,
    listen_port: u16,
};

/// WireGuard peer configuration.
pub const PeerConfig = struct {
    public_key: [32]u8,
    endpoint_addr: ?[4]u8 = null,
    endpoint_port: ?u16 = null,
    allowed_ips: []const AllowedIp = &.{},
    persistent_keepalive: u16 = 0,
};

/// An allowed IP entry.
pub const AllowedIp = struct {
    addr: [4]u8,
    cidr: u8,
};

/// Resolve the WireGuard generic netlink family ID.
/// Returns the family_id needed for subsequent WG commands.
pub fn resolveWireguardFamily() !u16 {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.GENERIC);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        nl.GENL_ID_CTRL,
        linux.NLM_F_REQUEST,
        sock.nextSeq(),
    );

    // genlmsghdr: CTRL_CMD_GETFAMILY
    b.appendStruct(nl.genlmsghdr, .{
        .cmd = nl.CTRL_CMD_GETFAMILY,
        .version = 1,
    });

    // CTRL_ATTR_FAMILY_NAME = "wireguard"
    b.addAttrStr(@intFromEnum(nl.CTRL_ATTR.FAMILY_NAME), "wireguard");

    const msg = b.finish();

    var resp_buf: [4096]u8 align(4) = undefined;
    const n = try sock.sendAndRecv(msg, &resp_buf);

    // Parse response to find CTRL_ATTR_FAMILY_ID
    return parseFamilyId(resp_buf[0..n]);
}

/// Set WireGuard device configuration (private key and listen port).
pub fn setDevice(family_id: u16, config: DeviceConfig) !void {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.GENERIC);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        family_id,
        linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        sock.nextSeq(),
    );

    // genlmsghdr
    b.appendStruct(nl.genlmsghdr, .{
        .cmd = nl.WG_CMD_SET_DEVICE,
        .version = 1,
    });

    // WGDEVICE_A_IFNAME
    b.addAttrStr(@intFromEnum(nl.WGDEVICE_A.IFNAME), config.ifname);

    // WGDEVICE_A_PRIVATE_KEY (32 bytes)
    b.addAttr(@intFromEnum(nl.WGDEVICE_A.PRIVATE_KEY), &config.private_key);

    // WGDEVICE_A_LISTEN_PORT (u16)
    b.addAttrU16(@intFromEnum(nl.WGDEVICE_A.LISTEN_PORT), config.listen_port);

    const msg = b.finish();
    try sock.sendAndAck(msg);
}

/// Add a peer to a WireGuard device.
pub fn addPeer(family_id: u16, ifname: []const u8, peer: PeerConfig) !void {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.GENERIC);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        family_id,
        linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        sock.nextSeq(),
    );

    b.appendStruct(nl.genlmsghdr, .{
        .cmd = nl.WG_CMD_SET_DEVICE,
        .version = 1,
    });

    b.addAttrStr(@intFromEnum(nl.WGDEVICE_A.IFNAME), ifname);

    // WGDEVICE_A_PEERS (nested)
    const peers_off = b.beginNested(@intFromEnum(nl.WGDEVICE_A.PEERS));
    {
        // First (only) peer entry — nested with index 0
        const peer_off = b.beginNested(0);
        {
            // WGPEER_A_PUBLIC_KEY
            b.addAttr(@intFromEnum(nl.WGPEER_A.PUBLIC_KEY), &peer.public_key);

            // WGPEER_A_FLAGS — replace allowed IPs for this peer
            b.addAttrU32(@intFromEnum(nl.WGPEER_A.FLAGS), nl.WGPEER_F_REPLACE_ALLOWEDIPS);

            // WGPEER_A_ENDPOINT (sockaddr_in)
            if (peer.endpoint_addr) |addr| {
                if (peer.endpoint_port) |port| {
                    // Build sockaddr_in (16 bytes)
                    var sa: [16]u8 = std.mem.zeroes([16]u8);
                    sa[0] = @intCast(linux.AF.INET); // sin_family (low byte)
                    sa[1] = 0;
                    // sin_port (network byte order)
                    sa[2] = @intCast(port >> 8);
                    sa[3] = @intCast(port & 0xff);
                    // sin_addr
                    sa[4] = addr[0];
                    sa[5] = addr[1];
                    sa[6] = addr[2];
                    sa[7] = addr[3];
                    b.addAttr(@intFromEnum(nl.WGPEER_A.ENDPOINT), &sa);
                }
            }

            // WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL
            if (peer.persistent_keepalive > 0) {
                b.addAttrU16(@intFromEnum(nl.WGPEER_A.PERSISTENT_KEEPALIVE_INTERVAL), peer.persistent_keepalive);
            }

            // WGPEER_A_ALLOWEDIPS (nested)
            if (peer.allowed_ips.len > 0) {
                const aips_off = b.beginNested(@intFromEnum(nl.WGPEER_A.ALLOWEDIPS));
                for (peer.allowed_ips, 0..) |aip, idx| {
                    const aip_off = b.beginNested(@intCast(idx));
                    {
                        b.addAttrU16(@intFromEnum(nl.WGALLOWEDIP_A.FAMILY), @intCast(linux.AF.INET));
                        b.addAttr(@intFromEnum(nl.WGALLOWEDIP_A.IPADDR), &aip.addr);
                        b.addAttr(@intFromEnum(nl.WGALLOWEDIP_A.CIDR_MASK), &[_]u8{aip.cidr});
                    }
                    b.endNested(aip_off);
                }
                b.endNested(aips_off);
            }
        }
        b.endNested(peer_off);
    }
    b.endNested(peers_off);

    const msg = b.finish();
    try sock.sendAndAck(msg);
}

/// Remove a peer from a WireGuard device by public key.
pub fn removePeer(family_id: u16, ifname: []const u8, public_key: [32]u8) !void {
    var sock = try nl.NetlinkSocket.open(linux.NETLINK.GENERIC);
    defer sock.close();

    var b = nl.MessageBuilder.init(
        family_id,
        linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        sock.nextSeq(),
    );

    b.appendStruct(nl.genlmsghdr, .{
        .cmd = nl.WG_CMD_SET_DEVICE,
        .version = 1,
    });

    b.addAttrStr(@intFromEnum(nl.WGDEVICE_A.IFNAME), ifname);

    const peers_off = b.beginNested(@intFromEnum(nl.WGDEVICE_A.PEERS));
    {
        const peer_off = b.beginNested(0);
        {
            b.addAttr(@intFromEnum(nl.WGPEER_A.PUBLIC_KEY), &public_key);
            b.addAttrU32(@intFromEnum(nl.WGPEER_A.FLAGS), nl.WGPEER_F_REMOVE_ME);
        }
        b.endNested(peer_off);
    }
    b.endNested(peers_off);

    const msg = b.finish();
    try sock.sendAndAck(msg);
}

// ─── Internal helpers ───

fn parseFamilyId(data: []const u8) !u16 {
    const hdr_size = @sizeOf(linux.nlmsghdr);
    if (data.len < hdr_size) return error.UnexpectedResponse;

    const hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(data[0..hdr_size]));
    if (hdr.type == .ERROR) return error.FamilyNotFound;

    // Skip nlmsghdr + genlmsghdr
    const genl_offset = hdr_size + @sizeOf(nl.genlmsghdr);
    if (data.len < genl_offset) return error.UnexpectedResponse;

    // Parse NLA attributes
    var offset: usize = genl_offset;
    while (offset + @sizeOf(nl.nlattr) <= data.len) {
        const nla: *const nl.nlattr = @ptrCast(@alignCast(data[offset..][0..@sizeOf(nl.nlattr)]));
        if (nla.len < @sizeOf(nl.nlattr)) break;

        const attr_type = nla.type & 0x3fff; // Strip NLA_F_NESTED flag
        const payload_offset = offset + @sizeOf(nl.nlattr);

        if (attr_type == @intFromEnum(nl.CTRL_ATTR.FAMILY_ID)) {
            if (payload_offset + 2 <= data.len) {
                const id_bytes = data[payload_offset..][0..2];
                return std.mem.readInt(u16, id_bytes, .little);
            }
        }

        // Advance to next NLA (aligned)
        const aligned_len = (nla.len + 3) & ~@as(u16, 3);
        offset += aligned_len;
    }

    return error.FamilyNotFound;
}
