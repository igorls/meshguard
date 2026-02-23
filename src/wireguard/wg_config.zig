///! WireGuard interface orchestrator for meshguard.
///!
///! High-level API that coordinates RTNETLINK (interface CRUD) and
///! WireGuard generic netlink (device configuration) to provide
///! a simple setup/teardown interface for the mesh daemon.
const std = @import("std");
const rtnetlink = @import("rtnetlink.zig");
const wg_netlink = @import("netlink.zig");
const ip_alloc = @import("ip.zig");

/// Default interface name for meshguard.
pub const DEFAULT_IFNAME = "mg0";

/// Full configuration for setting up a mesh interface.
pub const MeshConfig = struct {
    ifname: []const u8 = DEFAULT_IFNAME,
    private_key: [32]u8,
    listen_port: u16 = 51820,
    mesh_ip: [4]u8,
    mesh_prefix: u8 = 16, // /16 for 10.99.0.0/16
};

pub const SetupError = error{
    WireGuardModuleNotLoaded,
    InterfaceAlreadyExists,
    PermissionDenied,
    NetlinkError,
    SocketCreateFailed,
    BindFailed,
    SendFailed,
    RecvFailed,
    UnexpectedResponse,
    FamilyNotFound,
};

/// Set up the full mesh interface:
/// 1. Create WireGuard interface
/// 2. Configure private key and listen port
/// 3. Assign mesh IP address
/// 4. Bring interface up
pub fn setup(config: MeshConfig) SetupError!void {
    // Step 1: Create the interface via RTNETLINK
    rtnetlink.createWgInterface(config.ifname) catch |err| {
        return switch (err) {
            error.NetlinkError => error.InterfaceAlreadyExists,
            error.SocketCreateFailed => error.PermissionDenied,
            else => error.NetlinkError,
        };
    };

    // Step 2: Resolve WireGuard family and configure device
    const family_id = wg_netlink.resolveWireguardFamily() catch {
        // Cleanup: delete the interface we just created
        rtnetlink.deleteInterface(config.ifname) catch {};
        return error.WireGuardModuleNotLoaded;
    };

    wg_netlink.setDevice(family_id, .{
        .ifname = config.ifname,
        .private_key = config.private_key,
        .listen_port = config.listen_port,
    }) catch {
        rtnetlink.deleteInterface(config.ifname) catch {};
        return error.NetlinkError;
    };

    // Step 3: Assign mesh IP address
    const ifindex = rtnetlink.getInterfaceIndex(config.ifname) catch {
        rtnetlink.deleteInterface(config.ifname) catch {};
        return error.NetlinkError;
    };

    rtnetlink.addAddress(ifindex, config.mesh_ip, config.mesh_prefix) catch {
        rtnetlink.deleteInterface(config.ifname) catch {};
        return error.NetlinkError;
    };

    // Step 4: Bring interface up
    rtnetlink.setInterfaceUp(ifindex, true) catch {
        rtnetlink.deleteInterface(config.ifname) catch {};
        return error.NetlinkError;
    };
}

/// Tear down the mesh interface.
pub fn teardown(ifname: []const u8) !void {
    // Bring down first (best-effort)
    if (rtnetlink.getInterfaceIndex(ifname)) |ifindex| {
        rtnetlink.setInterfaceUp(ifindex, false) catch {};
    } else |_| {}

    // Delete the interface
    try rtnetlink.deleteInterface(ifname);
}

/// Add a peer to the running mesh.
pub fn addPeer(ifname: []const u8, peer: wg_netlink.PeerConfig) !void {
    const family_id = try wg_netlink.resolveWireguardFamily();
    try wg_netlink.addPeer(family_id, ifname, peer);
}

/// Remove a peer from the running mesh.
pub fn removePeer(ifname: []const u8, public_key: [32]u8) !void {
    const family_id = try wg_netlink.resolveWireguardFamily();
    try wg_netlink.removePeer(family_id, ifname, public_key);
}

/// Derive mesh IP from identity public key and return a MeshConfig.
pub fn configFromIdentity(
    private_key: [32]u8,
    public_key_bytes: [32]u8,
    listen_port: u16,
) MeshConfig {
    const mesh_ip = ip_alloc.deriveMeshIp(public_key_bytes);
    return MeshConfig{
        .private_key = private_key,
        .listen_port = listen_port,
        .mesh_ip = mesh_ip,
    };
}
