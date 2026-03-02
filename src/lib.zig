//! meshguard — decentralized WireGuard mesh VPN
//!
//! This is the library root. All modules are re-exported from here
//! so they can be used both by the CLI binary and by embedders.

const builtin = @import("builtin");
const is_linux = builtin.os.tag == .linux;
const is_windows = builtin.os.tag == .windows;

pub const identity = struct {
    pub const Keys = @import("identity/keys.zig");
    pub const Trust = @import("identity/trust.zig");
    pub const Org = @import("identity/org.zig");
};

pub const discovery = struct {
    pub const Swim = @import("discovery/swim.zig");
    pub const Membership = @import("discovery/membership.zig");
    pub const Seed = @import("discovery/seed.zig");
    pub const Lan = @import("discovery/lan.zig");
};

pub const nat = struct {
    pub const Stun = @import("nat/stun.zig");
    pub const Holepunch = @import("nat/holepunch.zig");
    pub const Relay = @import("nat/relay.zig");
    pub const CoordinatedPunch = @import("nat/coordinated_punch.zig");
    pub const UPnP = @import("nat/upnp.zig");
};

pub const wireguard = struct {
    // Linux-only: kernel WireGuard via netlink
    pub const NlSocket = if (is_linux) @import("wireguard/nlsocket.zig") else struct {};
    pub const RtNetlink = if (is_linux) @import("wireguard/rtnetlink.zig") else struct {};
    pub const Netlink = if (is_linux) @import("wireguard/netlink.zig") else struct {};
    pub const Config = if (is_linux) @import("wireguard/wg_config.zig") else struct {};
    pub const Ip = @import("wireguard/ip.zig");
    pub const Crypto = @import("wireguard/crypto.zig");
    pub const Noise = @import("wireguard/noise.zig");
    pub const Tunnel = @import("wireguard/tunnel.zig");
    pub const Device = @import("wireguard/device.zig");
};

pub const protocol = struct {
    pub const Messages = @import("protocol/messages.zig");
    pub const Codec = @import("protocol/codec.zig");
};

pub const net = struct {
    pub const Udp = @import("net/udp.zig");
    // Linux-only: batch I/O and offload optimizations
    pub const BatchUdp = if (is_linux) @import("net/batch_udp.zig") else struct {};
    pub const Offload = if (is_linux) @import("net/offload.zig") else struct {};
    pub const Io = @import("net/io.zig");
    pub const Tun = if (is_linux) @import("net/tun.zig") else struct {};
    pub const Wintun = if (is_windows) @import("net/wintun.zig") else struct {};
    pub const WinCfg = if (is_windows) @import("net/wincfg.zig") else struct {};
    pub const Dns = @import("net/dns.zig");
    pub const Pipeline = @import("net/pipeline.zig");
    pub const IoUring = if (is_linux) @import("net/io_uring.zig") else struct {};
};

pub const config = @import("config.zig");

pub const services = struct {
    pub const Policy = @import("services/policy.zig");
    pub const Control = @import("services/control.zig");
};

test {
    // Run all module tests
    @import("std").testing.refAllDecls(@This());
    _ = wireguard.Tunnel;
    _ = wireguard.Device;
    _ = wireguard.Noise;
    _ = wireguard.Crypto;
    _ = wireguard.Ip;
    if (is_linux) {
        _ = wireguard.Config;
        _ = wireguard.Netlink;
        _ = wireguard.RtNetlink;
        _ = wireguard.NlSocket;
    }
    _ = services.Policy;
}

