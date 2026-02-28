//! meshguard — decentralized WireGuard mesh VPN
//!
//! This is the library root. All modules are re-exported from here
//! so they can be used both by the CLI binary and by embedders.

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
    pub const NlSocket = @import("wireguard/nlsocket.zig");
    pub const RtNetlink = @import("wireguard/rtnetlink.zig");
    pub const Netlink = @import("wireguard/netlink.zig");
    pub const Config = @import("wireguard/wg_config.zig");
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
    pub const BatchUdp = @import("net/batch_udp.zig");
    pub const Offload = @import("net/offload.zig");
    pub const Io = @import("net/io.zig");
    pub const Tun = @import("net/tun.zig");
    pub const Dns = @import("net/dns.zig");
    pub const Pipeline = @import("net/pipeline.zig");
    pub const IoUring = @import("net/io_uring.zig");
};

pub const config = @import("config.zig");

pub const services = struct {
    pub const Policy = @import("services/policy.zig");
};

test {
    // Run all module tests
    @import("std").testing.refAllDecls(@This());
    _ = wireguard.Tunnel;
    _ = wireguard.Device;
    _ = wireguard.Noise;
    _ = wireguard.Crypto;
    _ = wireguard.Ip;
    _ = wireguard.Config;
    _ = wireguard.Netlink;
    _ = wireguard.RtNetlink;
    _ = wireguard.NlSocket;
    _ = services.Policy;
}
