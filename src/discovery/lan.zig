//! LAN peer discovery via UDP multicast beacons.
//!
//! Uses a lightweight multicast beacon on 239.99.99.1:51820 (separate from
//! mDNS to avoid conflicts). Peers periodically announce themselves and
//! listen for other peers on the same LAN.
//!
//! Beacon wire format (41 bytes):
//!   [5B magic "MGLAN"]
//!   [2B app_id (e.g. 0x5043 = "PC" for Peer Circle)]
//!   [32B ed25519_pubkey]
//!   [2B gossip_port (little-endian)]
//!
//! The app_id field allows different meshguard applications to coexist
//! on the same multicast group without interfering with each other.

const std = @import("std");
const posix = std.posix;

/// Multicast group for meshguard LAN discovery.
pub const MULTICAST_GROUP = [4]u8{ 239, 99, 99, 1 };
pub const MULTICAST_PORT: u16 = 51820;
const BEACON_MAGIC = "MGLAN";
const BEACON_SIZE: usize = 5 + 2 + 32 + 2; // 41 bytes

/// Well-known app IDs.
pub const APP_ID_PEER_CIRCLE: u16 = 0x5043; // "PC" (Peer Circle)

/// Callback when a LAN peer is discovered.
pub const OnLanPeerFn = *const fn (ctx: *anyopaque, pubkey: [32]u8, addr: [4]u8, gossip_port: u16) void;

pub const LanDiscovery = struct {
    sock_fd: posix.fd_t,
    our_pubkey: [32]u8,
    our_gossip_port: u16,
    app_id: u16,
    on_peer: OnLanPeerFn,
    on_peer_ctx: *anyopaque,
    running: std.atomic.Value(bool),

    /// Initialize LAN discovery: create multicast socket, join group.
    pub fn init(our_pubkey: [32]u8, gossip_port: u16, app_id: u16, on_peer: OnLanPeerFn, ctx: *anyopaque) !LanDiscovery {
        const sock_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(sock_fd);

        // Allow address reuse
        const one: c_int = 1;
        try posix.setsockopt(sock_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        // Bind to multicast port
        const bind_addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, MULTICAST_PORT),
            .addr = 0, // INADDR_ANY
            .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        try posix.bind(sock_fd, @ptrCast(&bind_addr), @sizeOf(posix.sockaddr.in));

        // Join multicast group
        const mreq = extern struct {
            multiaddr: [4]u8,
            interface: [4]u8,
        }{
            .multiaddr = MULTICAST_GROUP,
            .interface = .{ 0, 0, 0, 0 }, // INADDR_ANY
        };
        // IP_ADD_MEMBERSHIP = 35 on Linux
        try posix.setsockopt(sock_fd, posix.IPPROTO.IP, 35, std.mem.asBytes(&mreq));

        // Set multicast TTL to 1 (LAN only)
        const ttl: c_int = 1;
        try posix.setsockopt(sock_fd, posix.IPPROTO.IP, 33, std.mem.asBytes(&ttl)); // IP_MULTICAST_TTL

        // Disable loopback (don't receive our own beacons)
        const loopback: c_int = 0;
        try posix.setsockopt(sock_fd, posix.IPPROTO.IP, 34, std.mem.asBytes(&loopback)); // IP_MULTICAST_LOOP

        return .{
            .sock_fd = sock_fd,
            .our_pubkey = our_pubkey,
            .our_gossip_port = gossip_port,
            .app_id = app_id,
            .on_peer = on_peer,
            .on_peer_ctx = ctx,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    /// Send a beacon announcing our presence.
    pub fn sendBeacon(self: *LanDiscovery) void {
        var buf: [BEACON_SIZE]u8 = undefined;
        @memcpy(buf[0..5], BEACON_MAGIC);
        std.mem.writeInt(u16, buf[5..7], self.app_id, .little);
        @memcpy(buf[7..39], &self.our_pubkey);
        std.mem.writeInt(u16, buf[39..41], self.our_gossip_port, .little);

        const dest = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, MULTICAST_PORT),
            .addr = std.mem.nativeToBig(u32, (@as(u32, MULTICAST_GROUP[0]) << 24) |
                (@as(u32, MULTICAST_GROUP[1]) << 16) |
                (@as(u32, MULTICAST_GROUP[2]) << 8) |
                @as(u32, MULTICAST_GROUP[3])),
            .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };

        _ = posix.sendto(self.sock_fd, &buf, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
    }

    /// Check for incoming beacons (non-blocking). Returns number of peers discovered.
    pub fn recvBeacons(self: *LanDiscovery) u32 {
        var count: u32 = 0;
        var buf: [128]u8 = undefined;
        var src_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        while (count < 16) { // Max 16 beacons per tick
            const n = posix.recvfrom(self.sock_fd, &buf, 0, @ptrCast(&src_addr), &addr_len) catch break;
            if (n != BEACON_SIZE) continue;
            if (!std.mem.eql(u8, buf[0..5], BEACON_MAGIC)) continue;

            // Check app_id — only accept beacons from the same app
            const recv_app_id = std.mem.readInt(u16, buf[5..7], .little);
            if (recv_app_id != self.app_id) continue;

            // Extract peer info
            var peer_pubkey: [32]u8 = undefined;
            @memcpy(&peer_pubkey, buf[7..39]);
            const gossip_port = std.mem.readInt(u16, buf[39..41], .little);

            // Skip our own beacons (in case loopback disable didn't work)
            if (std.mem.eql(u8, &peer_pubkey, &self.our_pubkey)) continue;

            // Extract sender's IP from sockaddr
            const raw_addr = std.mem.nativeToBig(u32, src_addr.addr);
            const peer_addr: [4]u8 = .{
                @truncate(raw_addr >> 24),
                @truncate(raw_addr >> 16),
                @truncate(raw_addr >> 8),
                @truncate(raw_addr),
            };

            std.debug.print("  🔍 LAN beacon from {d}.{d}.{d}.{d}:{d}\n", .{
                peer_addr[0], peer_addr[1], peer_addr[2], peer_addr[3], gossip_port,
            });

            self.on_peer(self.on_peer_ctx, peer_pubkey, peer_addr, gossip_port);
            count += 1;
        }
        return count;
    }

    pub fn deinit(self: *LanDiscovery) void {
        self.running.store(false, .release);
        posix.close(self.sock_fd);
    }
};
