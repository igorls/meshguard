//! Wire protocol message types for meshguard.
//!
//! All messages exchanged between meshguard nodes over the gossip port (51821).
//! Messages are serialized with a minimal binary codec (see codec.zig).

const std = @import("std");

/// Message type tag — first byte of every wire message.
pub const MessageType = enum(u8) {
    // ─── SWIM protocol ───
    ping = 0x01,
    ping_req = 0x02,
    ack = 0x03,

    // ─── Handshake ───
    handshake_init = 0x10,
    handshake_resp = 0x11,
    handshake_complete = 0x12,

    // ─── Gossip payloads (piggybacked on SWIM) ───
    member_join = 0x20,
    member_leave = 0x21,
    member_suspect = 0x22,
    member_alive = 0x23,
    member_dead = 0x24,

    // ─── NAT traversal ───
    relay_request = 0x30,
    relay_data = 0x31,
    endpoint_update = 0x32,
    holepunch_request = 0x33,
    holepunch_response = 0x34,

    _,
};

/// SWIM Ping message.
pub const Ping = struct {
    /// Sender's Ed25519 public key
    sender_pubkey: [32]u8,
    /// Monotonic sequence number
    seq: u64,
    /// Piggybacked gossip updates
    gossip: []const GossipEntry,
};

/// SWIM Ping-Req: ask another node to probe a target.
pub const PingReq = struct {
    sender_pubkey: [32]u8,
    target_pubkey: [32]u8,
    seq: u64,
};

/// SWIM Ack: response to Ping or Ping-Req.
pub const Ack = struct {
    sender_pubkey: [32]u8,
    seq: u64,
    gossip: []const GossipEntry,
};

/// Handshake initiation: sent when two nodes first discover each other.
pub const HandshakeInit = struct {
    sender_pubkey: [32]u8,
    nonce: [32]u8,
    signature: [64]u8, // sign(nonce, sender_privkey)
    wg_pubkey: [32]u8, // sender's WireGuard public key
    mesh_ip: [4]u8, // sender's deterministic mesh IP
    wg_port: u16, // sender's WireGuard listen port
    gossip_port: u16, // sender's gossip listen port
};

/// Handshake response: sent back if the initiator is authorized.
pub const HandshakeResp = struct {
    sender_pubkey: [32]u8,
    nonce: [32]u8, // responder's nonce
    init_nonce: [32]u8, // echo of initiator's nonce
    signature: [64]u8, // sign(init_nonce ++ nonce, responder_privkey)
    wg_pubkey: [32]u8,
    mesh_ip: [4]u8,
    wg_port: u16,
    gossip_port: u16,
};

/// A single gossip entry piggybacked on SWIM messages.
pub const GossipEntry = struct {
    /// The node this entry is about
    subject_pubkey: [32]u8,
    /// What happened to this node
    event: MemberEvent,
    /// Lamport timestamp for crdt-like conflict resolution
    lamport: u64,
    /// Network endpoint (if known)
    endpoint: ?Endpoint,
    /// WireGuard X25519 public key (if known, for join/alive events)
    wg_pubkey: ?[32]u8 = null,
    /// STUN-discovered public endpoint (if known)
    public_endpoint: ?Endpoint = null,
    /// NAT type of this node
    nat_type: NatType = .unknown,
};

/// Membership events propagated via gossip.
pub const MemberEvent = enum(u8) {
    join = 0,
    alive = 1,
    suspect = 2,
    dead = 3,
    leave = 4,
};

/// NAT type classification (shared with STUN client).
pub const NatType = enum(u8) {
    public = 0,
    cone = 1,
    symmetric = 2,
    unknown = 3,
};

/// Network endpoint (IP:port pair).
pub const Endpoint = struct {
    addr: [4]u8, // IPv4 — extend to support IPv6 later
    port: u16,

    pub fn format(self: Endpoint, buf: []u8) []const u8 {
        const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.port,
        }) catch return "?";
        return result;
    }
};

/// Relay request: ask a public-IP node to relay traffic.
pub const RelayRequest = struct {
    sender_pubkey: [32]u8,
    target_pubkey: [32]u8,
};

/// Endpoint update: broadcast when a node's external IP changes.
pub const EndpointUpdate = struct {
    sender_pubkey: [32]u8,
    new_endpoint: Endpoint,
    signature: [64]u8, // sign(endpoint, sender_privkey)
};

/// Holepunch request: sent through a rendezvous peer to coordinate UDP hole punching.
pub const HolepunchRequest = struct {
    sender_pubkey: [32]u8,
    target_pubkey: [32]u8,
    public_endpoint: Endpoint,
    token: [16]u8, // random nonce for verification
};

/// Holepunch response: sent back through the rendezvous peer.
pub const HolepunchResponse = struct {
    sender_pubkey: [32]u8,
    public_endpoint: Endpoint,
    token_echo: [16]u8, // echo of request's token
};

test "message type values" {
    try std.testing.expectEqual(@as(u8, 0x01), @intFromEnum(MessageType.ping));
    try std.testing.expectEqual(@as(u8, 0x10), @intFromEnum(MessageType.handshake_init));
    try std.testing.expectEqual(@as(u8, 0x30), @intFromEnum(MessageType.relay_request));
    try std.testing.expectEqual(@as(u8, 0x33), @intFromEnum(MessageType.holepunch_request));
    try std.testing.expectEqual(@as(u8, 0x34), @intFromEnum(MessageType.holepunch_response));
}
