//! SWIM protocol implementation for meshguard.
//!
//! Single-threaded, poll-based gossip loop:
//!   1. Pick random alive peer → send PING
//!   2. Process received messages (PING/ACK/PING-REQ)
//!   3. Check pending pings for timeouts → escalate to PING-REQ
//!   4. Expire suspected peers → mark DEAD
//!   5. Piggyback gossip entries on outgoing messages

const std = @import("std");
const builtin = @import("builtin");
const Membership = @import("membership.zig");
const messages = @import("../protocol/messages.zig");
const codec = @import("../protocol/codec.zig");
const keys = @import("../identity/keys.zig");
const Org = @import("../identity/org.zig");
const Udp = @import("../net/udp.zig");
const Holepuncher = @import("../nat/holepunch.zig").Holepuncher;
const log = std.log.scoped(.swim);

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowNs() i128 {
    return @intCast(std.Io.Timestamp.now(zio(), .awake).toNanoseconds());
}

pub const SwimConfig = struct {
    gossip_port: u16 = 51821,
    gossip_interval_ms: u32 = 5000, // 5s — reasonable for WAN
    ping_timeout_ms: u32 = 3000, // 3s — generous for WAN
    ping_req_count: u32 = 3,
    max_gossip_per_message: u32 = 8,
    max_gossip_broadcasts: u32 = 6, // how many times to broadcast each gossip entry
};

/// Callback interface for SWIM events (e.g. WireGuard peer management).
pub const EventHandler = struct {
    ctx: *anyopaque,
    onPeerJoin: *const fn (ctx: *anyopaque, peer: *const Membership.Peer) void,
    onPeerDead: *const fn (ctx: *anyopaque, pubkey: [32]u8) void,
    onPeerPunched: ?*const fn (ctx: *anyopaque, peer: *const Membership.Peer, endpoint: messages.Endpoint) void = null,
    onAppMessage: ?*const fn (ctx: *anyopaque, data: []const u8) void = null,
    onWgPacket: ?*const fn (ctx: *anyopaque, data: []const u8, addr: [4]u8, port: u16) void = null,
};

/// Gossip entry with broadcast remaining counter.
const GossipSlot = struct {
    entry: messages.GossipEntry,
    remaining: u32, // broadcasts remaining before expiry
};

/// Pending ping tracking.
const PendingPing = struct {
    target_pubkey: [32]u8,
    target_endpoint: messages.Endpoint,
    seq: u64,
    sent_at_ns: i128,
    escalated: bool, // whether we've already sent ping-req
};

/// Hard ceiling on SWIM control-plane send rate (packets/sec). Legitimate
/// gossip needs only a handful of pps even in a large mesh; this is generous
/// headroom while still bounding any flood to a level a router shrugs off.
const SEND_RATE_PPS: f64 = 500.0;
/// Token-bucket capacity (allowed short burst above the sustained rate).
const SEND_BURST: f64 = 100.0;
// Bounded quarantine for unproven gossip hints. A sustained fake-candidate flood
// can starve honest hints until SWIM re-gossips them, but the fixed cap is the
// security boundary that prevents one packet from buying unbounded probe work.
const MAX_CANDIDATE_PEERS: usize = 64;
const CANDIDATE_PROBE_INTERVAL_NS: i128 = 1_000_000_000;
const CANDIDATE_TTL_NS: i128 = 30_000_000_000;
const CANDIDATE_MAX_PROBES: u8 = 3;

const CandidatePeer = struct {
    pubkey: [32]u8,
    endpoint: messages.Endpoint,
    first_seen_ns: i128,
    last_probe_ns: i128 = 0,
    probe_count: u8 = 0,
};

/// SWIM protocol state machine with event loop.
pub const SwimProtocol = struct {
    config: SwimConfig,
    membership: *Membership.MembershipTable,
    seq: u64,
    our_pubkey: [32]u8,
    our_wg_pubkey: [32]u8,
    our_mesh_ip: [4]u8,
    our_mesh_ip6: [16]u8,
    our_wg_port: u16,
    socket: Udp.UdpSocket,
    handler: ?EventHandler,
    running: std.atomic.Value(bool),

    // NAT traversal state
    our_public_endpoint: ?messages.Endpoint = null,
    our_nat_type: messages.NatType = .unknown,
    stun_refresh_counter: u32 = 0,

    // Ping rate limiting
    last_ping_sent_ns: i128 = 0,

    // Pending pings awaiting ACK
    pending: [16]PendingPing = std.mem.zeroes([16]PendingPing),
    pending_count: usize = 0,

    // Gossip queue with broadcast counters
    gossip_queue: [32]GossipSlot = std.mem.zeroes([32]GossipSlot),
    gossip_count: usize = 0,

    // Unauthenticated gossip endpoint hints. These are never exposed as members,
    // never re-gossiped, and only exist to trigger bounded direct certificate probes.
    candidate_peers: [MAX_CANDIDATE_PEERS]CandidatePeer = std.mem.zeroes([MAX_CANDIDATE_PEERS]CandidatePeer),
    candidate_count: usize = 0,

    // Snapshot buffer for encoding (avoids use-after-free on gossip_queue drain)
    gossip_snap: [8]messages.GossipEntry = std.mem.zeroes([8]messages.GossipEntry),

    // Hole punching coordinator
    holepuncher: Holepuncher = .{},
    last_punch_check_ns: i128 = 0,
    last_gossip_ns: i128 = 0,

    // Trust: authorized peer pubkeys (Ed25519)
    authorized_keys: [64][32]u8 = std.mem.zeroes([64][32]u8),
    authorized_count: usize = 0,
    enforce_trust: bool = false,

    // Org trust: trusted org pubkeys
    trusted_orgs: [16][32]u8 = std.mem.zeroes([16][32]u8),
    trusted_org_count: usize = 0,

    // Org alias registry: org_pubkey → alias (in-memory, populated via gossip)
    alias_org_pubkeys: [16][32]u8 = std.mem.zeroes([16][32]u8),
    alias_names: [16][32]u8 = std.mem.zeroes([16][32]u8),
    alias_lamports: [16]u64 = std.mem.zeroes([16]u64),
    alias_count: usize = 0,

    // Revoked node pubkeys (propagated via gossip)
    revoked_nodes: [64][32]u8 = std.mem.zeroes([64][32]u8),
    revoked_count: usize = 0,

    // Vouched external nodes: org admin vouches for standalone nodes (propagated via gossip)
    vouched_org_keys: [64][32]u8 = std.mem.zeroes([64][32]u8),
    vouched_node_keys: [64][32]u8 = std.mem.zeroes([64][32]u8),
    vouched_count: usize = 0,

    // Node's own org certificate (if any, loaded at init)
    our_org_cert: ?[186]u8 = null,

    // Control-plane send rate limiting (token bucket). A hard ceiling on
    // SWIM/gossip packets/sec so a pathological inbound rate (e.g. a NAT
    // retransmit storm) can never be amplified into a network-melting flood.
    // Tunnel DATA does NOT pass through here — it uses the socket directly via
    // the FFI layer — so egress throughput is unaffected by this cap.
    send_tokens: f64 = SEND_BURST,
    last_token_refill_ns: i128 = 0,

    // Debug counters
    pkts_sent: u32 = 0,
    pkts_recv: u32 = 0,
    raw_recv: u32 = 0,
    tick_count: u32 = 0,
    acks_sent: u32 = 0,
    sends_dropped_ratelimit: u32 = 0,

    // Liveness tracking: timestamp of last received packet (epoch nanoseconds, i64)
    last_recv_ns: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    pub fn init(
        membership: *Membership.MembershipTable,
        socket: Udp.UdpSocket,
        swim_config: SwimConfig,
        our_pubkey: [32]u8,
        our_wg_pubkey: [32]u8,
        our_mesh_ip: [4]u8,
        our_wg_port: u16,
        handler: ?EventHandler,
    ) SwimProtocol {
        return .{
            .config = swim_config,
            .membership = membership,
            .seq = 0,
            .our_pubkey = our_pubkey,
            .our_wg_pubkey = our_wg_pubkey,
            .our_mesh_ip = our_mesh_ip,
            .our_mesh_ip6 = @import("../wireguard/ip.zig").deriveIpv6FromPubkeyBytes(our_pubkey),
            .our_wg_port = our_wg_port,
            .socket = socket,
            .handler = handler,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    /// Set the STUN-discovered public endpoint and NAT type.
    pub fn setPublicEndpoint(self: *SwimProtocol, endpoint: ?messages.Endpoint, nat_type: messages.NatType) void {
        self.our_public_endpoint = endpoint;
        self.our_nat_type = nat_type;
    }

    /// Add an authorized peer pubkey. Call before run().
    pub fn addAuthorizedKey(self: *SwimProtocol, pubkey: [32]u8) void {
        if (self.authorized_count < self.authorized_keys.len) {
            self.authorized_keys[self.authorized_count] = pubkey;
            self.authorized_count += 1;
        }
    }

    /// Enable trust enforcement (only authorized peers can join).
    pub fn enableTrust(self: *SwimProtocol) void {
        self.enforce_trust = true;
    }

    fn nodeIsRevoked(self: *const SwimProtocol, pubkey: [32]u8) bool {
        for (self.revoked_nodes[0..self.revoked_count]) |revoked| {
            if (std.mem.eql(u8, &revoked, &pubkey)) return true;
        }
        return false;
    }

    fn certExpiryValid(expires_at: i64) bool {
        if (expires_at == 0) return true;
        return @as(i64, @intCast(std.Io.Timestamp.now(zio(), .real).toSeconds())) < expires_at;
    }

    fn certAuthorizesPeer(self: *const SwimProtocol, pubkey: [32]u8, cert_wire: [messages.ORG_CERT_WIRE_SIZE]u8) bool {
        const cert = Org.NodeCertificate.deserialize(&cert_wire);
        if (!std.mem.eql(u8, &cert.node_pubkey, &pubkey)) return false;
        if (!Org.verifyCertificate(&cert)) return false;
        if (!cert.isValid()) return false;
        if (!self.isOrgAuthorizedPeer(cert.org_pubkey)) return false;
        if (self.nodeIsRevoked(pubkey)) return false;
        return true;
    }

    fn recordedCertAuthorizesPeer(self: *const SwimProtocol, pubkey: [32]u8) bool {
        const peer = self.membership.peers.get(pubkey) orelse return false;
        const org_pubkey = peer.org_pubkey orelse return false;
        const expires_at = peer.cert_expires_at orelse return false;
        if (!self.isOrgAuthorizedPeer(org_pubkey)) return false;
        if (!certExpiryValid(expires_at)) return false;
        if (self.nodeIsRevoked(pubkey)) return false;
        return true;
    }

    fn recordPeerCertificate(self: *SwimProtocol, pubkey: [32]u8, cert_wire: [messages.ORG_CERT_WIRE_SIZE]u8) void {
        if (!self.certAuthorizesPeer(pubkey, cert_wire)) return;
        const cert = Org.NodeCertificate.deserialize(&cert_wire);
        if (self.membership.peers.getPtr(pubkey)) |peer| {
            peer.org_pubkey = cert.org_pubkey;
            peer.org_node_name = cert.node_name;
            peer.cert_expires_at = cert.expires_at;
        }
    }

    /// Check if a pubkey is authorized.
    fn isAuthorizedPeer(self: *const SwimProtocol, pubkey: [32]u8, presented_cert: ?[messages.ORG_CERT_WIRE_SIZE]u8) bool {
        if (!self.enforce_trust) return true;
        // Always allow our own pubkey
        if (std.mem.eql(u8, &pubkey, &self.our_pubkey)) return true;
        // Allow zero pubkey (initial seed hello pings)
        if (std.mem.eql(u8, &pubkey, &([_]u8{0} ** 32))) return true;
        // Check authorized set (individual keys)
        for (self.authorized_keys[0..self.authorized_count]) |key| {
            if (std.mem.eql(u8, &key, &pubkey)) return true;
        }
        // Check if revoked
        for (self.revoked_nodes[0..self.revoked_count]) |revoked| {
            if (std.mem.eql(u8, &revoked, &pubkey)) return false;
        }
        // Check previously admitted org certificate
        if (self.recordedCertAuthorizesPeer(pubkey)) return true;
        // Check presented org certificate
        if (presented_cert) |cert_wire| {
            if (self.certAuthorizesPeer(pubkey, cert_wire)) return true;
        }
        // Check if vouched by a trusted org
        for (0..self.vouched_count) |i| {
            if (std.mem.eql(u8, &self.vouched_node_keys[i], &pubkey)) {
                // Verify the vouching org is trusted
                if (self.isOrgAuthorizedPeer(self.vouched_org_keys[i])) return true;
            }
        }
        return false;
    }

    /// Check if a peer is authorized via org cert (checking peer's org cert against trusted orgs).
    pub fn isOrgAuthorizedPeer(self: *const SwimProtocol, org_pubkey: [32]u8) bool {
        for (self.trusted_orgs[0..self.trusted_org_count]) |trusted| {
            if (std.mem.eql(u8, &trusted, &org_pubkey)) return true;
        }
        return false;
    }

    /// Add a trusted org pubkey.
    pub fn addTrustedOrg(self: *SwimProtocol, org_pubkey: [32]u8) void {
        if (self.trusted_org_count < self.trusted_orgs.len) {
            self.trusted_orgs[self.trusted_org_count] = org_pubkey;
            self.trusted_org_count += 1;
        }
    }

    /// Set this node's org certificate.
    pub fn setOrgCert(self: *SwimProtocol, cert_wire: [186]u8) void {
        self.our_org_cert = cert_wire;
    }

    /// Run the SWIM event loop (blocking). Call stop() to exit.
    pub fn run(self: *SwimProtocol) !void {
        while (self.running.load(.acquire)) {
            try self.tick();
        }
    }

    /// Stop the event loop.
    pub fn stop(self: *SwimProtocol) void {
        self.running.store(false, .release);
    }

    /// Broadcast a leave announcement to all alive peers.
    /// Called from signal handler before stop() — async-signal-safe.
    /// Best-effort: sends a PING with piggybacked leave gossip to every
    /// alive peer so they remove us immediately (no suspicion timeout).
    pub fn broadcastLeave(self: *SwimProtocol) void {
        self.membership.lamport += 1;

        const leave_gossip = [1]messages.GossipEntry{.{
            .subject_pubkey = self.our_pubkey,
            .event = .leave,
            .lamport = self.membership.lamport,
            .endpoint = null,
        }};

        const ping = messages.Ping{
            .sender_pubkey = self.our_pubkey,
            .seq = self.seq +% 1,
            .gossip = &leave_gossip,
            .org_cert = self.our_org_cert orelse std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8),
            .has_org_cert = self.our_org_cert != null,
        };

        var buf: [1500]u8 = undefined;
        const written = codec.encodePing(&buf, ping) catch return;

        // Send to every alive peer with a known endpoint
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (peer.state == .alive or peer.state == .suspected) {
                if (peer.gossip_endpoint) |ep| {
                    self.gossipSend(buf[0..written], ep);
                }
            }
        }
    }

    /// Single iteration of the SWIM protocol.
    pub fn tick(self: *SwimProtocol) !void {
        self.tick_count += 1;
        // 1. Process incoming messages (poll with gossip_interval timeout)
        const poll_ms: i32 = @min(@as(i32, @intCast(self.config.gossip_interval_ms)), 200);
        if (try self.socket.pollRead(poll_ms)) {
            // Drain all available messages
            while (true) {
                var recv_buf: [1500]u8 = undefined;
                const result = try self.socket.recvFrom(&recv_buf);
                if (result == null) break;
                const recv = result.?;
                self.raw_recv += 1;
                self.handleMessage(recv.data, recv.endpoint());
            }
        }

        // 2. Check pending pings for timeouts
        self.checkTimeouts();

        // 3. Expire suspected peers
        var expired_buf: [256][32]u8 = undefined;
        const expired_n = self.membership.expireSuspected(&expired_buf);
        for (expired_buf[0..expired_n]) |pubkey| {
            // Log the expiration
            std.debug.print("  peer expired (suspect timeout): {x:0>2}{x:0>2}...\n", .{ pubkey[0], pubkey[1] });

            // Notify handler (remove WG peer)
            if (self.handler) |h| {
                h.onPeerDead(h.ctx, pubkey);
            }
            self.enqueueGossip(.{
                .subject_pubkey = pubkey,
                .event = .dead,
                .lamport = self.membership.lamport,
                .endpoint = null,
            });
        }

        // 4. Pick a random alive peer and send PING (rate-limited)
        const now_ns = nowNs();
        const interval_ns: i128 = @as(i128, self.config.gossip_interval_ms) * 1_000_000;
        if (now_ns - self.last_ping_sent_ns >= interval_ns) {
            if (self.membership.randomAlivePeer()) |peer| {
                if (peer.gossip_endpoint) |ep| {
                    self.sendPing(ep, peer.pubkey);
                    self.last_ping_sent_ns = now_ns;
                }
            }
        }

        // 5. Probe at most one unauthenticated candidate endpoint.
        self.probeCandidatePeer(now_ns);

        // 6. Hole punch: send probes for active punches
        _ = self.holepuncher.sendProbes(&self.socket);
        self.holepuncher.expireTimeouts();

        // 7. Check for unreachable cone NAT peers (every 30s)
        const punch_check_interval: i128 = 30_000_000_000; // 30s
        if (now_ns - self.last_punch_check_ns >= punch_check_interval) {
            self.last_punch_check_ns = now_ns;
            self.checkUnreachablePeers();
        }
    }

    /// Send initial PINGs to seed peers.
    pub fn seedPeers(self: *SwimProtocol, seeds: []const messages.Endpoint) void {
        for (seeds) |seed| {
            // Send a ping to each seed — we don't know their pubkey yet,
            // so we use a zero pubkey as "hello" ping
            self.sendPing(seed, [_]u8{0} ** 32);
        }
    }

    /// Process timers and gossip without polling the socket.
    /// Use this when an external event loop handles socket I/O.
    pub fn tickTimersOnly(self: *SwimProtocol) void {
        // 1. Check pending pings for timeouts
        self.checkTimeouts();

        const now_ns = nowNs();

        // 2. Expire suspected peers
        var expired_buf: [256][32]u8 = undefined;
        const expired_n = self.membership.expireSuspected(&expired_buf);
        for (expired_buf[0..expired_n]) |pubkey| {
            std.debug.print("  peer expired (suspect timeout): {x:0>2}{x:0>2}...\n", .{ pubkey[0], pubkey[1] });
            if (self.handler) |h| {
                h.onPeerDead(h.ctx, pubkey);
            }
            self.enqueueGossip(.{
                .subject_pubkey = pubkey,
                .event = .dead,
                .lamport = self.membership.lamport,
                .endpoint = null,
            });
        }

        // 3. Pick a random alive peer and send PING (rate-limited)
        const interval_ns: i128 = @as(i128, self.config.gossip_interval_ms) * 1_000_000;
        if (now_ns - self.last_ping_sent_ns >= interval_ns) {
            if (self.membership.randomAlivePeer()) |peer| {
                if (peer.gossip_endpoint) |ep| {
                    self.sendPing(ep, peer.pubkey);
                    self.last_ping_sent_ns = now_ns;
                }
            }
        }

        // 4. Probe at most one unauthenticated candidate endpoint.
        self.probeCandidatePeer(now_ns);

        // 5. Hole punch: send probes for active punches
        _ = self.holepuncher.sendProbes(&self.socket);
        self.holepuncher.expireTimeouts();

        // 6. Check for unreachable cone NAT peers (every 30s)
        const punch_check_interval: i128 = 30_000_000_000;
        if (now_ns - self.last_punch_check_ns >= punch_check_interval) {
            self.last_punch_check_ns = now_ns;
            self.checkUnreachablePeers();
        }
    }

    /// Receive-only tick for suspended/background mode.
    /// Processes incoming packets (ACKs, messages, SOS, WireGuard handshakes)
    /// but does NOT send PINGs, beacons, or escalate suspicion. This keeps the
    /// node reachable while minimizing battery and network usage.
    pub fn tickReceiveOnly(self: *SwimProtocol) !void {
        self.tick_count += 1;

        // Poll socket for incoming packets (200ms timeout)
        const poll_ms: i32 = 200;
        if (try self.socket.pollRead(poll_ms)) {
            while (true) {
                var recv_buf: [1500]u8 = undefined;
                const result = try self.socket.recvFrom(&recv_buf);
                if (result == null) break;
                const recv = result.?;
                self.raw_recv += 1;
                self.handleMessage(recv.data, recv.endpoint());
            }
        }

        // Still clear timed-out pending pings (prevents accumulation)
        // but don't escalate to PING-REQ since we're in low-power mode.
        self.checkTimeouts();
    }

    /// Re-ping all alive peers to refresh state after resuming from suspend.
    /// Call this immediately after exiting suspended mode to catch up on
    /// peer liveness and exchange gossip.
    pub fn pingAllAlive(self: *SwimProtocol) void {
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (peer.state == .alive or peer.state == .suspected) {
                if (peer.gossip_endpoint) |ep| {
                    self.sendPing(ep, peer.pubkey);
                }
            }
        }
    }

    /// Feed a received packet to SWIM from an external event loop.
    pub fn feedPacket(self: *SwimProtocol, data: []const u8, sender_addr: [4]u8, sender_port: u16) void {
        self.handleMessage(data, messages.Endpoint.initV4(sender_addr, sender_port));
    }

    // ─── Message handling ───

    pub fn feedPacketEndpoint(self: *SwimProtocol, data: []const u8, sender_endpoint: messages.Endpoint) void {
        self.handleMessage(data, sender_endpoint);
    }

    fn handleMessage(self: *SwimProtocol, data: []const u8, sender_endpoint: messages.Endpoint) void {
        // Check for holepunch probes (raw UDP with MGHP magic, not SWIM-encoded)
        if (data.len >= 4 and Holepuncher.isProbe(data[0..4])) {
            self.handleHolepunchProbe(sender_endpoint);
            return;
        }

        // Check for app messages (type 0x50) — relay or deliver locally
        // Wire: [0x50][32B dest][32B sender][12B nonce][N ciphertext][16B tag]
        if (data.len > 0 and data[0] == 0x50) {
            self.handleAppMessage(data, sender_endpoint);
            return;
        }

        // Check for WireGuard packets (Type 1-4: LE32 header)
        // These are handled by the tunnel FFI layer via onWgPacket callback.
        if (data.len >= 4) {
            const msg_type = std.mem.readInt(u32, data[0..4], .little);
            if (msg_type >= 1 and msg_type <= 4) {
                if (self.handler) |h| {
                    if (h.onWgPacket) |cb| {
                        cb(h.ctx, data, sender_endpoint.addr, sender_endpoint.port);
                    }
                }
                return;
            }
        }

        const decoded = codec.decode(data) catch return;
        self.pkts_recv += 1;
        self.last_recv_ns.store(@intCast(nowNs()), .release);

        // Trust enforcement: check sender's pubkey against authorized set
        const sender_pubkey: [32]u8 = switch (decoded) {
            .ping => |p| p.sender_pubkey,
            .ack => |a| a.sender_pubkey,
            .ping_req => |r| r.sender_pubkey,
            .holepunch_request => |req| req.sender_pubkey,
            .holepunch_response => |resp| resp.sender_pubkey,
            .org_alias_announce => |ann| ann.org_pubkey,
            .org_cert_revoke => |rev| rev.org_pubkey,
            .org_trust_vouch => |v| v.org_pubkey,
        };
        const presented_cert: ?[messages.ORG_CERT_WIRE_SIZE]u8 = switch (decoded) {
            .ping => |p| if (p.has_org_cert) p.org_cert else null,
            .ack => |a| if (a.has_org_cert) a.org_cert else null,
            else => null,
        };
        const org_control_message = switch (decoded) {
            .org_alias_announce, .org_cert_revoke, .org_trust_vouch => true,
            else => false,
        };
        if (!org_control_message and !self.isAuthorizedPeer(sender_pubkey, presented_cert)) return;

        switch (decoded) {
            .ping => |p| self.handlePing(&p, sender_endpoint),
            .ack => |a| self.handleAck(&a, sender_endpoint),
            .ping_req => |r| self.handlePingReq(r, sender_endpoint),
            .holepunch_request => |req| self.handleHolepunchRequest(req, sender_endpoint),
            .holepunch_response => |resp| self.handleHolepunchResponse(resp),
            .org_alias_announce => |ann| self.handleOrgAlias(ann),
            .org_cert_revoke => |rev| self.handleOrgRevoke(rev),
            .org_trust_vouch => |v| self.handleOrgVouch(v),
        }
    }

    /// Handle an incoming 0x50 app message: deliver locally or relay.
    /// Wire: [0x50][32B dest_pubkey][32B sender_pubkey][12B nonce][N ciphertext][16B tag]
    fn handleAppMessage(self: *SwimProtocol, data: []const u8, sender_endpoint: messages.Endpoint) void {
        _ = sender_endpoint;
        // Min size: 1 + 32 + 32 + 12 + 0 + 16 = 93 (empty payload)
        if (data.len < 93) return;

        const dest_pubkey = data[1..33];

        // Is this message for us?
        if (std.mem.eql(u8, dest_pubkey, &self.our_pubkey)) {
            // Deliver locally via callback
            if (self.handler) |h| {
                if (h.onAppMessage) |cb| {
                    cb(h.ctx, data);
                }
            }
            return;
        }

        // Not for us — relay to destination peer (rate-limited; no per-message
        // logging in this hot path).
        var dest_key: [32]u8 = undefined;
        @memcpy(&dest_key, dest_pubkey);
        const peer = self.membership.peers.get(dest_key) orelse return;
        const ep = peer.gossip_endpoint orelse return;

        // Forward the entire message as-is (encrypted, we can't read it)
        self.gossipSend(data, ep);
    }

    /// Verify an org control message before acting on it.
    ///
    /// SECURITY (C2): org_cert_revoke/alias/vouch carry a 64-byte Ed25519
    /// signature that the receiver previously decoded but NEVER verified, so a
    /// single spoofed UDP datagram could revoke/evict any node or hijack an
    /// alias. We now require BOTH that the issuing org is trusted AND that the
    /// signature over the canonical payload verifies against the org pubkey.
    fn orgSignatureValid(self: *const SwimProtocol, org_pubkey: [32]u8, payload: []const u8, signature: [64]u8) bool {
        if (!self.isOrgAuthorizedPeer(org_pubkey)) return false;
        const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(org_pubkey) catch return false;
        return keys.verify(payload, signature, pk);
    }

    /// Handle an OrgAliasAnnounce: register or update org alias, with Lamport conflict resolution.
    fn handleOrgAlias(self: *SwimProtocol, ann: messages.OrgAliasAnnounce) void {
        const signed = codec.orgAliasSignedBytes(ann);
        if (!self.orgSignatureValid(ann.org_pubkey, &signed, ann.signature)) {
            log.warn("org alias rejected: invalid or untrusted org signature", .{});
            return;
        }
        const alias_name = std.mem.trimEnd(u8, &ann.alias, "\x00");

        // Check for existing alias with same name from a different org (conflict)
        for (0..self.alias_count) |i| {
            const existing_name = std.mem.trimEnd(u8, &self.alias_names[i], "\x00");
            if (std.mem.eql(u8, existing_name, alias_name)) {
                if (std.mem.eql(u8, &self.alias_org_pubkeys[i], &ann.org_pubkey)) {
                    // Same org, update lamport if newer
                    if (ann.lamport > self.alias_lamports[i]) {
                        self.alias_lamports[i] = ann.lamport;
                    }
                    return;
                }
                // Different org, same alias name — conflict!
                if (ann.lamport < self.alias_lamports[i]) {
                    // Incoming claim is earlier — overwrite
                    log.warn("org alias conflict: '{s}' reassigned (earlier Lamport timestamp wins)", .{alias_name});
                    self.alias_org_pubkeys[i] = ann.org_pubkey;
                    self.alias_lamports[i] = ann.lamport;
                } else {
                    log.warn("org alias conflict: '{s}' claim rejected (later Lamport timestamp)", .{alias_name});
                }
                return;
            }
        }

        // Check for existing entry for this org (different alias name)
        for (0..self.alias_count) |i| {
            if (std.mem.eql(u8, &self.alias_org_pubkeys[i], &ann.org_pubkey)) {
                // Update alias name for this org
                self.alias_names[i] = ann.alias;
                self.alias_lamports[i] = ann.lamport;
                return;
            }
        }

        // New entry
        if (self.alias_count < self.alias_org_pubkeys.len) {
            self.alias_org_pubkeys[self.alias_count] = ann.org_pubkey;
            self.alias_names[self.alias_count] = ann.alias;
            self.alias_lamports[self.alias_count] = ann.lamport;
            self.alias_count += 1;
            log.info("org alias registered: '{s}'", .{alias_name});
        }
    }

    /// Handle an OrgCertRevoke: add the revoked node pubkey to the set.
    fn handleOrgRevoke(self: *SwimProtocol, rev: messages.OrgCertRevoke) void {
        const signed = codec.orgRevokeSignedBytes(rev);
        if (!self.orgSignatureValid(rev.org_pubkey, &signed, rev.signature)) {
            log.warn("org revoke rejected: invalid or untrusted org signature", .{});
            return;
        }
        // Check if already revoked
        for (self.revoked_nodes[0..self.revoked_count]) |revoked| {
            if (std.mem.eql(u8, &revoked, &rev.node_pubkey)) return;
        }

        // Add to revocation set
        if (self.revoked_count < self.revoked_nodes.len) {
            self.revoked_nodes[self.revoked_count] = rev.node_pubkey;
            self.revoked_count += 1;
            log.warn("node revoked by org (reason={d})", .{rev.reason});

            // If the revoked node is currently a peer, mark as dead
            if (self.membership.peers.getPtr(rev.node_pubkey)) |peer| {
                if (peer.state == .alive or peer.state == .suspected) {
                    self.membership.markDead(rev.node_pubkey);
                    if (self.handler) |h| {
                        h.onPeerDead(h.ctx, rev.node_pubkey);
                    }
                }
            }
        }
    }

    /// Handle an OrgTrustVouch: org admin vouches for an external standalone node.
    /// All nodes trusting this org will auto-accept the vouched node.
    fn handleOrgVouch(self: *SwimProtocol, vouch: messages.OrgTrustVouch) void {
        // Only process vouches from trusted orgs with a valid signature.
        const signed = codec.orgVouchSignedBytes(vouch);
        if (!self.orgSignatureValid(vouch.org_pubkey, &signed, vouch.signature)) {
            log.warn("org vouch rejected: invalid or untrusted org signature", .{});
            return;
        }

        // Check if already vouched (same org + same node)
        for (0..self.vouched_count) |i| {
            if (std.mem.eql(u8, &self.vouched_node_keys[i], &vouch.vouched_pubkey) and
                std.mem.eql(u8, &self.vouched_org_keys[i], &vouch.org_pubkey))
            {
                return; // Already registered
            }
        }

        // Don't vouch for revoked nodes
        for (self.revoked_nodes[0..self.revoked_count]) |revoked| {
            if (std.mem.eql(u8, &revoked, &vouch.vouched_pubkey)) {
                log.warn("org vouch rejected: node is revoked", .{});
                return;
            }
        }

        // Register the vouch
        if (self.vouched_count < self.vouched_org_keys.len) {
            self.vouched_org_keys[self.vouched_count] = vouch.org_pubkey;
            self.vouched_node_keys[self.vouched_count] = vouch.vouched_pubkey;
            self.vouched_count += 1;
            log.info("org vouched for external node", .{});
        }
    }

    fn handlePing(self: *SwimProtocol, ping: *const codec.DecodedPing, sender_endpoint: messages.Endpoint) void {
        // Register sender FIRST so gossip callbacks see the real network address
        if (!std.mem.eql(u8, &ping.sender_pubkey, &([_]u8{0} ** 32))) {
            self.registerOrUpdatePeerEndpoint(ping.sender_pubkey, sender_endpoint);
            if (ping.has_org_cert) {
                self.recordPeerCertificate(ping.sender_pubkey, ping.org_cert);
            }
            self.removeCandidatePeer(ping.sender_pubkey);
        }

        // Process piggybacked gossip (onPeerJoin may fire here)
        for (ping.gossip()) |entry| {
            self.applyGossip(entry);
        }

        // Send ACK back
        const gossip = self.collectGossip();
        const ack = messages.Ack{
            .sender_pubkey = self.our_pubkey,
            .seq = ping.seq,
            .gossip = gossip,
            .org_cert = self.our_org_cert orelse std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8),
            .has_org_cert = self.our_org_cert != null,
        };

        var buf: [1500]u8 = undefined;
        const written = codec.encodeAck(&buf, ack) catch return;
        // Rate-limited send, no per-packet logging: an unconditional
        // std.debug.print here (one stderr syscall per inbound PING) was the
        // CPU sink that, under a NAT retransmit storm, pegged a core and helped
        // melt the LAN. Count instead.
        self.gossipSend(buf[0..written], sender_endpoint);
        self.acks_sent +%= 1;
    }

    fn handleAck(self: *SwimProtocol, ack: *const codec.DecodedAck, sender_endpoint: messages.Endpoint) void {
        // Register sender FIRST so gossip callbacks see the real network address
        if (!std.mem.eql(u8, &ack.sender_pubkey, &([_]u8{0} ** 32))) {
            self.registerOrUpdatePeerEndpoint(ack.sender_pubkey, sender_endpoint);
            if (ack.has_org_cert) {
                self.recordPeerCertificate(ack.sender_pubkey, ack.org_cert);
            }
            self.removeCandidatePeer(ack.sender_pubkey);
        }

        // Process piggybacked gossip (onPeerJoin may fire here)
        for (ack.gossip()) |entry| {
            self.applyGossip(entry);
        }

        // Clear pending ping
        self.clearPending(ack.seq);
    }

    fn handlePingReq(self: *SwimProtocol, req: messages.PingReq, sender_endpoint: messages.Endpoint) void {
        _ = sender_endpoint;

        // Forward ping to the target
        if (self.membership.peers.get(req.target_pubkey)) |target| {
            if (target.gossip_endpoint) |ep| {
                self.sendPing(ep, req.target_pubkey);
            }
        }
    }

    // ─── Hole Punching ───

    fn handleHolepunchRequest(self: *SwimProtocol, req: messages.HolepunchRequest, sender_endpoint: messages.Endpoint) void {
        // Are we the target?
        if (std.mem.eql(u8, &req.target_pubkey, &self.our_pubkey)) {
            // We're the target — respond with our public endpoint
            if (self.our_public_endpoint) |our_ep| {
                const resp = messages.HolepunchResponse{
                    .sender_pubkey = self.our_pubkey,
                    .public_endpoint = our_ep,
                    .token_echo = req.token,
                };
                var buf: [128]u8 = undefined;
                const written = codec.encodeHolepunchResponse(&buf, resp) catch return;
                // Send response back through the rendezvous (sender)
                self.gossipSend(buf[0..written], sender_endpoint);

                // Also start probing the initiator's endpoint
                _ = self.holepuncher.initiate(self.our_pubkey, req.sender_pubkey, our_ep);
                if (self.holepuncher.handleResponse(messages.HolepunchResponse{
                    .sender_pubkey = req.sender_pubkey,
                    .public_endpoint = req.public_endpoint,
                    .token_echo = req.token,
                })) |_| {
                    // Probing will happen in tick()
                }
            }
        } else {
            // We're the rendezvous — forward to the target
            if (self.membership.peers.get(req.target_pubkey)) |target| {
                if (target.gossip_endpoint) |ep| {
                    var buf: [128]u8 = undefined;
                    const written = codec.encodeHolepunchRequest(&buf, req) catch return;
                    self.gossipSend(buf[0..written], ep);
                }
            }
        }
    }

    fn handleHolepunchResponse(self: *SwimProtocol, resp: messages.HolepunchResponse) void {
        // Store the target's endpoint and start probing
        if (self.holepuncher.handleResponse(resp)) |_| {
            // Probing will be done in tick() via sendProbes()
            std.debug.print("  [punch] got response from {x:0>2}{x:0>2}..., starting probes\n", .{ resp.sender_pubkey[0], resp.sender_pubkey[1] });
        }
    }

    fn handleHolepunchProbe(self: *SwimProtocol, sender_endpoint: messages.Endpoint) void {
        // A probe arrived — the hole is punched!
        // Find which peer this corresponds to by checking active punches
        // For now, check all peers with matching public endpoints
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (peer.public_endpoint) |pub_ep| {
                if (pub_ep.eql(sender_endpoint)) {
                    // Found the peer — notify handler to configure WG endpoint
                    var ep_buf: [64]u8 = undefined;
                    std.debug.print("  [punch] hole punched with {x:0>2}{x:0>2}... at {s}\n", .{
                        peer.pubkey[0], peer.pubkey[1], sender_endpoint.format(&ep_buf),
                    });
                    if (self.handler) |h| {
                        if (h.onPeerPunched) |callback| {
                            callback(h.ctx, peer, sender_endpoint);
                        }
                    }
                    return;
                }
            }
        }
    }

    fn checkUnreachablePeers(self: *SwimProtocol) void {
        // Look for alive peers that are NATted and we haven't punched yet
        if (self.our_public_endpoint == null) return; // We need our own endpoint
        if (self.our_nat_type == .unknown) return;

        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;

            // Only try punch for alive, NATted peers that we can't directly reach
            if (peer.state != .alive) continue;
            if (peer.nat_type == .public) continue; // Can reach directly
            if (peer.nat_type == .unknown) continue; // Don't know yet
            if (peer.handshake_complete) continue; // Already connected

            // Don't punch symmetric NAT (will fail)
            if (peer.nat_type == .symmetric and self.our_nat_type == .symmetric) continue;

            // Find a rendezvous peer (public, with gossip endpoint)
            var rendezvous_ep: ?messages.Endpoint = null;
            var inner_iter = self.membership.peers.iterator();
            while (inner_iter.next()) |inner_entry| {
                const r = inner_entry.value_ptr;
                if (r.nat_type == .public and r.state == .alive) {
                    if (r.gossip_endpoint) |ep| {
                        rendezvous_ep = ep;
                        break;
                    }
                }
            }

            if (rendezvous_ep) |rvz_ep| {
                // Initiate hole punch
                if (self.holepuncher.initiate(self.our_pubkey, peer.pubkey, self.our_public_endpoint.?)) |req| {
                    std.debug.print("  [punch] initiating punch to {x:0>2}{x:0>2}... via rendezvous\n", .{ peer.pubkey[0], peer.pubkey[1] });
                    var buf: [128]u8 = undefined;
                    const written = codec.encodeHolepunchRequest(&buf, req) catch continue;
                    self.gossipSend(buf[0..written], rvz_ep);
                }
            }
        }
    }

    // ─── Peer management ───

    pub fn registerOrUpdatePeer(self: *SwimProtocol, pubkey: [32]u8, addr: [4]u8, port: u16) void {
        self.registerOrUpdatePeerEndpoint(pubkey, messages.Endpoint.initV4(addr, port));
    }

    pub fn registerOrUpdatePeerEndpoint(self: *SwimProtocol, pubkey: [32]u8, endpoint: messages.Endpoint) void {
        // Skip self
        if (std.mem.eql(u8, &pubkey, &self.our_pubkey)) return;
        // Skip zero pubkey (used for initial seed pings)
        if (std.mem.eql(u8, &pubkey, &([_]u8{0} ** 32))) return;

        const existing = self.membership.peers.get(pubkey);

        if (existing) |_| {
            // Already known — mark alive
            self.membership.markAlive(pubkey, null);
        } else {
            // New peer — add to membership table
            self.membership.lamport += 1;

            // For now, derive mesh IP from pubkey (same as our derivation)
            const ip_mod = @import("../wireguard/ip.zig");
            const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(pubkey) catch return;
            const mesh_ip = ip_mod.deriveFromPubkey(pk);
            const mesh_ip6 = ip_mod.deriveIpv6FromPubkey(pk);

            self.membership.upsert(.{
                .pubkey = pubkey,
                .name = "",
                .state = .alive,
                .gossip_endpoint = endpoint,
                .wg_pubkey = null, // Will be set via gossip wg_pubkey field
                .mesh_ip = mesh_ip,
                .mesh_ip6 = mesh_ip6,
                .wg_port = 51830,
                .lamport = self.membership.lamport,
                .last_seen_ns = nowNs(),
                .suspected_at_ns = null,
                .last_rtt_ns = null,
                .handshake_complete = false,
            }) catch return;

            // Don't fire onPeerJoin yet — wait for wg_pubkey via gossip
            // The callback will fire from applyGossip when wg_pubkey is received

            // Enqueue join gossip with our WG pubkey + public endpoint
            self.enqueueGossip(.{
                .subject_pubkey = self.our_pubkey,
                .event = .alive,
                .lamport = self.membership.lamport,
                .endpoint = self.our_public_endpoint orelse messages.Endpoint.initV6(self.our_mesh_ip6, self.config.gossip_port),
                .wg_pubkey = self.our_wg_pubkey,
                .public_endpoint = self.our_public_endpoint,
                .nat_type = self.our_nat_type,
            });

            // Also enqueue gossip about the new peer (include wg/nat info if already known)
            const peer_info = self.membership.peers.get(pubkey);
            self.enqueueGossip(.{
                .subject_pubkey = pubkey,
                .event = .join,
                .lamport = self.membership.lamport,
                .endpoint = endpoint,
                .wg_pubkey = if (peer_info) |p| p.wg_pubkey else null,
                .public_endpoint = if (peer_info) |p| p.public_endpoint else null,
                .nat_type = if (peer_info) |p| p.nat_type else .unknown,
            });
        }
    }

    // ─── PING/timeout management ───

    /// Rate-limited control-plane send (token bucket). ALL SWIM gossip/ping/
    /// ack/ping-req/holepunch/relay traffic goes through here so it can never
    /// be amplified into a flood. Over-budget packets are dropped (counted),
    /// which is correct for an unreliable gossip protocol. Tunnel DATA does not
    /// use this path, so egress throughput is unaffected.
    fn gossipSend(self: *SwimProtocol, data: []const u8, endpoint: messages.Endpoint) void {
        const now = nowNs();
        if (self.last_token_refill_ns == 0) self.last_token_refill_ns = now;
        const elapsed_s: f64 = @as(f64, @floatFromInt(now - self.last_token_refill_ns)) / 1_000_000_000.0;
        self.last_token_refill_ns = now;
        self.send_tokens = @min(SEND_BURST, self.send_tokens + elapsed_s * SEND_RATE_PPS);
        if (self.send_tokens < 1.0) {
            self.sends_dropped_ratelimit +%= 1;
            return; // over budget — drop to protect the network
        }
        self.send_tokens -= 1.0;
        _ = self.socket.sendToEndpoint(data, endpoint) catch return;
        self.pkts_sent +%= 1;
    }

    fn sendPing(self: *SwimProtocol, endpoint: messages.Endpoint, target_pubkey: [32]u8) void {
        self.sendPingWithGossip(endpoint, target_pubkey, true);
    }

    fn sendCandidatePing(self: *SwimProtocol, endpoint: messages.Endpoint, target_pubkey: [32]u8) void {
        self.sendPingWithGossip(endpoint, target_pubkey, false);
    }

    fn sendPingWithGossip(self: *SwimProtocol, endpoint: messages.Endpoint, target_pubkey: [32]u8, include_gossip: bool) void {
        self.seq += 1;
        const gossip: []const messages.GossipEntry = if (include_gossip) self.collectGossip() else &.{};

        const ping = messages.Ping{
            .sender_pubkey = self.our_pubkey,
            .seq = self.seq,
            .gossip = gossip,
            .org_cert = self.our_org_cert orelse std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8),
            .has_org_cert = self.our_org_cert != null,
        };

        var buf: [1500]u8 = undefined;
        const written = codec.encodePing(&buf, ping) catch return;
        self.gossipSend(buf[0..written], endpoint);

        // Track pending
        if (self.pending_count < self.pending.len) {
            self.pending[self.pending_count] = .{
                .target_pubkey = target_pubkey,
                .target_endpoint = endpoint,
                .seq = self.seq,
                .sent_at_ns = nowNs(),
                .escalated = false,
            };
            self.pending_count += 1;
        }
    }

    fn clearPending(self: *SwimProtocol, seq: u64) void {
        var i: usize = 0;
        while (i < self.pending_count) {
            if (self.pending[i].seq == seq) {
                // Remove by swapping with last
                self.pending[i] = self.pending[self.pending_count - 1];
                self.pending_count -= 1;
            } else {
                i += 1;
            }
        }
    }

    fn checkTimeouts(self: *SwimProtocol) void {
        const now = nowNs();
        const timeout_ns: i128 = @as(i128, self.config.ping_timeout_ms) * 1_000_000;

        var i: usize = 0;
        while (i < self.pending_count) {
            const pending = &self.pending[i];
            if (now - pending.sent_at_ns > timeout_ns) {
                if (!pending.escalated) {
                    // Escalate: mark suspected + send PING-REQ
                    pending.escalated = true;
                    self.membership.suspect(pending.target_pubkey);

                    // Send PING-REQ to random peers
                    self.sendPingReqs(pending.target_pubkey, pending.seq);

                    // Extend timeout for indirect phase
                    pending.sent_at_ns = now;
                    i += 1;
                } else {
                    // Indirect also timed out — remove pending
                    self.pending[i] = self.pending[self.pending_count - 1];
                    self.pending_count -= 1;
                }
            } else {
                i += 1;
            }
        }
    }

    fn sendPingReqs(self: *SwimProtocol, target_pubkey: [32]u8, seq: u64) void {
        var sent: u32 = 0;
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            if (sent >= self.config.ping_req_count) break;
            if (std.mem.eql(u8, &entry.key_ptr.*, &target_pubkey)) continue;
            if (entry.value_ptr.state != .alive) continue;
            if (entry.value_ptr.gossip_endpoint == null) continue;

            const ep = entry.value_ptr.gossip_endpoint.?;
            const req = messages.PingReq{
                .sender_pubkey = self.our_pubkey,
                .target_pubkey = target_pubkey,
                .seq = seq,
            };

            var buf: [128]u8 = undefined;
            const written = codec.encodePingReq(&buf, req) catch continue;
            self.gossipSend(buf[0..written], ep);
            sent += 1;
        }
    }

    fn hasPendingPing(self: *const SwimProtocol, pubkey: [32]u8) bool {
        for (self.pending[0..self.pending_count]) |pending| {
            if (std.mem.eql(u8, &pending.target_pubkey, &pubkey)) return true;
        }
        return false;
    }

    fn removeCandidateAt(self: *SwimProtocol, index: usize) void {
        self.candidate_peers[index] = self.candidate_peers[self.candidate_count - 1];
        self.candidate_count -= 1;
    }

    fn removeCandidatePeer(self: *SwimProtocol, pubkey: [32]u8) void {
        var i: usize = 0;
        while (i < self.candidate_count) {
            if (std.mem.eql(u8, &self.candidate_peers[i].pubkey, &pubkey)) {
                self.removeCandidateAt(i);
            } else {
                i += 1;
            }
        }
    }

    fn learnCandidatePeer(self: *SwimProtocol, pubkey: [32]u8, endpoint: messages.Endpoint) void {
        if (self.membership.peers.getPtr(pubkey) != null) return;
        if (self.nodeIsRevoked(pubkey)) return;

        const now = nowNs();
        for (self.candidate_peers[0..self.candidate_count]) |*candidate| {
            if (std.mem.eql(u8, &candidate.pubkey, &pubkey)) {
                if (!messages.Endpoint.eql(candidate.endpoint, endpoint)) {
                    candidate.endpoint = endpoint;
                    candidate.last_probe_ns = 0;
                    candidate.probe_count = 0;
                }
                return;
            }
        }

        if (self.candidate_count < self.candidate_peers.len) {
            self.candidate_peers[self.candidate_count] = .{
                .pubkey = pubkey,
                .endpoint = endpoint,
                .first_seen_ns = now,
            };
            self.candidate_count += 1;
            return;
        }

        var oldest: usize = 0;
        for (self.candidate_peers[1..], 1..) |candidate, i| {
            if (candidate.first_seen_ns < self.candidate_peers[oldest].first_seen_ns) {
                oldest = i;
            }
        }
        self.candidate_peers[oldest] = .{
            .pubkey = pubkey,
            .endpoint = endpoint,
            .first_seen_ns = now,
        };
    }

    fn expireCandidatePeers(self: *SwimProtocol, now: i128) void {
        var i: usize = 0;
        while (i < self.candidate_count) {
            const candidate = self.candidate_peers[i];
            if (now - candidate.first_seen_ns > CANDIDATE_TTL_NS or candidate.probe_count >= CANDIDATE_MAX_PROBES) {
                self.removeCandidateAt(i);
            } else {
                i += 1;
            }
        }
    }

    fn probeCandidatePeer(self: *SwimProtocol, now: i128) void {
        self.expireCandidatePeers(now);
        if (self.pending_count >= self.pending.len) return;

        var i: usize = 0;
        while (i < self.candidate_count) : (i += 1) {
            const candidate = &self.candidate_peers[i];
            if (self.hasPendingPing(candidate.pubkey)) continue;
            if (candidate.last_probe_ns != 0 and now - candidate.last_probe_ns < CANDIDATE_PROBE_INTERVAL_NS) continue;

            self.sendCandidatePing(candidate.endpoint, candidate.pubkey);
            candidate.last_probe_ns = now;
            candidate.probe_count += 1;
            return;
        }
    }

    // ─── Gossip management ───

    fn collectGossip(self: *SwimProtocol) []const messages.GossipEntry {
        if (self.gossip_count == 0) return &.{};
        const count = @min(self.gossip_count, self.config.max_gossip_per_message);

        // Copy entries into snapshot buffer
        for (0..count) |i| {
            self.gossip_snap[i] = self.gossip_queue[i].entry;
        }

        // Decrement broadcast counters and remove expired entries
        var write: usize = 0;
        for (0..self.gossip_count) |read| {
            if (read < count) {
                // This entry was just sent — decrement
                self.gossip_queue[read].remaining -= 1;
            }
            if (self.gossip_queue[read].remaining > 0) {
                if (write != read) {
                    self.gossip_queue[write] = self.gossip_queue[read];
                }
                write += 1;
            }
        }
        self.gossip_count = write;

        return self.gossip_snap[0..count];
    }

    fn enqueueGossip(self: *SwimProtocol, entry: messages.GossipEntry) void {
        if (self.gossip_count < self.gossip_queue.len) {
            self.gossip_queue[self.gossip_count] = .{
                .entry = entry,
                .remaining = self.config.max_gossip_broadcasts,
            };
            self.gossip_count += 1;
        }
    }

    /// React to an unauthenticated gossip claim that a third party is failing.
    /// Marks the subject suspected locally and actively probes it, so OUR failure
    /// detector — not a remote attacker — decides whether to evict. Only peers we
    /// currently consider alive are probed, which bounds any reflected traffic to
    /// endpoints already in our (capped) membership table.
    fn suspectAndProbe(self: *SwimProtocol, subject: [32]u8) void {
        const ep = blk: {
            const peer = self.membership.peers.getPtr(subject) orelse return;
            if (peer.state != .alive) return; // already suspected/dead, or unknown
            break :blk peer.gossip_endpoint;
        };
        self.membership.suspect(subject);
        if (ep) |e| self.sendPing(e, subject);
    }

    fn applyGossip(self: *SwimProtocol, entry: messages.GossipEntry) void {
        // Self-suspicion refutation: if someone suspects/kills us, broadcast alive
        if (std.mem.eql(u8, &entry.subject_pubkey, &self.our_pubkey)) {
            if (entry.event == .suspect or entry.event == .dead) {
                // Refute by broadcasting alive with higher Lamport clock
                self.membership.lamport = @max(self.membership.lamport, entry.lamport) + 1;
                self.enqueueGossip(.{
                    .subject_pubkey = self.our_pubkey,
                    .event = .alive,
                    .lamport = self.membership.lamport,
                    .endpoint = self.our_public_endpoint,
                });
            }
            return;
        }
        // Skip zero-pubkey entries
        if (std.mem.eql(u8, &entry.subject_pubkey, &([_]u8{0} ** 32))) return;

        switch (entry.event) {
            .join, .alive => {
                if (!self.isAuthorizedPeer(entry.subject_pubkey, null)) {
                    if (entry.endpoint) |ep| {
                        self.learnCandidatePeer(entry.subject_pubkey, ep);
                    }
                    return;
                }

                // The gossip endpoint is only used to LEARN about brand-new peers.
                // For peers we already track, liveness is decided by our own
                // failure detector (direct ping/ack → markAlive), never by
                // unauthenticated gossip.
                if (entry.endpoint) |ep| {
                    if (self.membership.peers.getPtr(entry.subject_pubkey) == null) {
                        self.registerOrUpdatePeerEndpoint(entry.subject_pubkey, ep);
                    }
                }

                // SECURITY (M6): do NOT let gossip clear local suspicion or
                // resurrect a peer our detector has marked down. A replayed/forged
                // `alive` used to reset suspected_at_ns, letting an attacker
                // indefinitely postpone failure detection (or revive a dead peer).
                // Only direct observation clears suspicion. We still absorb the
                // additive NAT/WG discovery metadata below.
                if (self.membership.peers.getPtr(entry.subject_pubkey)) |peer| {
                    // Update public endpoint if present
                    if (entry.public_endpoint) |pub_ep| {
                        peer.public_endpoint = pub_ep;
                    }
                    // Update NAT type
                    if (entry.nat_type != .unknown) {
                        peer.nat_type = entry.nat_type;
                        peer.is_relay_capable = (entry.nat_type == .public);
                    }

                    // Update WG pubkey if present in gossip
                    if (entry.wg_pubkey) |wg_key| {
                        if (peer.wg_pubkey == null) {
                            peer.wg_pubkey = wg_key;
                            // Fire onPeerJoin now that we have the WG key
                            if (self.handler) |h| {
                                h.onPeerJoin(h.ctx, peer);
                            }
                        }
                    }
                }
            },
            // SECURITY (H2): gossip entries are unauthenticated and the sender gate
            // is open by default, so a single packet could previously markDead any
            // third party and tear down its WireGuard tunnel. We now only DOWNGRADE
            // the claim to local suspicion and let our OWN failure detector confirm
            // it before any eviction. A live peer answers our probe and stays alive;
            // a genuinely dead/departed peer fails our probes and is reaped by
            // expireSuspected.
            .suspect, .dead, .leave => {
                self.suspectAndProbe(entry.subject_pubkey);
            },
        }
    }
};

// ─── Tests ───

test "swim creates sequential pings" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();

    // Bind to port 0 for an ephemeral port — works without root
    var socket = Udp.UdpSocket.bind(0) catch |err| {
        std.debug.print("Skipping test: could not bind UDP socket: {}\n", .{err});
        return;
    };
    defer socket.close();

    var swim = SwimProtocol.init(
        &membership,
        socket,
        .{}, // SwimConfig
        [_]u8{1} ** 32, // our_pubkey
        [_]u8{2} ** 32, // our_wg_pubkey
        .{ 127, 0, 0, 1 }, // our_mesh_ip
        51821, // our_wg_port
        null, // handler
    );

    const target_pubkey = [_]u8{3} ** 32;
    const target = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 12345);

    // Send first ping
    swim.sendPing(target, target_pubkey);
    try std.testing.expectEqual(@as(u64, 1), swim.seq);
    try std.testing.expectEqual(@as(usize, 1), swim.pending_count);
    try std.testing.expectEqual(target_pubkey, swim.pending[0].target_pubkey);
    try std.testing.expectEqual(@as(u64, 1), swim.pending[0].seq);

    // Send second ping
    swim.sendPing(messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 12346), target_pubkey);
    try std.testing.expectEqual(@as(u64, 2), swim.seq);
    try std.testing.expectEqual(@as(usize, 2), swim.pending_count);
    try std.testing.expectEqual(@as(u64, 2), swim.pending[1].seq);
}

fn aliveTestPeer(pk: [32]u8) Membership.Peer {
    return .{
        .pubkey = pk,
        .name = "",
        .state = .alive,
        .gossip_endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 40000),
        .wg_pubkey = null,
        .mesh_ip = .{ 10, 99, 0, 1 },
        .wg_port = 51830,
        .lamport = 1,
        .last_seen_ns = 0,
        .suspected_at_ns = null,
        .last_rtt_ns = null,
        .handshake_complete = false,
    };
}

const JoinCounter = struct {
    count: usize = 0,
    last_pubkey: ?[32]u8 = null,
};

fn countPeerJoin(ctx: *anyopaque, peer: *const Membership.Peer) void {
    const counter: *JoinCounter = @ptrCast(@alignCast(ctx));
    counter.count += 1;
    counter.last_pubkey = peer.pubkey;
}

fn ignorePeerDead(_: *anyopaque, _: [32]u8) void {}

fn inertTestSocket() Udp.UdpSocket {
    const fd: std.posix.socket_t = if (builtin.os.tag == .windows)
        @as(std.posix.socket_t, @ptrFromInt(std.math.maxInt(usize)))
    else
        @as(std.posix.socket_t, -1);
    return .{ .fd = fd, .port = 0 };
}

fn issueCertWire(org_kp: Org.OrgKeyPair, node_pubkey: [32]u8, name: []const u8) ![messages.ORG_CERT_WIRE_SIZE]u8 {
    var cert = try Org.issueCertificate(org_kp, node_pubkey, name, 0);
    var cert_wire: [messages.ORG_CERT_WIRE_SIZE]u8 = undefined;
    cert.serialize(&cert_wire);
    return cert_wire;
}

test "gossiped join cannot admit an unauthorized subject with wg key" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    const socket = inertTestSocket();

    var joins = JoinCounter{};
    const handler = EventHandler{
        .ctx = &joins,
        .onPeerJoin = countPeerJoin,
        .onPeerDead = ignorePeerDead,
    };
    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, handler);
    swim.enableTrust();
    swim.addTrustedOrg([_]u8{0xA0} ** 32);

    const fake_kp = keys.generate();
    const fake_peer = fake_kp.public_key.toBytes();
    swim.applyGossip(.{
        .subject_pubkey = fake_peer,
        .event = .join,
        .lamport = 10,
        .endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 40000),
        .wg_pubkey = [_]u8{0x66} ** 32,
    });

    try std.testing.expect(membership.peers.get(fake_peer) == null);
    try std.testing.expectEqual(@as(usize, 1), swim.candidate_count);
    try std.testing.expectEqual(fake_peer, swim.candidate_peers[0].pubkey);
    try std.testing.expectEqual(@as(usize, 0), joins.count);

    try membership.upsert(aliveTestPeer(fake_peer));
    swim.applyGossip(.{
        .subject_pubkey = fake_peer,
        .event = .alive,
        .lamport = 11,
        .endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 40001),
        .wg_pubkey = [_]u8{0x77} ** 32,
    });

    try std.testing.expect(membership.peers.get(fake_peer).?.wg_pubkey == null);
    try std.testing.expectEqual(@as(usize, 0), joins.count);
}

test "unauthorized gossip candidates are capped and probed one at a time" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    const socket = inertTestSocket();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);
    swim.enableTrust();
    swim.addTrustedOrg([_]u8{0xA0} ** 32);

    var i: usize = 0;
    while (i < MAX_CANDIDATE_PEERS + 8) : (i += 1) {
        var subject = [_]u8{0x51} ** 32;
        subject[0] = @intCast(i + 1);
        subject[31] = @intCast(0xA0 + i);
        swim.applyGossip(.{
            .subject_pubkey = subject,
            .event = .join,
            .lamport = @intCast(i + 1),
            .endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, @intCast(41000 + i)),
            .wg_pubkey = [_]u8{0x66} ** 32,
        });
    }

    try std.testing.expectEqual(MAX_CANDIDATE_PEERS, swim.candidate_count);
    try std.testing.expectEqual(@as(usize, 0), membership.count());
    try std.testing.expectEqual(@as(usize, 0), swim.gossip_count);

    swim.send_tokens = 0;
    swim.last_token_refill_ns = nowNs();
    const dropped_before = swim.sends_dropped_ratelimit;
    swim.probeCandidatePeer(swim.last_token_refill_ns);

    try std.testing.expectEqual(dropped_before +% 1, swim.sends_dropped_ratelimit);
    try std.testing.expectEqual(@as(usize, 1), swim.pending_count);
}

test "candidate probes do not drain queued gossip" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    const socket = inertTestSocket();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);
    swim.enableTrust();
    swim.addTrustedOrg([_]u8{0xA0} ** 32);

    const candidate = [_]u8{0x32} ** 32;
    swim.applyGossip(.{
        .subject_pubkey = candidate,
        .event = .join,
        .lamport = 1,
        .endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 41900),
    });
    swim.enqueueGossip(.{
        .subject_pubkey = [_]u8{0x99} ** 32,
        .event = .alive,
        .lamport = 2,
        .endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 41901),
    });
    try std.testing.expectEqual(@as(usize, 1), swim.candidate_count);
    try std.testing.expectEqual(@as(usize, 1), swim.gossip_count);
    const remaining_before = swim.gossip_queue[0].remaining;

    swim.send_tokens = 0;
    swim.last_token_refill_ns = nowNs();
    swim.probeCandidatePeer(swim.last_token_refill_ns);

    try std.testing.expectEqual(@as(usize, 1), swim.pending_count);
    try std.testing.expectEqual(@as(usize, 1), swim.gossip_count);
    try std.testing.expectEqual(remaining_before, swim.gossip_queue[0].remaining);
}

test "candidate with invalid cert never graduates and is evicted" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    const socket = inertTestSocket();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);
    swim.enableTrust();
    swim.addTrustedOrg([_]u8{0xA0} ** 32);

    const candidate = [_]u8{0x33} ** 32;
    const endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 42000);
    swim.applyGossip(.{
        .subject_pubkey = candidate,
        .event = .join,
        .lamport = 1,
        .endpoint = endpoint,
        .wg_pubkey = [_]u8{0x44} ** 32,
    });
    try std.testing.expectEqual(@as(usize, 1), swim.candidate_count);

    var ack_buf: [1500]u8 = undefined;
    const invalid_cert = std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8);
    const written = try codec.encodeAck(&ack_buf, .{
        .sender_pubkey = candidate,
        .seq = 1,
        .gossip = &.{},
        .org_cert = invalid_cert,
        .has_org_cert = true,
    });
    swim.handleMessage(ack_buf[0..written], endpoint);

    try std.testing.expectEqual(@as(usize, 0), membership.count());
    try std.testing.expectEqual(@as(usize, 1), swim.candidate_count);

    swim.candidate_peers[0].probe_count = CANDIDATE_MAX_PROBES;
    swim.probeCandidatePeer(nowNs());
    try std.testing.expectEqual(@as(usize, 0), swim.candidate_count);
}

test "candidate endpoint refresh resets probes but not lifetime" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    const socket = inertTestSocket();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);
    swim.enableTrust();
    swim.addTrustedOrg([_]u8{0xA0} ** 32);

    const candidate = [_]u8{0x34} ** 32;
    const stale_endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 42100);
    const fresh_endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 42101);
    swim.applyGossip(.{
        .subject_pubkey = candidate,
        .event = .join,
        .lamport = 1,
        .endpoint = stale_endpoint,
    });
    const first_seen = swim.candidate_peers[0].first_seen_ns;
    swim.candidate_peers[0].probe_count = CANDIDATE_MAX_PROBES;
    swim.candidate_peers[0].last_probe_ns = first_seen + 1;

    swim.applyGossip(.{
        .subject_pubkey = candidate,
        .event = .alive,
        .lamport = 2,
        .endpoint = fresh_endpoint,
    });

    try std.testing.expect(messages.Endpoint.eql(swim.candidate_peers[0].endpoint, fresh_endpoint));
    try std.testing.expectEqual(first_seen, swim.candidate_peers[0].first_seen_ns);
    try std.testing.expectEqual(@as(u8, 0), swim.candidate_peers[0].probe_count);
    try std.testing.expectEqual(@as(i128, 0), swim.candidate_peers[0].last_probe_ns);

    const expiring_candidate = [_]u8{0x35} ** 32;
    const endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 42102);
    swim.applyGossip(.{
        .subject_pubkey = expiring_candidate,
        .event = .join,
        .lamport = 3,
        .endpoint = endpoint,
    });
    const expiring_index: usize = if (std.mem.eql(u8, &swim.candidate_peers[0].pubkey, &expiring_candidate)) 0 else 1;
    const expired_start = nowNs() - CANDIDATE_TTL_NS - 1;
    swim.candidate_peers[expiring_index].first_seen_ns = expired_start;
    swim.candidate_peers[expiring_index].probe_count = CANDIDATE_MAX_PROBES - 1;
    swim.applyGossip(.{
        .subject_pubkey = expiring_candidate,
        .event = .alive,
        .lamport = 4,
        .endpoint = endpoint,
    });

    try std.testing.expectEqual(expired_start, swim.candidate_peers[expiring_index].first_seen_ns);
    try std.testing.expectEqual(CANDIDATE_MAX_PROBES - 1, swim.candidate_peers[expiring_index].probe_count);
    swim.probeCandidatePeer(nowNs());
    try std.testing.expectEqual(@as(usize, 1), swim.candidate_count);
    try std.testing.expect(std.mem.eql(u8, &swim.candidate_peers[0].pubkey, &candidate));
}

test "cert-only gossip candidate is probed then graduates on direct cert" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    const socket = inertTestSocket();

    var joins = JoinCounter{};
    const handler = EventHandler{
        .ctx = &joins,
        .onPeerJoin = countPeerJoin,
        .onPeerDead = ignorePeerDead,
    };
    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, handler);
    swim.enableTrust();

    const org_kp = Org.generateOrgKeyPair();
    const org_pubkey = org_kp.public_key.toBytes();
    swim.addTrustedOrg(org_pubkey);

    const node_kp = keys.generate();
    const node_pubkey = node_kp.public_key.toBytes();
    const cert_wire = try issueCertWire(org_kp, node_pubkey, "node-1");
    const endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 43000);
    const wg_key = [_]u8{0x77} ** 32;

    swim.applyGossip(.{
        .subject_pubkey = node_pubkey,
        .event = .join,
        .lamport = 1,
        .endpoint = endpoint,
        .wg_pubkey = wg_key,
    });

    try std.testing.expectEqual(@as(usize, 0), membership.count());
    try std.testing.expectEqual(@as(usize, 1), swim.candidate_count);
    try std.testing.expectEqual(@as(usize, 0), joins.count);

    swim.probeCandidatePeer(nowNs());
    try std.testing.expectEqual(@as(usize, 1), swim.pending_count);
    try std.testing.expectEqual(node_pubkey, swim.pending[0].target_pubkey);

    var ack_buf: [1500]u8 = undefined;
    const written = try codec.encodeAck(&ack_buf, .{
        .sender_pubkey = node_pubkey,
        .seq = swim.pending[0].seq,
        .gossip = &.{},
        .org_cert = cert_wire,
        .has_org_cert = true,
    });
    swim.handleMessage(ack_buf[0..written], endpoint);

    const recorded = membership.peers.get(node_pubkey).?;
    try std.testing.expectEqualSlices(u8, &org_pubkey, &recorded.org_pubkey.?);
    try std.testing.expectEqual(@as(usize, 0), swim.candidate_count);
    try std.testing.expectEqual(@as(usize, 0), swim.pending_count);
    try std.testing.expect(recorded.wg_pubkey == null);
    try std.testing.expectEqual(@as(usize, 0), joins.count);

    swim.applyGossip(.{
        .subject_pubkey = node_pubkey,
        .event = .alive,
        .lamport = 2,
        .endpoint = endpoint,
        .wg_pubkey = wg_key,
    });

    try std.testing.expectEqualSlices(u8, &wg_key, &membership.peers.get(node_pubkey).?.wg_pubkey.?);
    try std.testing.expectEqual(@as(usize, 1), joins.count);
    try std.testing.expectEqualSlices(u8, &node_pubkey, &joins.last_pubkey.?);
}

test "gossiped join still admits an individually authorized subject" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    const socket = inertTestSocket();

    var joins = JoinCounter{};
    const handler = EventHandler{
        .ctx = &joins,
        .onPeerJoin = countPeerJoin,
        .onPeerDead = ignorePeerDead,
    };
    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, handler);
    swim.enableTrust();

    const peer_kp = keys.generate();
    const peer = peer_kp.public_key.toBytes();
    const wg_key = [_]u8{0x44} ** 32;
    swim.addAuthorizedKey(peer);
    swim.applyGossip(.{
        .subject_pubkey = peer,
        .event = .join,
        .lamport = 10,
        .endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 40000),
        .wg_pubkey = wg_key,
    });

    const recorded = membership.peers.get(peer).?;
    try std.testing.expectEqualSlices(u8, &wg_key, &recorded.wg_pubkey.?);
    try std.testing.expectEqual(@as(usize, 1), joins.count);
    try std.testing.expectEqualSlices(u8, &peer, &joins.last_pubkey.?);
}

test "trusted org does not admit arbitrary peers without a cert" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    var socket = Udp.UdpSocket.bind(0) catch return;
    defer socket.close();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);
    swim.enableTrust();
    swim.addTrustedOrg([_]u8{0xA0} ** 32);

    try std.testing.expect(!swim.isAuthorizedPeer([_]u8{0x55} ** 32, null));
}

test "valid trusted org cert admits and records peer until revoked" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    var socket = Udp.UdpSocket.bind(0) catch return;
    defer socket.close();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);
    swim.enableTrust();

    const org_kp = Org.generateOrgKeyPair();
    const org_pubkey = org_kp.public_key.toBytes();
    swim.addTrustedOrg(org_pubkey);

    const node_kp = keys.generate();
    const node_pubkey = node_kp.public_key.toBytes();
    var cert = try Org.issueCertificate(org_kp, node_pubkey, "node-1", 0);
    var cert_wire: [messages.ORG_CERT_WIRE_SIZE]u8 = undefined;
    cert.serialize(&cert_wire);

    try std.testing.expect(swim.isAuthorizedPeer(node_pubkey, cert_wire));
    try std.testing.expect(!swim.isAuthorizedPeer([_]u8{0x66} ** 32, cert_wire));

    try membership.upsert(aliveTestPeer(node_pubkey));
    swim.recordPeerCertificate(node_pubkey, cert_wire);

    const recorded = membership.peers.get(node_pubkey).?;
    try std.testing.expect(recorded.org_pubkey != null);
    try std.testing.expectEqualSlices(u8, &org_pubkey, &recorded.org_pubkey.?);
    try std.testing.expectEqualSlices(u8, &cert.node_name, &recorded.org_node_name);
    try std.testing.expectEqual(@as(?i64, 0), recorded.cert_expires_at);
    try std.testing.expect(swim.isAuthorizedPeer(node_pubkey, null));

    swim.revoked_nodes[0] = node_pubkey;
    swim.revoked_count = 1;
    try std.testing.expect(!swim.isAuthorizedPeer(node_pubkey, null));
    try std.testing.expect(!swim.isAuthorizedPeer(node_pubkey, cert_wire));
}

test "org revoke requires a valid trusted-org signature (C2 regression)" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    var socket = Udp.UdpSocket.bind(0) catch return; // skip if no socket
    defer socket.close();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);

    const org_kp = keys.generate();
    const org_pubkey = org_kp.public_key.toBytes();
    swim.addTrustedOrg(org_pubkey);

    const victim = [_]u8{0x77} ** 32;
    try membership.upsert(aliveTestPeer(victim));

    // (1) Forged: trusted org pubkey but an all-zero signature → rejected.
    const forged = messages.OrgCertRevoke{ .org_pubkey = org_pubkey, .node_pubkey = victim, .reason = 2, .lamport = 5, .signature = [_]u8{0} ** 64 };
    swim.handleOrgRevoke(forged);
    try std.testing.expect(membership.peers.get(victim).?.state == .alive);
    try std.testing.expectEqual(@as(usize, 0), swim.revoked_count);

    // (2) Valid: correctly signed by the trusted org → revoked + marked dead.
    var valid = messages.OrgCertRevoke{ .org_pubkey = org_pubkey, .node_pubkey = victim, .reason = 2, .lamport = 6, .signature = undefined };
    const signed = codec.orgRevokeSignedBytes(valid);
    valid.signature = keys.sign(&signed, org_kp.secret_key) catch unreachable;
    swim.handleOrgRevoke(valid);
    try std.testing.expect(membership.peers.get(victim).?.state == .dead);
    try std.testing.expectEqual(@as(usize, 1), swim.revoked_count);

    // (3) Untrusted org with a valid self-signature → rejected.
    const evil_kp = keys.generate();
    const evil_pub = evil_kp.public_key.toBytes();
    const victim2 = [_]u8{0x88} ** 32;
    try membership.upsert(aliveTestPeer(victim2));
    var evil = messages.OrgCertRevoke{ .org_pubkey = evil_pub, .node_pubkey = victim2, .reason = 2, .lamport = 7, .signature = undefined };
    const evil_signed = codec.orgRevokeSignedBytes(evil);
    evil.signature = keys.sign(&evil_signed, evil_kp.secret_key) catch unreachable;
    swim.handleOrgRevoke(evil);
    try std.testing.expect(membership.peers.get(victim2).?.state == .alive);
}

test "gossiped dead does not instantly evict a third party (H2 regression)" {
    const allocator = std.testing.allocator;
    var membership = Membership.MembershipTable.init(allocator, 5000);
    defer membership.deinit();
    var socket = Udp.UdpSocket.bind(0) catch return;
    defer socket.close();

    var swim = SwimProtocol.init(&membership, socket, .{}, [_]u8{1} ** 32, [_]u8{2} ** 32, .{ 127, 0, 0, 1 }, 51821, null);

    const victim = [_]u8{0x55} ** 32;
    try membership.upsert(aliveTestPeer(victim));

    // An unauthenticated gossip "dead" about a third party must only DOWNGRADE
    // to local suspicion (to be confirmed by our own probes), never instant-kill.
    swim.applyGossip(.{ .subject_pubkey = victim, .event = .dead, .lamport = 99, .endpoint = null });
    const p = membership.peers.get(victim).?;
    try std.testing.expect(p.state != .dead);
    try std.testing.expect(p.state == .suspected);

    // A replayed "alive" from gossip must NOT clear our local suspicion (M6).
    swim.applyGossip(.{ .subject_pubkey = victim, .event = .alive, .lamport = 100, .endpoint = messages.Endpoint.initV4(.{ 127, 0, 0, 1 }, 40000) });
    try std.testing.expect(membership.peers.get(victim).?.state == .suspected);
}
