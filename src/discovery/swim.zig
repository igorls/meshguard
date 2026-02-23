//! SWIM protocol implementation for meshguard.
//!
//! Single-threaded, poll-based gossip loop:
//!   1. Pick random alive peer → send PING
//!   2. Process received messages (PING/ACK/PING-REQ)
//!   3. Check pending pings for timeouts → escalate to PING-REQ
//!   4. Expire suspected peers → mark DEAD
//!   5. Piggyback gossip entries on outgoing messages

const std = @import("std");
const Membership = @import("membership.zig");
const messages = @import("../protocol/messages.zig");
const codec = @import("../protocol/codec.zig");
const Udp = @import("../net/udp.zig");
const Holepuncher = @import("../nat/holepunch.zig").Holepuncher;
const log = std.log.scoped(.swim);

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
};

/// Gossip entry with broadcast remaining counter.
const GossipSlot = struct {
    entry: messages.GossipEntry,
    remaining: u32, // broadcasts remaining before expiry
};

/// Pending ping tracking.
const PendingPing = struct {
    target_pubkey: [32]u8,
    target_addr: [4]u8,
    target_port: u16,
    seq: u64,
    sent_at_ns: i128,
    escalated: bool, // whether we've already sent ping-req
};

/// SWIM protocol state machine with event loop.
pub const SwimProtocol = struct {
    config: SwimConfig,
    membership: *Membership.MembershipTable,
    seq: u64,
    our_pubkey: [32]u8,
    our_wg_pubkey: [32]u8,
    our_mesh_ip: [4]u8,
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

    // Node's own org certificate (if any, loaded at init)
    our_org_cert: ?[186]u8 = null,

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

    /// Check if a pubkey is authorized.
    fn isAuthorizedPeer(self: *const SwimProtocol, pubkey: [32]u8) bool {
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
        };

        var buf: [1500]u8 = undefined;
        const written = codec.encodePing(&buf, ping) catch return;

        // Send to every alive peer with a known endpoint
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (peer.state == .alive or peer.state == .suspected) {
                if (peer.gossip_endpoint) |ep| {
                    _ = self.socket.sendTo(buf[0..written], ep.addr, ep.port) catch {};
                }
            }
        }
    }

    /// Single iteration of the SWIM protocol.
    pub fn tick(self: *SwimProtocol) !void {
        // 1. Process incoming messages (poll with gossip_interval timeout)
        const poll_ms: i32 = @min(@as(i32, @intCast(self.config.gossip_interval_ms)), 200);
        if (try self.socket.pollRead(poll_ms)) {
            // Drain all available messages
            while (true) {
                var recv_buf: [1500]u8 = undefined;
                const result = try self.socket.recvFrom(&recv_buf);
                if (result == null) break;
                const recv = result.?;
                self.handleMessage(recv.data, recv.sender_addr, recv.sender_port);
            }
        }

        // 2. Check pending pings for timeouts
        self.checkTimeouts();

        // 3. Expire suspected peers
        const expired = self.membership.expireSuspected();
        for (expired) |pubkey| {
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
        const now_ns = std.time.nanoTimestamp();
        const interval_ns: i128 = @as(i128, self.config.gossip_interval_ms) * 1_000_000;
        if (now_ns - self.last_ping_sent_ns >= interval_ns) {
            if (self.membership.randomAlivePeer()) |peer| {
                if (peer.gossip_endpoint) |ep| {
                    self.sendPing(ep.addr, ep.port, peer.pubkey);
                    self.last_ping_sent_ns = now_ns;
                }
            }
        }

        // 5. Hole punch: send probes for active punches
        _ = self.holepuncher.sendProbes(&self.socket);
        self.holepuncher.expireTimeouts();

        // 6. Check for unreachable cone NAT peers (every 30s)
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
            self.sendPing(seed.addr, seed.port, [_]u8{0} ** 32);
        }
    }

    /// Process timers and gossip without polling the socket.
    /// Use this when an external event loop handles socket I/O.
    pub fn tickTimersOnly(self: *SwimProtocol) void {
        // 1. Check pending pings for timeouts
        self.checkTimeouts();

        const now_ns = std.time.nanoTimestamp();

        // 2. Expire suspected peers
        const expired = self.membership.expireSuspected();
        for (expired) |pubkey| {
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
                    self.sendPing(ep.addr, ep.port, peer.pubkey);
                    self.last_ping_sent_ns = now_ns;
                }
            }
        }

        // 4. Hole punch: send probes for active punches
        _ = self.holepuncher.sendProbes(&self.socket);
        self.holepuncher.expireTimeouts();

        // 5. Check for unreachable cone NAT peers (every 30s)
        const punch_check_interval: i128 = 30_000_000_000;
        if (now_ns - self.last_punch_check_ns >= punch_check_interval) {
            self.last_punch_check_ns = now_ns;
            self.checkUnreachablePeers();
        }
    }

    /// Feed a received packet to SWIM from an external event loop.
    pub fn feedPacket(self: *SwimProtocol, data: []const u8, sender_addr: [4]u8, sender_port: u16) void {
        self.handleMessage(data, sender_addr, sender_port);
    }

    // ─── Message handling ───

    fn handleMessage(self: *SwimProtocol, data: []const u8, sender_addr: [4]u8, sender_port: u16) void {
        // Check for holepunch probes (raw UDP with MGHP magic, not SWIM-encoded)
        if (data.len >= 4 and Holepuncher.isProbe(data[0..4])) {
            self.handleHolepunchProbe(sender_addr, sender_port);
            return;
        }

        const decoded = codec.decode(data) catch return;

        // Trust enforcement: check sender's pubkey against authorized set
        const sender_pubkey: [32]u8 = switch (decoded) {
            .ping => |p| p.sender_pubkey,
            .ack => |a| a.sender_pubkey,
            .ping_req => |r| r.sender_pubkey,
            .holepunch_request => |req| req.sender_pubkey,
            .holepunch_response => |resp| resp.sender_pubkey,
            .org_alias_announce => |ann| ann.org_pubkey,
            .org_cert_revoke => |rev| rev.org_pubkey,
        };
        if (!self.isAuthorizedPeer(sender_pubkey)) return;

        switch (decoded) {
            .ping => |p| self.handlePing(&p, sender_addr, sender_port),
            .ack => |a| self.handleAck(&a, sender_addr, sender_port),
            .ping_req => |r| self.handlePingReq(r, sender_addr, sender_port),
            .holepunch_request => |req| self.handleHolepunchRequest(req, sender_addr, sender_port),
            .holepunch_response => |resp| self.handleHolepunchResponse(resp),
            .org_alias_announce => |ann| self.handleOrgAlias(ann),
            .org_cert_revoke => |rev| self.handleOrgRevoke(rev),
        }
    }

    /// Handle an OrgAliasAnnounce: register or update org alias, with Lamport conflict resolution.
    fn handleOrgAlias(self: *SwimProtocol, ann: messages.OrgAliasAnnounce) void {
        const alias_name = std.mem.trimRight(u8, &ann.alias, "\x00");

        // Check for existing alias with same name from a different org (conflict)
        for (0..self.alias_count) |i| {
            const existing_name = std.mem.trimRight(u8, &self.alias_names[i], "\x00");
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

    fn handlePing(self: *SwimProtocol, ping: *const codec.DecodedPing, sender_addr: [4]u8, sender_port: u16) void {
        // Register sender FIRST so gossip callbacks see the real network address
        if (!std.mem.eql(u8, &ping.sender_pubkey, &([_]u8{0} ** 32))) {
            self.registerOrUpdatePeer(ping.sender_pubkey, sender_addr, sender_port);
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
        };

        var buf: [1500]u8 = undefined;
        const written = codec.encodeAck(&buf, ack) catch return;
        _ = self.socket.sendTo(buf[0..written], sender_addr, sender_port) catch {};
    }

    fn handleAck(self: *SwimProtocol, ack: *const codec.DecodedAck, sender_addr: [4]u8, sender_port: u16) void {
        // Register sender FIRST so gossip callbacks see the real network address
        if (!std.mem.eql(u8, &ack.sender_pubkey, &([_]u8{0} ** 32))) {
            self.registerOrUpdatePeer(ack.sender_pubkey, sender_addr, sender_port);
        }

        // Process piggybacked gossip (onPeerJoin may fire here)
        for (ack.gossip()) |entry| {
            self.applyGossip(entry);
        }

        // Clear pending ping
        self.clearPending(ack.seq);
    }

    fn handlePingReq(self: *SwimProtocol, req: messages.PingReq, sender_addr: [4]u8, sender_port: u16) void {
        _ = sender_addr;
        _ = sender_port;

        // Forward ping to the target
        if (self.membership.peers.get(req.target_pubkey)) |target| {
            if (target.gossip_endpoint) |ep| {
                self.sendPing(ep.addr, ep.port, req.target_pubkey);
            }
        }
    }

    // ─── Hole Punching ───

    fn handleHolepunchRequest(self: *SwimProtocol, req: messages.HolepunchRequest, sender_addr: [4]u8, sender_port: u16) void {
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
                _ = self.socket.sendTo(buf[0..written], sender_addr, sender_port) catch {};

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
                    _ = self.socket.sendTo(buf[0..written], ep.addr, ep.port) catch {};
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

    fn handleHolepunchProbe(self: *SwimProtocol, sender_addr: [4]u8, sender_port: u16) void {
        // A probe arrived — the hole is punched!
        // Find which peer this corresponds to by checking active punches
        // For now, check all peers with matching public endpoints
        var iter = self.membership.peers.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (peer.public_endpoint) |pub_ep| {
                if (std.mem.eql(u8, &pub_ep.addr, &sender_addr)) {
                    // Found the peer — notify handler to configure WG endpoint
                    std.debug.print("  [punch] hole punched with {x:0>2}{x:0>2}... at {d}.{d}.{d}.{d}:{d}\n", .{
                        peer.pubkey[0], peer.pubkey[1],
                        sender_addr[0], sender_addr[1],
                        sender_addr[2], sender_addr[3],
                        sender_port,
                    });
                    const punched_ep = messages.Endpoint{ .addr = sender_addr, .port = sender_port };
                    if (self.handler) |h| {
                        if (h.onPeerPunched) |callback| {
                            callback(h.ctx, peer, punched_ep);
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
                    _ = self.socket.sendTo(buf[0..written], rvz_ep.addr, rvz_ep.port) catch {};
                }
            }
        }
    }

    // ─── Peer management ───

    fn registerOrUpdatePeer(self: *SwimProtocol, pubkey: [32]u8, addr: [4]u8, port: u16) void {
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

            self.membership.upsert(.{
                .pubkey = pubkey,
                .name = "",
                .state = .alive,
                .gossip_endpoint = .{ .addr = addr, .port = port },
                .wg_pubkey = null, // Will be set via gossip wg_pubkey field
                .mesh_ip = mesh_ip,
                .wg_port = 51830,
                .lamport = self.membership.lamport,
                .last_seen_ns = std.time.nanoTimestamp(),
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
                .endpoint = self.our_public_endpoint orelse .{ .addr = self.our_mesh_ip, .port = self.config.gossip_port },
                .wg_pubkey = self.our_wg_pubkey,
                .public_endpoint = self.our_public_endpoint,
                .nat_type = self.our_nat_type,
            });

            // Also enqueue gossip about the new peer
            self.enqueueGossip(.{
                .subject_pubkey = pubkey,
                .event = .join,
                .lamport = self.membership.lamport,
                .endpoint = .{ .addr = addr, .port = port },
            });
        }
    }

    // ─── PING/timeout management ───

    fn sendPing(self: *SwimProtocol, addr: [4]u8, port: u16, target_pubkey: [32]u8) void {
        self.seq += 1;
        const gossip = self.collectGossip();

        const ping = messages.Ping{
            .sender_pubkey = self.our_pubkey,
            .seq = self.seq,
            .gossip = gossip,
        };

        var buf: [1500]u8 = undefined;
        const written = codec.encodePing(&buf, ping) catch return;
        _ = self.socket.sendTo(buf[0..written], addr, port) catch return;

        // Track pending
        if (self.pending_count < self.pending.len) {
            self.pending[self.pending_count] = .{
                .target_pubkey = target_pubkey,
                .target_addr = addr,
                .target_port = port,
                .seq = self.seq,
                .sent_at_ns = std.time.nanoTimestamp(),
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
        const now = std.time.nanoTimestamp();
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
            _ = self.socket.sendTo(buf[0..written], ep.addr, ep.port) catch continue;
            sent += 1;
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
                // Only use gossip endpoint for NEW peer registration.
                // For existing peers, the real sender_addr from direct
                // pings (set in handlePing/handleAck) is more reliable.
                if (entry.endpoint) |ep| {
                    if (self.membership.peers.getPtr(entry.subject_pubkey) == null) {
                        self.registerOrUpdatePeer(entry.subject_pubkey, ep.addr, ep.port);
                    } else {
                        // Peer exists — just refresh alive state without changing endpoint
                        if (self.membership.peers.getPtr(entry.subject_pubkey)) |peer| {
                            peer.state = .alive;
                            peer.suspected_at_ns = null;
                        }
                    }
                }

                // Update peer NAT info from gossip
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
            .suspect => {
                self.membership.suspect(entry.subject_pubkey);
            },
            .dead => {
                self.membership.markDead(entry.subject_pubkey);
                if (self.handler) |h| {
                    h.onPeerDead(h.ctx, entry.subject_pubkey);
                }
            },
            .leave => {
                self.membership.markDead(entry.subject_pubkey);
                if (self.handler) |h| {
                    h.onPeerDead(h.ctx, entry.subject_pubkey);
                }
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
    const target_addr = [4]u8{ 127, 0, 0, 1 };
    const target_port = 12345;

    // Send first ping
    swim.sendPing(target_addr, target_port, target_pubkey);
    try std.testing.expectEqual(@as(u64, 1), swim.seq);
    try std.testing.expectEqual(@as(usize, 1), swim.pending_count);
    try std.testing.expectEqual(target_pubkey, swim.pending[0].target_pubkey);
    try std.testing.expectEqual(@as(u64, 1), swim.pending[0].seq);

    // Send second ping
    swim.sendPing(target_addr, target_port + 1, target_pubkey);
    try std.testing.expectEqual(@as(u64, 2), swim.seq);
    try std.testing.expectEqual(@as(usize, 2), swim.pending_count);
    try std.testing.expectEqual(@as(u64, 2), swim.pending[1].seq);
}
