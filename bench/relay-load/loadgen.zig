//! Relay load generator (Linux).
//!
//! Simulates many relay clients against one relay, each with its own UDP
//! socket on its own loopback address so per-address limits apply as they
//! would on the internet. Every client behaves like a mobile context with a
//! pinned relay: it pings with its signed WireGuard binding, proves its
//! endpoint with a Noise handshake, re-proves periodically, answers relay
//! pings, and sends app frames to a few contacts at a Poisson rate.
//!
//! Frames carry a cleartext measurement header instead of ciphertext; the
//! relay never decrypts, so this measures exactly the relay's forwarding work
//! without spending the generator's CPU on sealing.
//!
//! Optional adversaries: flooders (proven clients sending far above their
//! budget), spoofers (unproven sockets naming honest clients as sender), and a
//! reconnect storm (every client moves to a new source port at once).
//!
//! Prints one JSON object with proof times, delivery, loss and latency.

const std = @import("std");
const mg = @import("meshguard");
const linux = std.os.linux;
const Codec = mg.protocol.Codec;
const Messages = mg.protocol.Messages;
const Noise = mg.wireguard.Noise;
const Binding = mg.identity.Binding;
const Udp = mg.net.Udp;
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;

const ns_per_s: i128 = std.time.ns_per_s;
const ns_per_ms: i128 = std.time.ns_per_ms;
const MAGIC = "MGLD";
const HEADER = 1 + 32 + 32 + 12; // 0x50, dest, sender, nonce
const TAG = 16;

const Options = struct {
    relay_addr: [4]u8 = .{ 127, 0, 0, 1 },
    relay_port: u16 = 51821,
    relay_key: [32]u8 = std.mem.zeroes([32]u8),
    clients: u32 = 1000,
    contacts: u32 = 4,
    /// App frames per second per honest client.
    rate: f64 = 0.5,
    payload: u32 = 200,
    /// Seconds to wait for clients to prove before measuring.
    warmup_s: u32 = 60,
    duration_s: u32 = 30,
    keepalive_s: f64 = 25,
    /// Seconds between endpoint re-proofs (mobile contexts use 15).
    reproof_s: f64 = 15,
    flooders: u32 = 0,
    flood_pps: f64 = 2000,
    spoofers: u32 = 0,
    spoof_pps: f64 = 200,
    /// Seconds into the measurement when every client moves to a new port.
    storm_at_s: f64 = 0,
    seed: u64 = 1,
};

const Role = enum(u8) { honest, flooder, spoofer };

const Client = struct {
    role: Role,
    identity: [32]u8,
    wg_private: [32]u8,
    wg_public: [32]u8,
    binding: Messages.WgBinding,
    addr: [4]u8,
    socket: Udp.UdpSocket,
    proven: bool = false,
    first_proof_ns: i128 = 0,
    /// When the current proof attempt started (0 = none outstanding).
    attempt_ns: i128 = 0,
    hs: ?Noise.Handshake = null,
    ts: u64 = 1,
    seq: u64 = 0,
    ping_seq: u64 = 0,
};

const EventKind = enum(u8) { send, ping, reproof, retry, flood, spoof };

const Event = struct {
    at: i128,
    client: u32,
    kind: EventKind,

    fn order(_: void, a: Event, b: Event) std.math.Order {
        return std.math.order(a.at, b.at);
    }
};

const Queue = std.PriorityQueue(Event, void, Event.order);

const Metrics = struct {
    sent: u64 = 0,
    sent_to_unproven: u64 = 0,
    received: u64 = 0,
    duplicates: u64 = 0,
    flood_sent: u64 = 0,
    flood_received: u64 = 0,
    spoof_sent: u64 = 0,
    spoof_delivered: u64 = 0,
    handshakes_sent: u64 = 0,
    proofs: u64 = 0,
    send_errors: u64 = 0,
    latencies_us: std.ArrayListUnmanaged(u32) = .empty,
    storm_reproven_ms: ?u64 = null,
};

fn nowNs() i128 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * ns_per_s + ts.nsec;
}

fn clientAddr(i: u32) [4]u8 {
    return .{ 127, @intCast(i / 62500 + 1), @intCast((i / 250) % 250 + 1), @intCast(i % 250 + 1) };
}

fn parseEndpoint(text: []const u8) !struct { addr: [4]u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidEndpoint;
    var addr: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text[0..colon], '.');
    for (&addr) |*octet| octet.* = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidEndpoint, 10);
    return .{ .addr = addr, .port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10) };
}

fn parseOptions(args: []const []const u8) !Options {
    var o = Options{};
    var have_key = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const name = args[i];
        if (i + 1 >= args.len) return error.MissingValue;
        const value = args[i + 1];
        i += 1;
        if (std.mem.eql(u8, name, "--relay")) {
            const ep = try parseEndpoint(value);
            o.relay_addr = ep.addr;
            o.relay_port = ep.port;
        } else if (std.mem.eql(u8, name, "--relay-key")) {
            _ = try std.base64.standard.Decoder.decode(&o.relay_key, value);
            have_key = true;
        } else if (std.mem.eql(u8, name, "--clients")) {
            o.clients = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--contacts")) {
            o.contacts = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--rate")) {
            o.rate = try std.fmt.parseFloat(f64, value);
        } else if (std.mem.eql(u8, name, "--payload")) {
            o.payload = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--warmup")) {
            o.warmup_s = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--duration")) {
            o.duration_s = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--keepalive")) {
            o.keepalive_s = try std.fmt.parseFloat(f64, value);
        } else if (std.mem.eql(u8, name, "--reproof")) {
            o.reproof_s = try std.fmt.parseFloat(f64, value);
        } else if (std.mem.eql(u8, name, "--flooders")) {
            o.flooders = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--flood-pps")) {
            o.flood_pps = try std.fmt.parseFloat(f64, value);
        } else if (std.mem.eql(u8, name, "--spoofers")) {
            o.spoofers = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--spoof-pps")) {
            o.spoof_pps = try std.fmt.parseFloat(f64, value);
        } else if (std.mem.eql(u8, name, "--storm-at")) {
            o.storm_at_s = try std.fmt.parseFloat(f64, value);
        } else if (std.mem.eql(u8, name, "--seed")) {
            o.seed = try std.fmt.parseInt(u64, value, 10);
        } else return error.UnknownOption;
    }
    if (!have_key) return error.MissingRelayKey;
    if (o.clients < 2 or o.contacts == 0 or o.payload < 32 or o.payload > 1024) return error.InvalidOption;
    return o;
}

const Generator = struct {
    allocator: std.mem.Allocator,
    o: Options,
    relay: Messages.Endpoint,
    relay_wg: [32]u8,
    clients: []Client,
    honest: u32,
    epoll_fd: i32,
    queue: Queue = .empty,
    rng: std.Random.DefaultPrng,
    m: Metrics = .{},
    measuring: bool = false,
    measure_start: i128 = 0,
    storm_start: i128 = 0,
    storm_pending: u32 = 0,
    last_seq: []u64,
    start_ns: i128 = 0,
    warmup_ms: u64 = 0,
    measured_ms: u64 = 0,

    fn rand(self: *Generator) std.Random {
        return self.rng.random();
    }

    fn after(_: *Generator, seconds: f64) i128 {
        return nowNs() + @as(i128, @intFromFloat(seconds * @as(f64, @floatFromInt(ns_per_s))));
    }

    /// Exponential inter-arrival time for a Poisson process.
    fn poisson(self: *Generator, rate: f64) f64 {
        const u = @max(self.rand().float(f64), 1e-12);
        return -@log(u) / rate;
    }

    fn schedule(self: *Generator, at: i128, client: u32, kind: EventKind) !void {
        try self.queue.push(self.allocator, .{ .at = at, .client = client, .kind = kind });
    }

    fn openSocket(self: *Generator, c: *Client, index: u32) !void {
        c.socket = try Udp.UdpSocket.bindAddr(c.addr, 0);
        var ev = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .u32 = index } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, @intCast(c.socket.fd), &ev);
        if (@as(isize, @bitCast(rc)) < 0) return error.EpollAddFailed;
    }

    fn init(allocator: std.mem.Allocator, o: Options) !Generator {
        const relay_pk = try Ed25519.PublicKey.fromBytes(o.relay_key);
        const total = o.clients + o.flooders + o.spoofers;
        const epoll_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (@as(isize, @bitCast(epoll_rc)) < 0) return error.EpollCreateFailed;

        var g = Generator{
            .allocator = allocator,
            .o = o,
            .relay = Messages.Endpoint.initV4(o.relay_addr, o.relay_port),
            .relay_wg = try X25519.publicKeyFromEd25519(relay_pk),
            .clients = try allocator.alloc(Client, total),
            .honest = o.clients,
            .epoll_fd = @intCast(epoll_rc),
            .rng = std.Random.DefaultPrng.init(o.seed),
            .last_seq = try allocator.alloc(u64, total),
        };
        @memset(g.last_seq, 0);
        for (g.clients, 0..) |*c, n| {
            const index: u32 = @intCast(n);
            var seed: [32]u8 = undefined;
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update("meshguard-relay-loadgen");
            h.update(std.mem.asBytes(&o.seed));
            h.update(std.mem.asBytes(&index));
            h.final(&seed);
            const kp = try Ed25519.KeyPair.generateDeterministic(seed);
            var private = seed;
            private[0] &= 248;
            private[31] &= 127;
            private[31] |= 64;
            const public = try X25519.recoverPublicKey(private);
            c.* = .{
                .role = if (index < o.clients) .honest else if (index < o.clients + o.flooders) .flooder else .spoofer,
                .identity = kp.public_key.toBytes(),
                .wg_private = private,
                .wg_public = public,
                .binding = try Binding.signWithSeed(seed, public),
                .addr = clientAddr(index),
                .socket = undefined,
            };
            try g.openSocket(c, index);
        }
        return g;
    }

    fn send(self: *Generator, c: *Client, data: []const u8) void {
        _ = c.socket.sendToEndpoint(data, self.relay) catch {
            self.m.send_errors += 1;
        };
    }

    fn sendPing(self: *Generator, c: *Client) void {
        var buf: [512]u8 = undefined;
        c.ping_seq += 1;
        const len = Codec.encodePing(&buf, .{ .sender_pubkey = c.identity, .seq = c.ping_seq, .gossip = &.{}, .wg_binding = c.binding }) catch return;
        self.send(c, buf[0..len]);
    }

    fn startProof(self: *Generator, c: *Client) void {
        if (c.hs) |*old| old.deinit();
        c.hs = Noise.Handshake.init(c.wg_private, c.wg_public, self.relay_wg) catch return;
        var ephemeral: [32]u8 = undefined;
        self.rand().bytes(&ephemeral);
        var tai: [12]u8 = std.mem.zeroes([12]u8);
        std.mem.writeInt(u64, tai[0..8], 0x4000000000000000 + c.ts, .big);
        c.ts += 1;
        const msg = c.hs.?.createInitiationWithEntropy(self.rand().int(u32), ephemeral, tai) catch return;
        c.attempt_ns = nowNs();
        self.m.handshakes_sent += 1;
        self.send(c, std.mem.asBytes(&msg));
    }

    fn frame(self: *Generator, buf: []u8, from: *Client, from_index: u32, to: *const Client, kind: u8) []const u8 {
        const len = HEADER + self.o.payload + TAG;
        buf[0] = 0x50;
        @memcpy(buf[1..33], &to.identity);
        @memcpy(buf[33..65], &from.identity);
        from.seq += 1;
        std.mem.writeInt(u64, buf[65..73], from.seq, .little);
        @memset(buf[73..77], 0);
        const body = buf[HEADER .. HEADER + self.o.payload];
        @memcpy(body[0..4], MAGIC);
        body[4] = kind;
        std.mem.writeInt(u32, body[5..9], from_index, .little);
        std.mem.writeInt(u64, body[9..17], from.seq, .little);
        std.mem.writeInt(i64, body[17..25], @intCast(nowNs()), .little);
        @memset(body[25..], 0x5a);
        @memset(buf[HEADER + self.o.payload .. len], 0);
        return buf[0..len];
    }

    fn contactOf(self: *Generator, i: u32) u32 {
        const k = self.rand().uintLessThan(u32, @min(self.o.contacts, self.honest - 1));
        return (i + 1 + k) % self.honest;
    }

    fn handle(self: *Generator, e: Event) !void {
        const c = &self.clients[e.client];
        var buf: [1500]u8 = undefined;
        switch (e.kind) {
            .send => {
                if (c.proven) {
                    const to_index = self.contactOf(e.client);
                    const to = &self.clients[to_index];
                    self.send(c, self.frame(&buf, c, e.client, to, 0));
                    if (self.measuring) {
                        if (to.proven) self.m.sent += 1 else self.m.sent_to_unproven += 1;
                    }
                }
                try self.schedule(self.after(self.poisson(self.o.rate)), e.client, .send);
            },
            .flood => {
                if (c.proven) {
                    const to = &self.clients[self.rand().uintLessThan(u32, self.honest)];
                    self.send(c, self.frame(&buf, c, e.client, to, 1));
                    if (self.measuring) self.m.flood_sent += 1;
                }
                try self.schedule(self.after(1.0 / self.o.flood_pps), e.client, .flood);
            },
            .spoof => {
                // Name an honest client as sender from an unproven socket.
                const victim = self.rand().uintLessThan(u32, self.honest);
                const to = &self.clients[self.rand().uintLessThan(u32, self.honest)];
                const f = self.frame(&buf, &self.clients[victim], victim, to, 2);
                self.send(c, f);
                if (self.measuring) self.m.spoof_sent += 1;
                try self.schedule(self.after(1.0 / self.o.spoof_pps), e.client, .spoof);
            },
            .ping => {
                self.sendPing(c);
                try self.schedule(self.after(self.o.keepalive_s * (0.8 + 0.4 * self.rand().float(f64))), e.client, .ping);
            },
            .reproof => {
                self.startProof(c);
                try self.schedule(self.after(self.o.reproof_s * (0.9 + 0.2 * self.rand().float(f64))), e.client, .reproof);
            },
            .retry => {
                // Retry with backoff until the first proof lands.
                if (c.attempt_ns != 0 and nowNs() - c.attempt_ns >= ns_per_s) {
                    self.sendPing(c);
                    self.startProof(c);
                }
                if (!c.proven or c.attempt_ns != 0) {
                    try self.schedule(self.after(1.0 + self.rand().float(f64)), e.client, .retry);
                }
            },
        }
    }

    fn receive(self: *Generator, index: u32) void {
        const c = &self.clients[index];
        var buf: [2048]u8 = undefined;
        while (c.socket.recvFrom(&buf) catch null) |r| {
            const d = r.data;
            if (d.len == @sizeOf(Noise.HandshakeResponse) and std.mem.readInt(u32, d[0..4], .little) == 2) {
                var msg: Noise.HandshakeResponse = undefined;
                @memcpy(std.mem.asBytes(&msg), d);
                if (c.hs) |*hs| {
                    if (hs.consumeResponse(&msg)) |_| {
                        hs.deinit();
                        c.hs = null;
                        const now = nowNs();
                        if (!c.proven) {
                            c.proven = true;
                            c.first_proof_ns = now;
                        }
                        c.attempt_ns = 0;
                        self.m.proofs += 1;
                        if (self.storm_start != 0 and self.storm_pending > 0) {
                            self.storm_pending -= 1;
                            if (self.storm_pending == 0) self.m.storm_reproven_ms = @intCast(@divTrunc(now - self.storm_start, ns_per_ms));
                        }
                    } else |_| {}
                }
                continue;
            }
            if (d.len >= 50 and d[0] == 0x01) {
                // Answer relay pings like a mobile context.
                var ack: [512]u8 = undefined;
                const seq = std.mem.readInt(u64, d[33..41], .little);
                const len = Codec.encodeAck(&ack, .{ .sender_pubkey = c.identity, .seq = seq, .gossip = &.{}, .wg_binding = c.binding }) catch continue;
                self.send(c, ack[0..len]);
                continue;
            }
            if (d.len < HEADER + 25 + TAG or d[0] != 0x50) continue;
            const body = d[HEADER..];
            if (!std.mem.eql(u8, body[0..4], MAGIC)) continue;
            const kind = body[4];
            const from = std.mem.readInt(u32, body[5..9], .little);
            const seq = std.mem.readInt(u64, body[9..17], .little);
            const sent_ns: i128 = std.mem.readInt(i64, body[17..25], .little);
            switch (kind) {
                0 => {
                    if (from >= self.last_seq.len) continue;
                    if (seq <= self.last_seq[from] and self.last_seq[from] != 0) {
                        // Frames from one sender can be reordered; only exact repeats are duplicates.
                        if (seq == self.last_seq[from]) self.m.duplicates += 1;
                    }
                    if (seq > self.last_seq[from]) self.last_seq[from] = seq;
                    if (self.measuring and sent_ns >= self.measure_start) {
                        self.m.received += 1;
                        const us: u64 = @intCast(@max(@divTrunc(nowNs() - sent_ns, 1000), 0));
                        self.m.latencies_us.append(self.allocator, @intCast(@min(us, std.math.maxInt(u32)))) catch {};
                    }
                },
                1 => if (self.measuring) {
                    self.m.flood_received += 1;
                },
                2 => self.m.spoof_delivered += 1,
                else => {},
            }
        }
    }

    fn pump(self: *Generator, until: i128) !void {
        var events: [256]linux.epoll_event = undefined;
        while (true) {
            const now = nowNs();
            if (now >= until) return;
            while (self.queue.peek()) |e| {
                if (e.at > now) break;
                _ = self.queue.pop();
                try self.handle(e);
            }
            const next = if (self.queue.peek()) |e| e.at else until;
            const wait_ms: i32 = @intCast(std.math.clamp(@divTrunc(@min(next, until) - nowNs(), ns_per_ms), 0, 10));
            const n = linux.epoll_wait(self.epoll_fd, &events, events.len, wait_ms);
            const count: isize = @bitCast(n);
            if (count <= 0) continue;
            for (events[0..@intCast(count)]) |ev| self.receive(ev.data.u32);
        }
    }

    fn provenHonest(self: *const Generator) u32 {
        var n: u32 = 0;
        for (self.clients[0..self.honest]) |c| {
            if (c.proven) n += 1;
        }
        return n;
    }

    fn run(self: *Generator) !void {
        const start = nowNs();
        self.start_ns = start;
        // Everyone joins at once: the startup storm the relay must absorb.
        for (self.clients, 0..) |*c, n| {
            const index: u32 = @intCast(n);
            if (c.role == .spoofer) continue;
            self.sendPing(c);
            self.startProof(c);
            try self.schedule(self.after(1.0 + self.rand().float(f64)), index, .retry);
            try self.schedule(self.after(self.o.keepalive_s * self.rand().float(f64)), index, .ping);
            if (self.o.reproof_s > 0) try self.schedule(self.after(self.o.reproof_s * (1 + self.rand().float(f64))), index, .reproof);
        }

        // Warm up until nearly everyone has proven or the time runs out.
        const warmup_end = start + @as(i128, self.o.warmup_s) * ns_per_s;
        while (nowNs() < warmup_end) {
            try self.pump(@min(nowNs() + 200 * ns_per_ms, warmup_end));
            if (self.provenHonest() * 1000 >= self.honest * 999) break;
        }
        self.warmup_ms = @intCast(@divTrunc(nowNs() - start, ns_per_ms));

        for (self.clients, 0..) |c, n| {
            const index: u32 = @intCast(n);
            switch (c.role) {
                .honest => try self.schedule(self.after(self.poisson(self.o.rate)), index, .send),
                .flooder => try self.schedule(nowNs(), index, .flood),
                .spoofer => try self.schedule(nowNs(), index, .spoof),
            }
        }

        self.measuring = true;
        self.measure_start = nowNs();
        const end = self.measure_start + @as(i128, self.o.duration_s) * ns_per_s;
        if (self.o.storm_at_s > 0) {
            try self.pump(self.measure_start + @as(i128, @intFromFloat(self.o.storm_at_s * @as(f64, @floatFromInt(ns_per_s)))));
            try self.storm();
        }
        try self.pump(end);
        self.measuring = false;
        // Stop sending and let frames in flight arrive.
        const drain_end = nowNs() + ns_per_s;
        self.queue.items.len = 0;
        while (nowNs() < drain_end) {
            var events: [256]linux.epoll_event = undefined;
            const n = linux.epoll_wait(self.epoll_fd, &events, events.len, 10);
            const count: isize = @bitCast(n);
            if (count <= 0) continue;
            for (events[0..@intCast(count)]) |ev| self.receive(ev.data.u32);
        }
        self.measured_ms = @intCast(@divTrunc(end - self.measure_start, ns_per_ms));
    }

    /// Every honest client moves to a new source port and proves again, as
    /// after a relay restart or a mass network change.
    fn storm(self: *Generator) !void {
        self.storm_start = nowNs();
        self.storm_pending = self.honest;
        for (self.clients[0..self.honest], 0..) |*c, n| {
            const index: u32 = @intCast(n);
            _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, @intCast(c.socket.fd), null);
            c.socket.close();
            try self.openSocket(c, index);
            self.sendPing(c);
            self.startProof(c);
            try self.schedule(self.after(1.0 + self.rand().float(f64)), index, .retry);
        }
    }

    fn report(self: *Generator, out: std.Io.File) !void {
        const lat = self.m.latencies_us.items;
        std.mem.sort(u32, lat, {}, std.sort.asc(u32));
        const pct = struct {
            fn at(values: []const u32, p: f64) u32 {
                if (values.len == 0) return 0;
                const idx: usize = @intFromFloat(@floor(p * @as(f64, @floatFromInt(values.len - 1))));
                return values[idx];
            }
        }.at;
        // Time from start until each client's first proof, in milliseconds.
        var proof_times = try self.allocator.alloc(u32, self.honest);
        defer self.allocator.free(proof_times);
        var proven: usize = 0;
        for (self.clients[0..self.honest]) |c| {
            if (!c.proven) continue;
            proof_times[proven] = @intCast(@divTrunc(c.first_proof_ns - self.start_ns, ns_per_ms));
            proven += 1;
        }
        std.mem.sort(u32, proof_times[0..proven], {}, std.sort.asc(u32));
        const proofs = proof_times[0..proven];
        const loss: f64 = if (self.m.sent == 0) 0 else 1.0 - @as(f64, @floatFromInt(self.m.received)) / @as(f64, @floatFromInt(self.m.sent));
        const seconds = @as(f64, @floatFromInt(self.measured_ms)) / 1000.0;
        var text: [2048]u8 = undefined;
        const json = try std.fmt.bufPrint(&text,
            \\{{"clients":{d},"flooders":{d},"spoofers":{d},"proven":{d},"proof_ms":{{"p50":{d},"p99":{d},"max":{d}}},"warmup_ms":{d},"measured_ms":{d},"sent":{d},"sent_to_unproven":{d},"received":{d},"duplicates":{d},"loss":{d:.6},"throughput_per_s":{d:.1},"latency_us":{{"p50":{d},"p95":{d},"p99":{d},"max":{d}}},"handshakes_sent":{d},"proofs":{d},"flood_sent":{d},"flood_received":{d},"spoof_sent":{d},"spoof_delivered":{d},"storm_reproven_ms":{?d},"send_errors":{d}}}
            \\
        , .{
            self.honest,            self.o.flooders,          self.o.spoofers,                                    proven,
            pct(proofs, 0.50),      pct(proofs, 0.99),        if (proofs.len > 0) proofs[proofs.len - 1] else 0,  self.warmup_ms,
            self.measured_ms,       self.m.sent,              self.m.sent_to_unproven,                            self.m.received,
            self.m.duplicates,      loss,                     @as(f64, @floatFromInt(self.m.received)) / seconds, pct(lat, 0.50),
            pct(lat, 0.95),         pct(lat, 0.99),           if (lat.len > 0) lat[lat.len - 1] else 0,           self.m.handshakes_sent,
            self.m.proofs,          self.m.flood_sent,        self.m.flood_received,                              self.m.spoof_sent,
            self.m.spoof_delivered, self.m.storm_reproven_ms, self.m.send_errors,
        });
        try out.writeStreamingAll(std.Io.Threaded.global_single_threaded.io(), json);
    }
};

fn raiseFileLimit(needed: u64) !void {
    var limit: linux.rlimit = undefined;
    _ = linux.getrlimit(.NOFILE, &limit);
    if (limit.cur >= needed) return;
    if (limit.max < needed) return error.FileLimitTooLow;
    limit.cur = needed;
    if (@as(isize, @bitCast(linux.setrlimit(.NOFILE, &limit))) < 0) return error.FileLimitTooLow;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const options = parseOptions(args) catch |err| {
        const usage =
            \\usage: relay-loadgen --relay <ip:port> --relay-key <base64 ed25519> [--clients N]
            \\       [--contacts K] [--rate per-client/s] [--payload bytes] [--warmup s] [--duration s]
            \\       [--keepalive s] [--reproof s] [--flooders N] [--flood-pps n] [--spoofers N]
            \\       [--spoof-pps n] [--storm-at s] [--seed n]
            \\
        ;
        try std.Io.File.stderr().writeStreamingAll(init.io, usage);
        return err;
    };
    try raiseFileLimit(options.clients + options.flooders + options.spoofers + 64);
    var gen = try Generator.init(init.gpa, options);
    try gen.run();
    try gen.report(std.Io.File.stdout());
}
