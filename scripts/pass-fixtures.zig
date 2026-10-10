//! Prints certificate ("pass") fixtures as JSON for cross-implementation tests:
//! src/identity/org.zig and tests/web/gateway.test.mjs check the same verdicts.
//! Deterministic: regenerate with
//!   zig build pass-fixtures > src/identity/testdata/passes.json
const std = @import("std");
const mg = @import("meshguard");
const Org = mg.identity.Org;
const Ed25519 = std.crypto.sign.Ed25519;

const ISSUED: i64 = 1_800_000_000;
const EXPIRES: i64 = ISSUED + 86_400;
const SKEW: i64 = 300;

fn keyPair(label: []const u8) !Org.OrgKeyPair {
    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &seed, .{});
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
}

fn wgKey(label: []const u8) [32]u8 {
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &key, .{});
    return key;
}

fn certificate(org: Org.OrgKeyPair, node: [32]u8, wg: ?[32]u8, issued: i64, expires: i64) !Org.NodeCertificate {
    var cert = Org.NodeCertificate{
        .version = if (wg != null) Org.CERT_VERSION_V2 else Org.CERT_VERSION_V1,
        .org_pubkey = org.public_key.toBytes(),
        .node_pubkey = node,
        .node_name = std.mem.zeroes([32]u8),
        .issued_at = issued,
        .expires_at = expires,
        .wg_pubkey = wg orelse std.mem.zeroes([32]u8),
    };
    try Org.signCertificate(&cert, org.secret_key);
    return cert;
}

const Case = struct {
    name: []const u8,
    cert: Org.NodeCertificate,
    node: [32]u8,
    wg: [32]u8,
    now: i64,
    expect: []const u8,
};

pub fn main(init: std.process.Init) !void {
    const org = try keyPair("pass-fixture-org");
    const other_org = try keyPair("pass-fixture-other-org");
    const issuer = try keyPair("pass-fixture-issuer");
    const node = (try keyPair("pass-fixture-node")).public_key.toBytes();
    const wg = wgKey("pass-fixture-wg");
    const now = ISSUED + 100;

    var delegated = try Org.issueDelegatedCertificateV2(org, issuer, node, wg, "", EXPIRES);
    delegated.issued_at = ISSUED;
    try Org.signCertificate(&delegated, issuer.secret_key);

    var bad_grant = try Org.issueDelegatedCertificateV2(other_org, issuer, node, wg, "", EXPIRES);
    bad_grant.issued_at = ISSUED;
    bad_grant.org_pubkey = org.public_key.toBytes();
    try Org.signCertificate(&bad_grant, issuer.secret_key);

    var tampered = try certificate(org, node, wg, ISSUED, EXPIRES);
    tampered.node_name[0] = 'x';

    const valid = try certificate(org, node, wg, ISSUED, EXPIRES);
    const cases = [_]Case{
        .{ .name = "valid v2", .cert = valid, .node = node, .wg = wg, .now = now, .expect = "ok" },
        .{ .name = "valid v1", .cert = try certificate(org, node, null, ISSUED, EXPIRES), .node = node, .wg = wg, .now = now, .expect = "ok" },
        .{ .name = "delegated v2", .cert = delegated, .node = node, .wg = wg, .now = now, .expect = "ok" },
        .{ .name = "never expires", .cert = try certificate(org, node, wg, ISSUED, 0), .node = node, .wg = wg, .now = EXPIRES * 2, .expect = "ok" },
        .{ .name = "expired within skew", .cert = valid, .node = node, .wg = wg, .now = EXPIRES + SKEW - 1, .expect = "ok" },
        .{ .name = "expired", .cert = valid, .node = node, .wg = wg, .now = EXPIRES + SKEW, .expect = "expired" },
        .{ .name = "issued in the future", .cert = valid, .node = node, .wg = wg, .now = ISSUED - SKEW - 1, .expect = "expired" },
        .{ .name = "untrusted org", .cert = try certificate(other_org, node, wg, ISSUED, EXPIRES), .node = node, .wg = wg, .now = now, .expect = "untrusted-org" },
        .{ .name = "another identity", .cert = valid, .node = wgKey("someone else"), .wg = wg, .now = now, .expect = "wrong-identity" },
        .{ .name = "another WireGuard key", .cert = valid, .node = node, .wg = wgKey("other wg"), .now = now, .expect = "wrong-wireguard-key" },
        .{ .name = "tampered", .cert = tampered, .node = node, .wg = wg, .now = now, .expect = "bad-signature" },
        .{ .name = "delegation grant from another org", .cert = bad_grant, .node = node, .wg = wg, .now = now, .expect = "bad-signature" },
    };

    var out: std.ArrayListUnmanaged(u8) = .empty;
    const a = init.gpa;
    defer out.deinit(a);
    var b64: [44]u8 = undefined;
    try out.print(a, "{{\n  \"trusted_orgs\": [\"{s}\"],\n  \"skew\": {d},\n  \"cases\": [\n", .{ std.base64.standard.Encoder.encode(&b64, &org.public_key.toBytes()), SKEW });
    for (cases, 0..) |c, i| {
        var wire: [Org.NodeCertificate.WIRE_SIZE]u8 = undefined;
        c.cert.serialize(&wire);
        const len: usize = if (c.cert.version == Org.CERT_VERSION_V1) Org.V1_CERT_WIRE_SIZE else wire.len;
        var node_b64: [44]u8 = undefined;
        var wg_b64: [44]u8 = undefined;
        try out.print(a, "    {{\"name\": \"{s}\", \"pass\": \"{x}\", \"public_key\": \"{s}\", \"wg_public_key\": \"{s}\", \"now\": {d}, \"expect\": \"{s}\"}}{s}\n", .{
            c.name,
            wire[0..len],
            std.base64.standard.Encoder.encode(&node_b64, &c.node),
            std.base64.standard.Encoder.encode(&wg_b64, &c.wg),
            c.now,
            c.expect,
            if (i + 1 < cases.len) "," else "",
        });
    }
    try out.appendSlice(a, "  ]\n}\n");
    try std.Io.File.stdout().writeStreamingAll(init.io, out.items);
}
