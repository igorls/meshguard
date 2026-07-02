# meshguard — Adversarial Networking Security Review

**Date:** 2026-06-06  ·  **Scope:** src/net, src/nat, src/discovery, src/protocol, src/wireguard

**Method:** Multi-agent adversarial workflow — 2 recon agents established the build/ReleaseFast baseline and unauthenticated attack surface; 11 specialized hunters (one attacker-lens per subsystem) found 40 candidate issues; each was attacked by 3 independent skeptic lenses (reachability/correctness/exploitability, majority-vote to survive); 32 confirmed, 8 refuted. 135 agents total.

**Independent verification:** Both CRITICAL findings (C1 base64 stack OOB, C2 unsigned org-revoke) were re-checked line-by-line by the lead against the live source and the Zig 0.16.0 std base64 decoder; both confirmed exactly as described.

> ⚠️ This document describes vulnerabilities, most now REMEDIATED in the working tree (see status below). Treat as sensitive until released.

## Remediation status (applied 2026-06-06)

All Criticals + Highs + the two cheapest Mediums were fixed in the working tree, each with a regression test. Verified across `zig build test`, Debug, **ReleaseFast** (shipping), and ReleaseSafe.

| ID | Issue | Fix | Test |
|----|-------|-----|------|
| C1 | base64 token stack OOB | bound decoded size vs output before decode (`coordinated_punch.zig`) | ✅ |
| C2 | unsigned org revoke/alias/vouch | Ed25519-verify canonical payload + require trusted org (`swim.zig`/`codec.zig`) | ✅ |
| H1 | inner-source-IP spoofing | RX cryptokey-routing check in `decryptTransport` (`device.zig`) | ✅ |
| H2 | gossip instant-evicts third parties | downgrade dead/leave/suspect to local suspicion + own-probe confirm (`swim.zig`) | ✅ |
| H3 | unbounded membership growth | `MAX_MEMBERS` cap + reclaim non-alive slots (`membership.zig`) | ✅ |
| H4 | handshake flood (MAC1 public) | per-source + global token bucket before X25519 (`device.zig`); **cookie/MAC2 = follow-up** | ✅ |
| H5 | DNS spoofing | random TXID + `connect()` source filter + TXID/question validation (`dns.zig`) | ✅ |
| H6 | peer-table data race / UAF | `WgDevice` RwLock (write: mutate, read: data plane); pipeline + decrypt paths | ✅ (unit) |
| H7 | FFI/membership map race | `MembershipTable` RwLock; single-writer model, read-locked external readers | ✅ (unit) |
| H8 | `expireSuspected` use-after-return | caller-owned buffer instead of stack-slice return (`membership.zig`) | ✅ |
| M5 | IPv6 bypasses service filter | classify IPv6 + fail-closed `allowPacket` (`policy.zig`) | ✅ |
| M6 | gossip alive ignores Lamport | gossip can no longer clear local suspicion / resurrect (`swim.zig`) | ✅ |

**Deferred (with rationale in `SECURITY.md`):** WireGuard cookie/MAC2 for source-spoofed handshake floods (H4 follow-up); legacy serial-encrypt path locking (H6 follow-up, non-UAF); the remaining Mediums/Lows (M1–M4, M7, L1–L9 — STUN/UPnP corroboration, SSDP CRLF, relay auth, punch/NTP source binding). Concurrency fixes (H6/H7) are reasoned + unit-tested but warrant a multi-node race/TSan soak before being relied on under adversarial churn.

---

## Executive Summary

meshguard multiplexes WireGuard, SWIM gossip, STUN/hole-punch and app-relay onto a single UDP port (51821); every byte after the first classifier byte is attacker-controlled and processed before authentication. The shipped binary is built -Doptimize=ReleaseFast, so Zig safety checks are off and OOB writes/bad casts/overflow are silent corruption, not panics. This turns parsing/state-machine defects into memory-safety and DoS issues in production. I verified the top items by reading source and building reproducers, de-duplicated 32 confirmed findings to distinct root causes, and excluded 8 refuted items.

## CRITICAL

### C1. Stack OOB write decoding an attacker-supplied mg:// punch token — src/nat/coordinated_punch.zig:324
Bug class: OOB stack write (RCE-class). Trigger: victim runs `meshguard connect`/`connect --join <token>`; attacker supplies mg:// + ~150-251 base64url chars (out-of-band token). Impact: base64UrlDecode decodes into bin[106], bounding only input; std base64 Decoder.decode tail loop writes dest[dest_idx] with no dest_idx<dest.len guard (std/base64.zig:275; WithIgnore at 348 does check). decoded_len!=106 runs after the overflow. Reproduced: 200 'A' -> decoded_len=150 into a 106-byte array (silent ReleaseFast; panic at base64.zig:275 in Debug); max ~188 bytes, attacker-controlled length and content before any signature check. Fix: compute calcSizeForSlice and reject if > output.len before decode; require exactly 142 base64 chars.

### C2. Org trust messages accepted without Ed25519 signature verification — src/discovery/swim.zig:591 (gate :486; decode codec.zig:495)
Bug class: spoofing/auth bypass. Dedupe of codec-parse-1 + swim-state-1 + memsafety-sweep-1. Trigger: one UDP datagram [0x42][org_pubkey][victim_pubkey][reason][lamport][64B sig]; org pubkey is public, signature never checked. Impact: decoders copy the sig but no handler verifies it; the only gate isAuthorizedPeer returns true when enforce_trust=false (default) and for any pubkey when trusted_org_count>0 (swim.zig:203). handleOrgRevoke adds the victim to revoked_nodes (permanent rejoin bar) and calls markDead+onPeerDead -> wgOnPeerDead (main.zig:1790) -> removePeer, dropping the tunnel; repeat to partition the mesh. org_alias_announce enables alias hijack via Lamport race. Fix: reconstruct the signed bytes and Ed25519-verify before acting; reject org_pubkey not in trusted_orgs; gate revoke on isOrgAuthorizedPeer.

## HIGH

### H1. No AllowedIPs inner-source-IP check on decrypt->TUN — src/wireguard/device.zig:459 (writes main.zig:2669/2714/2798/2950, wg_interop.zig:198)
Dedupe of wg-transport-1 + tun-ip-spoof-1 + memsafety-sweep-4. Trigger: an admitted peer sends a Type-4 packet whose decrypted inner source IP is any value. Impact: decryptTransport returns the peer slot but no caller validates inner source vs peers[slot].mesh_ip/mesh_ip6; the only check (parseTransportHeader + service_filter) inspects destination only; allowed_ips is consumed solely by the kernel-offload path; the userspace plane (default; only path on macOS/Windows/FreeBSD) ignores it. A peer impersonates any mesh source, bypassing source ACLs and poisoning ARP/conntrack. Fix: drop unless inner source equals the peer mesh IP, enforced inside decryptTransport.

### H2. Gossip dead/leave/suspect applied to arbitrary subject with no per-subject auth — src/discovery/swim.zig:1088
Trigger: Ping/Ack whose sender passes the open-by-default gate, gossip entry subject=victim event=.dead/.leave/.suspect; GossipEntry has no signature. Impact: .dead/.leave immediately markDead+onPeerDead on the subject (same teardown as C2) with no suspicion phase or incarnation check; the gate validates only the sender, so one malicious member evicts every other. Fix: require local failure confirmation before markDead or signed .leave; honor Lamport; gate subjects through trust.

### H3. Unbounded membership-table growth from unauthenticated gossip — src/discovery/membership.zig:99 (registration swim.zig:846)
Dedupe of swim-state-2 + memsafety-sweep-2 + concurrency-4. Trigger: stream of Pings/Acks (default enforce_trust=false) with distinct random subject pubkeys, up to 8/datagram. Impact: upsert does an uncapped peers.put; no MAX_PEERS (remove() only in a test at membership.zig:270); markDead never frees, so fakes accumulate and are scanned every tick (linear randomAlivePeer, quadratic checkUnreachablePeers) -> OOM + CPU blowup. Fix: cap size + evict stale dead; remove() dead peers; register only individually-authorized subjects under trust.

### H4. No rate limit/cookie on inbound WG handshake; MAC1 key gossiped in cleartext — src/wireguard/device.zig:384 (MAC1 noise.zig:604; cookie no-ops main.zig:2752/2833/2985)
Trigger: attacker learns the WG static pubkey from cleartext gossip (codec.zig:235), forges valid-MAC1 inits, floods. Impact: MAC1 is the only gate but its key is public; each MAC1-passing packet forces an X25519 before AEAD fails; handleInitiation runs on the single thread shared with SWIM/transport/TUN, so a flood burns CPU and stalls the control plane; MAC2 never checked, cookies are no-ops. Fix: implement cookie/MAC2 under-load; per-source token bucket before the X25519.

### H5. DNS resolver accepts spoofed responses — src/net/dns.zig:451 (TXID :138/:156; recv :440/:444)
Trigger: off-path flood of the ephemeral port within 2s, or a malicious/on-path resolver. Impact: query IDs are compile-time constants (0xABCD/0xCDEF) never validated; socket never connect()ed; recvfrom passes null source; parsers never check TXID or echoed question. Forged A/TXT answers feed bootstrap seed endpoints -> peer injection (open trust) or bootstrap DoS. Config-gated (--dns/hostname seeds). Fix: random per-query TXID + verify; connect()/verify source; validate the question.

### H6. Cross-thread data race / UAF on WgDevice peer table — src/wireguard/device.zig:344 (reads main.zig:2298-2304/2250-2254)
Trigger: malicious peer drives a peer DEAD while data flows; removePeer secureZeros keys and nils peers[slot] concurrently with workers encrypting that tunnel. Impact: no lock over peers[]/index_map/key bytes (only per-tunnel replay_lock/atomic counter); a worker captures &active_tunnel past the null checks, then the key is zeroed mid-encrypt -> torn read/UAF or zero-key ciphertext on the wire under ReleaseFast. Fix: RwLock (shared workers/exclusive remove) or epoch/RCU retirement.

### H7. FFI host-thread queries race the SWIM thread on a non-thread-safe AutoHashMap — src/meshguard_ffi.zig:531 (also :670 and status/peer/debug exports)
Trigger: host calls a query/send export while the SWIM loop registers fresh pubkeys (peers.put grow/rehash/free). Impact: exports read membership.peers lock-free; a get/iterator concurrent with a resize dereferences freed/relocated buckets -> crash, wrong peer, or freed-memory read in the host. Attacker amplifies via cheap peer churn; FFI deployment only. Fix: mutex/RwLock around all membership.peers access, or marshal onto the SWIM thread.

### H8. expireSuspected returns a slice into its own stack frame (use-after-return) — src/discovery/membership.zig:216 (consumers swim.zig:296-311/355-367)
Trigger: any time >=1 peer transitions SUSPECTED->DEAD on timeout (attacker-forceable by withholding ACKs). Impact: returns to_kill_buf[0..count] backed by a reclaimed frame; the caller loop print/onPeerDead/enqueueGossip frames overwrite it (reproduced corruption after index 0). Honest scoping: markDead runs before the return, so correct peers are marked dead; garbage keys then miss the hashmap (no-op), so the real effect is missed tunnel teardown / lost dead-gossip for the 2nd..Nth simultaneous expiry, not arbitrary corruption. High for the memory-safety defect, bounded impact. Fix: make to_kill_buf a field, pass an owned buffer + return count, or do side-effects while the buffer is live.

## MEDIUM

- M1 Malicious/MITM STUN server dictates the gossiped public endpoint — src/nat/stun.zig:195. discover() trusts the first responder (no sanity check/quorum) and infers NAT type from one server; gossiped mesh-wide + in punch tokens, redirecting traffic (reachability DoS; WG auth prevents content MITM). Fix: two-server agreement, reject reserved addresses.
- M2 Rogue IGD GetExternalIPAddress sets the gossiped public endpoint — src/nat/upnp.zig:501. Attacker-chosen external IP gossiped as .public (no validation/STUN corroboration), redirecting peers. LAN+NAT gated, recoverable. Fix: reject reserved IPs, corroborate with STUN.
- M3 Rogue SSDP responder controls UPnP TCP connect target + CRLF-injects SOAP — src/nat/upnp.zig:268 and :438/:345. gateway_ip from spoofable source, port/path from attacker LOCATION; controlURL copied verbatim into the request line. Honest scoping: connect IP pinned to packet source, no secrets in bodies, LAN attacker already stronger. Fix: validate SSDP source (RFC1918, port 1900, host==responder); reject CRLF.
- M4 Unauthenticated 0x50 app-message relay (reflection/laundering before auth) — src/discovery/swim.zig:502/534. Dedupe of codec-parse-2 + memsafety-sweep-3. handleAppMessage runs before the auth gate; node forwards the verbatim datagram (1:1, no amplification) to a named peer. Fix: authenticate sender + rate-limit behind the gate.
- M5 IPv6 decrypted packets bypass the service filter — src/services/policy.zig:478. parseTransportHeader is IPv4-only and returns null for IPv6, so callers skip the filter and write to TUN; default-deny leaks all IPv6. Fix: parse IPv6, fail-closed until done.
- M6 markAlive/applyGossip-alive override liveness ignoring Lamport — src/discovery/membership.zig:121; swim.zig:1055-1056. Anti-replay/incarnation bypass: pin a dead peer .alive or reset suspected_at_ns; upsert enforces Lamport but the liveness mutators do not. Fix: Lamport-order all liveness transitions.
- M7 Coordinated-punch loop accepts a probe from any source — src/nat/coordinated_punch.zig:512. Matches only magic+nonce, latches the spoofed source as the peer endpoint -> seeds file. Honest scoping: writes a seed file not the live endpoint; WG auth prevents MITM; recoverable. Fix: require source==expected peer; bind nonce to sender pubkey.

## LOW

- L1 codec.zig:353 — decodePing/Ack report the declared gossip_count after early break, exposing undefined slots; refuted as exploitable (buffer zeroes; applyGossip drops zero-pubkey; out-of-range enum switch was a no-op). Fix: running counter + else=>return.
- L2 tunnel.zig:211 — decrypt() never enforces REJECT_AFTER_MESSAGES (time-only); a keyed peer can park its RX window near 2^64; no memory unsafety. Fix: reject counter>=REJECT_AFTER_MESSAGES, signal rekey.
- L3 swim.zig:866 — each new subject enqueues 2 gossip slots, 6x rebroadcast, no dedup; refuted as amplification (fixed 5s cadence, 8-entry cap); harm bounded by H3. Fix: enqueue only confirmed peers; dedup.
- L4 noise.zig:381 — forged handshake response forces 2 X25519 before AEAD; on-path only; dominated by H4. Fix: verify MAC1 on responses first.
- L5 coordinated_punch.zig:354 — NTP response accepted with no source/origin check (bounded read); interactive connect only; skews scheduling. Fix: validate source, echo+verify a random Transmit Timestamp.
- L6 dns.zig:284 — A/TXT parsers ignore QDCOUNT; no memory unsafety; nothing beyond H5. Fix: honor QDCOUNT.

## Systemic patterns

1. Authentication runs after action on the shared port (org messages, 0x50 relay, holepunch probes, gossip subjects mutate state before/without the gate, which is open by default and a no-op in org mode).
2. Signatures decoded but never verified (C2 org messages; H2 unsigned gossip). Verifiers exist in keys.zig/org.zig but are not called.
3. Missing cryptokey-routing/source binding (H1 inner source IP, M1/M2 STUN/UPnP endpoint, M3 SSDP, M7 punch probe, H5/L6 DNS) — all trusted without binding to identity.
4. No bounds on attacker-grown state, no eviction (H3); the same map read lock-free across threads (H6/H7).
5. ReleaseFast turns parser bugs into corruption (C1 base64 OOB, H8 use-after-return are silent in production).
6. No DoS budget on expensive crypto (H4/L4 X25519 on unauthenticated input on the single control thread; cookie/MAC2 absent).

## Recommended hardening checklist

- C1: bound base64 decode output; validate exact token length before decode.
- C2/H2: Ed25519-verify all org messages; confirm locally (or require subject signature) before acting on third-party dead/leave; trust-gate gossip subjects.
- H1/M5: enforce inner-source-IP==peer AllowedIP on every decrypt->TUN write; parse IPv6 (fail-closed).
- H3: cap membership + evict stale dead; rate-limit registration per source.
- H4/L4: cookie/MAC2 under-load; verify MAC1 on responses; per-source token bucket before X25519.
- H5/L6: random DNS TXID, connected socket/source check, question+TXID validation, honor QDCOUNT.
- H6/H7: RwLock (or RCU/epoch) over the peer table and FFI membership map; never free tunnel state while a worker holds a reference.
- H8: eliminate the stack-slice return from expireSuspected.
- M1/M2: cross-validate STUN/UPnP endpoints; reject reserved addresses; two-source agreement.
- M3: validate SSDP source; sanitize controlURL/host for CRLF.
- M4: authenticate + rate-limit the 0x50 relay behind the gate.
- M6: Lamport-order liveness transitions.
- M7/L5: bind punch/NTP responses to expected source/nonce.
- Global: consider ReleaseSafe for the parse/dispatch path; move all authorization ahead of handler dispatch; make enforce_trust default-on/fail-closed.

---

## Appendix A — all 32 confirmed findings (raw, by hunter dimension)

_Counts: {'raw': 40, 'confirmed': 32, 'refuted': 8}  ·  by consensus severity: {'critical': 3, 'medium': 11, 'low': 9, 'high': 9}_


### codec-fuzz (1)
- **[low]** decodePing/decodeAck report trusted declared gossip_count while loop writes fewer entries — reads uninitialized GossipEntry stack memory — `src/protocol/codec.zig:353` (lenses real 2/3, reach 3/3, class OOB-read)

### codec-parse (2)
- **[critical]** Org trust messages (alias/revoke/vouch) carry an Ed25519 signature that is decoded but NEVER verified — forged org_cert_revoke evicts arbitrary peers — `src/protocol/codec.zig:495` (lenses real 3/3, reach 3/3, class spoofing)
- **[medium]** Unauthenticated 0x50 app-message relay forwards attacker bytes to a third peer before any auth check (reflection/amplification) — `src/discovery/swim.zig:534` (lenses real 3/3, reach 3/3, class amplification)

### concurrency (4)
- **[high]** Cross-thread data race / use-after-free on WgDevice peer table (control thread removePeer vs data-plane worker threads) — `src/wireguard/device.zig:344` (lenses real 3/3, reach 3/3, class UAF)
- **[medium]** expireSuspected returns a slice into its own stack frame (use-after-return) — `src/discovery/membership.zig:216` (lenses real 3/3, reach 3/3, class UAF)
- **[high]** FFI: host-thread queries race the SWIM event-loop thread on a non-thread-safe AutoHashMap — `src/meshguard_ffi.zig:531` (lenses real 3/3, reach 3/3, class race)
- **[medium]** Unbounded SWIM membership-table growth from unauthenticated pings (memory exhaustion) — `src/discovery/swim.zig:846` (lenses real 3/3, reach 3/3, class unbounded-growth)

### dns-parse (2)
- **[high]** DNS resolver accepts spoofed responses: unconnected socket + no source check + no transaction-ID validation (predictable constant TXID) — `src/net/dns.zig:451` (lenses real 3/3, reach 3/3, class spoofing)
- **[low]** DNS A/TXT parsers ignore qdcount and always skip exactly one question, causing answer-section desync on attacker-crafted responses — `src/net/dns.zig:284` (lenses real 3/3, reach 3/3, class state-machine)

### memsafety-sweep (4)
- **[high]** Forged org_cert_revoke evicts arbitrary peers (no Ed25519 signature verification on org messages) — `src/discovery/swim.zig:591` (lenses real 3/3, reach 3/3, class spoofing)
- **[medium]** Unbounded membership hashmap growth from attacker-chosen gossip subject pubkeys (memory-exhaustion DoS) — `src/discovery/swim.zig:846` (lenses real 3/3, reach 3/3, class unbounded-growth)
- **[low]** Unauthenticated app-message relay forwards attacker bytes to a third peer before any auth check — `src/discovery/swim.zig:502` (lenses real 3/3, reach 3/3, class amplification)
- **[medium]** Decrypted transport packets written to TUN with no inner source-IP validation (cross-peer source spoofing) — `src/wireguard/device.zig:459` (lenses real 3/3, reach 3/3, class spoofing)

### nat-stun-punch (5)
- **[critical]** Stack buffer overflow decoding an attacker-supplied mg:// punch token (base64UrlDecode overruns 106-byte bin buffer) — `src/nat/coordinated_punch.zig:324` (lenses real 3/3, reach 3/3, class OOB-write)
- **[medium]** Coordinated-punch loop accepts a probe from ANY source address (endpoint hijack via spoofed MGCP probe) — `src/nat/coordinated_punch.zig:512` (lenses real 3/3, reach 3/3, class spoofing)
- **[low]** Unauthenticated 4-byte MGHP probe forces onPeerPunched / premature direct-connection state — `src/discovery/swim.zig:445` (lenses real 3/3, reach 3/3, class spoofing)
- **[medium]** Malicious/MITM STUN server fully dictates the node's learned public endpoint (gossiped to all peers) — `src/nat/stun.zig:195` (lenses real 3/3, reach 3/3, class spoofing)
- **[low]** NTP response accepted without transaction/origin validation; skews punch scheduling — `src/nat/coordinated_punch.zig:354` (lenses real 3/3, reach 3/3, class spoofing)

### nat-upnp (3)
- **[low]** Rogue/spoofed SSDP responder fully controls TCP connect target (IP via source addr, port+path via LOCATION) — SSRF primitive with no LAN/private-IP/source-port validation — `src/nat/upnp.zig:268` (lenses real 3/3, reach 3/3, class spoofing)
- **[medium]** HTTP request-line / header (CRLF) injection via unsanitized controlURL and LOCATION host from untrusted IGD — `src/nat/upnp.zig:438` (lenses real 3/3, reach 3/3, class spoofing)
- **[medium]** Rogue IGD's GetExternalIPAddress response sets the node's gossiped public endpoint, redirecting mesh peers — `src/nat/upnp.zig:501` (lenses real 3/3, reach 3/3, class spoofing)

### swim-state (5)
- **[critical]** Org messages (revoke/vouch/alias) accepted without Ed25519 signature verification — forged org_cert_revoke evicts any peer & tears down its WireGuard tunnel — `src/discovery/swim.zig:591` (lenses real 3/3, reach 3/3, class spoofing)
- **[high]** Unbounded membership-table growth from unauthenticated gossip — memory exhaustion via fake peer injection — `src/discovery/membership.zig:99` (lenses real 3/3, reach 3/3, class unbounded-growth)
- **[high]** Gossip dead/leave/suspect applied to arbitrary subject with no per-subject authentication — any peer can kill/suspect any other peer — `src/discovery/swim.zig:1088` (lenses real 3/3, reach 3/3, class state-machine)
- **[medium]** markAlive / applyGossip alive overrides peer state ignoring Lamport — attacker resurrects a dead peer and erases suspicion — `src/discovery/membership.zig:121` (lenses real 3/3, reach 3/3, class state-machine)
- **[low]** Gossip-triggered fanout amplification — one inbound packet causes a broadcast wave (enqueueGossip on every new/expired peer with no dedup) — `src/discovery/swim.zig:866` (lenses real 3/3, reach 3/3, class amplification)

### tun-ip-spoof (2)
- **[high]** No AllowedIPs / inner-source-IP validation on decrypt→TUN ingress: any peer can spoof any mesh source IP (cross-tenant impersonation, service-policy bypass) — `src/main.zig:2669` (lenses real 3/3, reach 3/3, class spoofing)
- **[medium]** IPv6 decrypted packets bypass the service filter entirely (IPv4-only transport-header parser misparses/skips IPv6) — `src/services/policy.zig:478` (lenses real 3/3, reach 3/3, class state-machine)

### wg-handshake (2)
- **[high]** No rate limit or cookie defense on inbound handshake initiation; MAC1 anti-DoS gate is defeated because WG static pubkeys are gossiped in cleartext, enabling per-packet X25519 CPU exhaustion of the single control-plane thread — `src/wireguard/device.zig:384` (lenses real 3/3, reach 3/3, class amplification)
- **[low]** Forged handshake response forces two X25519 scalarmults before authentication fails (secondary CPU-amplification for an on-path attacker) — `src/wireguard/noise.zig:381` (lenses real 3/3, reach 3/3, class amplification)

### wg-transport (2)
- **[high]** Decrypted inner IP packet written to TUN with no AllowedIPs / inner-source-IP check (cross-tenant spoofing) — `src/wireguard/device.zig:459` (lenses real 3/3, reach 3/3, class spoofing)
- **[low]** Receive path never enforces REJECT_AFTER_MESSAGES on the inbound counter — `src/wireguard/tunnel.zig:211` (lenses real 3/3, reach 3/3, class state-machine)
