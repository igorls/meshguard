# Performance Optimization Roadmap

This document captures the current performance profile, what has been tried, what worked, and what the remaining optimization opportunities are.

## Current Standing

| Metric            | Value                                             |
| ----------------- | ------------------------------------------------- |
| **Download**      | 3.93 Gbps                                         |
| **Upload**        | 3.94 Gbps                                         |
| **Latency (avg)** | 0.194 ms                                          |
| **Test setup**    | LXC containers, localhost veth, 8 encrypt workers |

## Architecture Overview

```
                         TX PATH (Upload)
                    ┌─────────────────────────┐
 TUN read ──► GSO split ──► encrypt (N workers) ──► sendmmsg ──► UDP
                    │            │                       │
                    │  12.5% CPU │  ~1% CPU              │
                    └─────────────────────────┘

                         RX PATH (Download)
                    ┌─────────────────────────┐
 UDP ──► recvGRO ──► classify ──► decrypt ──► coalesce ──► writev(TUN)
   │        │            │           │             │
   │  GRO   │  single    │   ~1%     │   vnet_hdr  │
   │  64KB  │  thread    │   CPU     │   GSO       │
                    └─────────────────────────┘
```

## Flamegraph Profile (3.87 Gbps sender)

| % CPU | Function         | Path                                   | Optimizable?                      |
| ----- | ---------------- | -------------------------------------- | --------------------------------- |
| 12.5% | `gsoSplit`       | TX: GSO packet splitting               | ❌ Compiler-optimal (SIMD memcpy) |
| 9.5%  | `memset`         | Buffer zeroing (nonces, padding, cmsg) | ❌ Structurally required          |
| 5.6%  | `memcpy`         | Data copies (headers, payloads)        | ❌ Compiler-optimal               |
| 3.9%  | kernel copy      | `_copy_to/from_iter` (recvmsg/sendmsg) | 🔶 Reducible with io_uring        |
| 1.6%  | syscall overhead | `entry_SYSRETQ`                        | 🔶 Reducible with io_uring        |
| 1.1%  | libsodium        | ChaCha20-Poly1305 (AVX2)               | ✅ Already hardware-accelerated   |

**Key insight**: Crypto is ~1% of CPU. The bottleneck is data movement and syscall overhead.

## What Has Been Tried

### ✅ Successful

| Optimization                   | Impact               | Commit    |
| ------------------------------ | -------------------- | --------- |
| UDP GRO on control socket      | **+27% DL, +31% UL** | `a36527d` |
| SO_BUSY_POLL (50μs)            | +1% DL, +2% UL       | `b362320` |
| GRO drain loop                 | +1% DL, +2% UL       | `b362320` |
| CryptoQueue cache-line padding | +1% DL, +2% UL       | `b362320` |

### ❌ Failed (Reverted)

| Optimization                       | Result      | Why                                                        |
| ---------------------------------- | ----------- | ---------------------------------------------------------- |
| SO_REUSEPORT parallel RX           | Neutral     | Single-peer = one UDP 4-tuple, kernel hashes to one worker |
| DecryptQueue dispatch              | **-42% UL** | Per-packet memcpy + CAS overhead > crypto savings          |
| gsoSplit header merge (3→2 memcpy) | **-14%**    | Runtime-sized copy defeated compiler SIMD codegen          |
| GROReceiver cmsg_buf zero removal  | **-14%**    | Stale cmsg data broke GRO segment_size parsing             |

## Future Optimization Opportunities

### Tier 1: High Impact (Architectural)

#### 1. `io_uring` for UDP Receive

**Expected impact**: +15-30% download  
**Complexity**: Medium  
**Risk**: Low (fallback to poll+recvmsg)

Replace the `poll()` → `recvGRO()` double-syscall with `io_uring` completion-based async I/O. Currently 5.5% of CPU is in syscall overhead (`entry_SYSRETQ` + kernel copies). `io_uring` eliminates the poll() syscall entirely and can submit multiple recvmsg operations in one batch.

**Implementation plan**:

1. Create `io_uring` instance with `IORING_SETUP_SQPOLL` for kernel-side polling
2. Submit `IORING_OP_RECVMSG` with `IOSQE_BUFFER_SELECT` for zero-copy receive
3. Process completions in the control loop instead of poll+recvmsg
4. Fallback to current GRO path if `io_uring` unavailable (kernel < 5.6)

**Files to modify**: `src/main.zig` (userspaceEventLoop), `src/net/io_uring.zig` (already has `IoUringReader`)

#### 2. Parallel RX with Per-Worker TUN Queues

**Expected impact**: +50-100% download (multi-core scaling)  
**Complexity**: High  
**Risk**: Medium (ordering, replay window contention)

The current architecture uses a single control thread for all UDP receive + decrypt. With `IFF_MULTI_QUEUE` TUN, multiple threads could each:

1. Read from the same GRO-enabled UDP socket (via `SO_REUSEPORT` — only helps with multi-peer)
2. Decrypt packets independently
3. Write to their own TUN queue

**Challenges**:

- Single-peer: all packets share one UDP 4-tuple → kernel can't distribute
- WireGuard replay window uses a mutex (`replay_lock`) → serializes single-peer decrypt
- Packet ordering must be preserved for TCP flows

**When this makes sense**: Multi-peer workloads where different peers hash to different workers.

#### 3. Direct TUN GSO Write (RX Path)

**Expected impact**: +10-20% download  
**Complexity**: Medium  
**Risk**: Low

Instead of decrypting individual packets and then `writeCoalescedToTun`, construct a `virtio_net_hdr` + coalesced payload and write it as a single GSO super-packet to TUN. The kernel would handle segmentation.

Currently `writeCoalescedToTun` already does TCP coalescing + vnet_hdr writes, but this could be optimized further by:

1. Avoiding per-packet `writev` for small batches
2. Using `io_uring` for TUN writes (batch submit)
3. Increasing coalescing window beyond current 64 packets

**Files to modify**: `src/main.zig` (writeCoalescedToTun), `src/net/offload.zig`

### Tier 2: Medium Impact (Protocol)

#### 4. Connected UDP Sockets Per Peer

**Expected impact**: +5-10% upload  
**Complexity**: Low  
**Risk**: Medium (mesh protocol changes needed)

Use `connect()` on per-peer UDP sockets so the kernel caches the route lookup. Currently every `sendmsg` does a full route lookup.

**Challenge**: Requires one socket per peer + multiplexing logic. The main gossip socket must remain unconnected for SWIM/STUN/handshake packets from unknown sources.

**Implementation plan**:

1. After WireGuard handshake completes, open a connected UDP socket to the peer's endpoint
2. Route transport packets through the connected socket
3. Keep the main socket for control-plane (SWIM, handshakes, STUN)
4. Handle endpoint changes (NAT rebinding) by reconnecting

#### 5. Kernel-Assisted Crypto (AF_ALG)

**Expected impact**: Potentially +10-20% for non-AVX2 hardware  
**Complexity**: Low  
**Risk**: Low

Use Linux `AF_ALG` socket interface to offload ChaCha20-Poly1305 to the kernel's crypto subsystem, which may use hardware acceleration on some platforms.

**Note**: On x86_64 with AVX2, libsodium is already optimal (~1% CPU). This primarily benefits ARM or older x86 without SIMD.

### Tier 3: Speculative

#### 6. XDP/eBPF Packet Classification

**Expected impact**: Unknown (potentially large)  
**Complexity**: Very High  
**Risk**: High

Attach an XDP program to classify incoming UDP packets at the NIC driver level, before they reach the kernel network stack. WireGuard transport packets (type 4) could be redirected to a dedicated receive queue, bypassing the normal socket path entirely.

#### 7. DPDK Bypass

**Expected impact**: +100-300% (eliminates kernel entirely)  
**Complexity**: Very High  
**Risk**: High (loses kernel networking stack)

Full kernel bypass using DPDK for packet I/O. Eliminates all syscall overhead and kernel copies. Only viable for dedicated appliance deployments, not general-purpose mesh nodes.

## Methodology

### Benchmarking

```bash
# Single-stream throughput (10s, 8 encrypt workers)
bash docker/lxc-mg-bench.sh 10 8

# Compare against wireguard-go, kernel WG, boringtun
bash docker/lxc-4way-bench.sh 10

# Flamegraph + perf report (in-container, no sudo)
bash docker/perf-capture.sh 10 8
```

### Profiling Tips

1. Build with `ReleaseSafe` (not `ReleaseFast`) for perf — preserves frame pointers
2. Use `perf record -F 999 --call-graph dwarf,16384` for full stack traces
3. The `perf-capture.sh` script runs perf inside the LXC container (root, no `perf_event_paranoid` issues)
4. Look at `bench-results/flamegraph.svg` for visual hotspot analysis
5. Look at `bench-results/perf-report.txt` for function-level breakdown

### Key Learnings

1. **Don't merge fixed-size memcpy calls** — the compiler generates SIMD intrinsics for known sizes. Runtime-sized copies use generic memcpy which is slower.
2. **cmsg buffers must be zeroed** — stale cmsg data from previous recvmsg calls causes incorrect GRO segment_size parsing.
3. **Per-packet cross-thread dispatch is expensive** — memcpy + CAS + condvar overhead for a 1500-byte packet exceeds the cost of just decrypting it inline.
4. **SO_REUSEPORT doesn't help single-peer VPN** — all packets share the same UDP 4-tuple, so the kernel hashes them to one worker.
5. **Crypto is not the bottleneck** — with AVX2 libsodium, ChaCha20-Poly1305 is ~1% CPU. The bottleneck is syscall overhead and data movement.
