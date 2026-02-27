# Bolt Journal

## 2024-05-22 - Initial Setup
**Learning:** Performance optimization task started.
**Action:** Investigating hot paths for optimization opportunities.

## 2024-05-22 - GSO Optimization Analysis
**Learning:** The project implements a custom `ZeroCopyGSOSender` in `src/net/batch_udp.zig` which constructs `sendmsg` calls with `UDP_SEGMENT` cmsg.
**Insight:** `ZeroCopyGSOSender.sendGSO` uses a hardcoded `GSO_MAX_SIZE = 15000` cap in `src/net/batch_udp.zig` to stay under "veth's EMSGSIZE limit".
**Opportunity:** The `GSO_MAX_SIZE` check in `append` is:
```zig
if (self.used >= 64 or self.total_bytes + data.len > GSO_MAX_SIZE) return false;
```
However, the `sendGSO` function constructs the `msghdr` but the `append` function doesn't actually check if the *individual* segment size matches the `segment_size` already set. Wait, `append` sets `segment_size` on the first packet. It implicitly assumes all subsequent packets are the same size (which is true for GSO).

## 2024-05-22 - Zero-Copy Optimization Candidate
**Learning:** In `src/wireguard/tunnel.zig`, `encrypt` copies plaintext to output buffer before encrypting in-place.
**Insight:** `Tunnel.encryptPreassigned` avoids this copy, and `tunReaderPipeline` uses it. So the main data path is already optimized for zero-copy.

**Learning:** `src/net/pipeline.zig` defines `PacketBuffer` with `align(CACHE_LINE)`.
```zig
pub const PacketBuffer = struct {
    data: [2048]u8 align(CACHE_LINE) = undefined,
    // ...
};
```
This is good.

## 2024-05-22 - Selected Optimization: Prefetching in Batch Processing
**Observation:** `cryptoWorkerPipeline` in `src/main.zig` iterates over a batch of packets and encrypts them.
```zig
        // STAGE 2: Encrypt all packets in-place (100% cache-local, no locks)
        for (0..batch.count) |i| {
            var pkt = &pool.buffers[batch.buf_indices[i]];
            if (tun.encryptPreassigned(&pkt.data, batch.lengths[i], batch.nonces[i])) |enc_len| {
                pkt.len = @intCast(enc_len);
            } else {
                pkt.len = 0; // mark as failed
            }
        }
```
`pool.buffers` is a large array (`MAX_BUFFERS` = 16384). `batch.buf_indices` are random indices into this pool.
The access pattern to `pool.buffers` is random-ish (depending on allocation order).
Each `PacketBuffer` is 2048+ bytes (aligned to 64).
Fetching `pkt` (pointer to `pool.buffers[idx]`) might incur a cache miss.
Accessing `pkt.data` for encryption will definitely incur a cache miss if not in cache.
Since we process a batch of up to 64 packets, we can use `@prefetch` to bring the *next* packet's buffer into cache while processing the current one.
Specifically, `pool.buffers[batch.buf_indices[i+1]]`.

**Hypothesis:** Adding `@prefetch` for the next packet buffer in the loop will reduce stall cycles waiting for memory during the encryption loop.
This affects the `cryptoWorkerPipeline`, which is a critical hot path (Stage 2).
It is a small, safe change.

Let's verify where `pool.buffers` is located. It's in `DataPlanePool`.
```zig
pub const DataPlanePool = struct {
    buffers: [MAX_BUFFERS]PacketBuffer align(CACHE_LINE) = undefined,
    // ...
```
`MAX_BUFFERS` is 16384. `PacketBuffer` is ~2056 bytes. Total size ~33MB.
This is larger than L3 cache (usually). So random access *will* miss.

**Plan:**
1. Modify `cryptoWorkerPipeline` in `src/main.zig`.
2. Inside the encryption loop, prefetch the buffer for iteration `i + prefetch_dist`.
3. `prefetch_dist` of 1 or 2 is usually good.

Also, `tunReaderPipeline` iterates over segments.
```zig
                    for (0..seg_count) |s| {
                        const buf_idx = pool_indices[s];
                        var pkt = &pool.buffers[buf_idx];
                        // ...
                        @memcpy(pkt.data[Pipeline.WG_HEADER_LEN..][0..ip_packet.len], ip_packet);
```
Here too, prefetching might help, but `pool_indices` are allocated in a batch from the free list. `allocBufferBatch` pops from `free_bufs` stack.
If `free_bufs` maintains locality (recently freed buffers are reused), they might be in cache. But `DataPlanePool` is LIFO (stack), so recently freed (hot) buffers are reused first. This is good.
However, `cryptoWorkerPipeline` processes packets that were filled by `tunReaderPipeline`.
The time between filling (TUN read) and encrypting (crypto worker) involves:
- `tunReaderPipeline`: writes to `pkt.data`
- `dispatchBatch`: pushes to `crypto_q`
- `cryptoWorkerPipeline`: pops from `crypto_q`
- `encryptPreassigned`: reads/writes `pkt.data`

If the queue depth is small, data might still be in L3.
But explicit prefetch is safer.

**Another candidate:** `flushPeerTxRing` iterates over batches and packets to send.
```zig
        for (0..head_batch.count) |i| {
            const pkt = &pool.buffers[head_batch.buf_indices[i]];
            // ...
            if (!gso_tx.append(pkt.data[0..pkt.len])) { ... }
        }
```
Here `gso_tx.append` reads `pkt.data` (for `sendmsg`).
Prefetching here could also help.

**Selected optimization:** Add `@prefetch` to `cryptoWorkerPipeline` loop.
Why? Encryption is compute intensive but also memory intensive (streaming data).
ChaCha20-Poly1305 touches every byte of the packet.
If the packet data is not in L1/L2, the CPU stalls.
Prefetching the next packet header/data structure (`PacketBuffer`) is useful.
Prefetching the *content* of the next packet (`pkt.data`) is even better.

Wait, `PacketBuffer` struct:
```zig
pub const PacketBuffer = struct {
    data: [2048]u8 align(CACHE_LINE) = undefined,
    len: u16 = 0,
    endpoint_addr: [4]u8 = .{ 0, 0, 0, 0 },
    endpoint_port: u16 = 0,
};
```
`data` is at offset 0.
So `&pkt.data` is same cache line as `pkt`.
Prefetching `pkt` brings `data` (start of it) into cache.

I will implement prefetching in `cryptoWorkerPipeline`.

**One more check:** `src/wireguard/tunnel.zig` `encryptPreassigned`.
It's called per packet.
It calls `sodium.encrypt`.
If I prefetch `pool.buffers[next_idx]`, I bring the next packet's struct and first ~64 bytes of data into cache.

**Code to modify:** `src/main.zig`.

**Implementation Details:**
Zig's `@prefetch` builtin: `@prefetch(ptr, options)`.
`options` is `.{ .rw = .read, .locality = 3, .cache = .data }` (default).
Since we are going to write (encrypt in place), `rw = .write` might be better (Read For Ownership).

```zig
const std = @import("std");
// ...
        for (0..batch.count) |i| {
            // Prefetch next packet (distance 2 is often better for heavy loops)
            if (i + 1 < batch.count) {
                const next_idx = batch.buf_indices[i + 1];
                const next_pkt = &pool.buffers[next_idx];
                // Prefetch the PacketBuffer struct (which starts with 'data')
                @prefetch(next_pkt, .{ .rw = .write, .locality = 3, .cache = .data });
            }

            var pkt = &pool.buffers[batch.buf_indices[i]];
            // ...
```

Wait, `pool.buffers` is a slice/pointer. `&pool.buffers[next_idx]` is a pointer.
`@prefetch` takes a pointer.

I'll start with `read_file` of `src/main.zig` again to locate `cryptoWorkerPipeline` exactly.
I already read it.
It's around line 1350.

```zig
fn cryptoWorkerPipeline(
    running: *const std.atomic.Value(bool),
    wg_dev: *lib.wireguard.Device.WgDevice,
    udp_fd: posix.fd_t,
    pool: *lib.net.Pipeline.DataPlanePool,
    crypto_q: *lib.net.Pipeline.CryptoQueue,
) void {
    const Pipeline = lib.net.Pipeline;

    while (running.load(.acquire)) {
        const batch_idx = crypto_q.pop() orelse break; // null = closed
        var batch = &pool.batches[batch_idx];
        var peer = &(wg_dev.peers[batch.peer_slot] orelse continue);
        var tun = &(peer.active_tunnel orelse continue);

        // STAGE 2: Encrypt all packets in-place (100% cache-local, no locks)
        for (0..batch.count) |i| {
            var pkt = &pool.buffers[batch.buf_indices[i]];
            if (tun.encryptPreassigned(&pkt.data, batch.lengths[i], batch.nonces[i])) |enc_len| {
                pkt.len = @intCast(enc_len);
            } else {
                pkt.len = 0; // mark as failed
            }
        }
//...
```

I will verify `PacketBuffer` layout again.
`src/net/pipeline.zig`:
```zig
pub const PacketBuffer = struct {
    data: [2048]u8 align(CACHE_LINE) = undefined,
    //...
```
Yes, `data` is first.

I will request a plan review for this optimization.
I'll also look for other prefetch opportunities in `tunReaderPipeline` and `flushPeerTxRing`.
`flushPeerTxRing` iterates to `append` to `gso_tx`.
`gso_tx.append` reads the data.
So prefetching there is also good.
However, `cryptoWorkerPipeline` is the heavy lifter (encryption).

**Plan:**
1.  Modify `src/main.zig`:
    *   In `cryptoWorkerPipeline`, add prefetch logic.
    *   In `flushPeerTxRing`, add prefetch logic.
2.  Verify compilation and tests.
3.  Benchmark (conceptually, I can't run full perf test here).

Wait, the prompt asked for ONE small performance improvement. I should pick the most impactful one.
Crypto is the bottleneck usually. `cryptoWorkerPipeline` is the best place.

Also, `prefetch` is cheap, adding it to two places is fine and fits "one optimization task" (prefetching hot loops).

Let's check if there are any other low hanging fruits.
`src/wireguard/tunnel.zig`: `ReplayWindow.check` uses modulo.
I can replace `% COUNTER_WINDOW_SIZE` with `& (COUNTER_WINDOW_SIZE - 1)` just to be explicit and sure, since `COUNTER_WINDOW_SIZE` is `const`.
But that's micro-optimization.

I'll stick with prefetching.
I will also verify if `std.builtin.PrefetchOptions` is available in Zig 0.15 (it should be).
The syntax is `@prefetch(ptr, options)`.

I will create the plan.
