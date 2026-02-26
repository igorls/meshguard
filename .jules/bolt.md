# Performance Journal

## 2024-05-23 - Zero-copy TUN GSO Write
**Learning:** `writeCoalescedToTun` was performing a `memcpy` of up to 64KB per GSO super-packet to assemble it in a contiguous buffer before writing to TUN. This is inefficient as the data is already available in the decryption buffer.
**Action:** Implemented `writeGSOScatter` in `TunDevice` using `writev` (scatter-gather I/O). Modified `writeCoalescedToTun` to construct an `iovec` array pointing to the modified header (stack-allocated) and the original payload segments. This eliminates the data copy on the RX path.
**Bonus:** Fixed a potential bug/latency issue where the TCP PSH flag from the last coalesced segment was not propagated to the GSO super-packet header.
