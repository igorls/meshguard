
## 2024-05-19 - Optimization: Dominant packet path extraction
**Learning:** There are two distinct hot-path switches in packet classification:
1. `PacketType.classify` switches over the raw integer `msg_type` (a `u32` read from the first 4 bytes). Zig compiles integer switches to jump tables or sequential branches depending on the optimizer; on this critical inner loop the jump table evaluation adds measurable overhead.
2. The event loops (`processIncomingPacket`, `windowsEventLoop`, `macosEventLoop`) switch over the `PacketType` enum returned by `classify`.

**Action:** In both cases, extracting the dominant data-plane case as an explicit `if` branch before the `switch` — `if (msg_type == 4) return .wg_transport;` in `classify`, and `if (pkt_type == .wg_transport)` in the event loops — forces the compiler to emit a single, predictable branch instruction that the CPU branch predictor handles efficiently. The remaining `switch` arm for the extracted value is then marked `unreachable` so the switch stays exhaustive and the compiler can elide it on the fast path.
