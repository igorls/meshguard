
## 2024-05-19 - Optimization: Dominant packet path extraction
**Learning:** Zig switch statements over integer values compile down to jump tables or sequential branches depending on the optimizer. In hot loops like `PacketType.classify(pkt)` checking, an enum `switch` can cause a pipeline stall on jump evaluation.
**Action:** Extracting the dominant data-plane case (e.g. `if (pkt_type == .wg_transport)`) explicitly before the `switch` statement forces the compiler to emit a direct branch instruction, which the CPU branch predictor handles much more efficiently, avoiding jump table overhead on the hot path. Remember to include the unreachable case within the switch so the code compiles.
