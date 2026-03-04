## 2025-02-17 - [Data Plane Hot-Path Optimization]
**Learning:** In Zig, standard `switch` statements on integers compile to jump tables. Extracting the dominant case (e.g., data-plane packets) into an explicit `if` branch before a `switch` improves branch prediction and avoids jump table overhead.
Additionally, marking small, frequently called utility functions on the hot path (like packet classification, hash functions, and IP parsing) with the `inline` keyword ensures the compiler eliminates function call overhead across module boundaries.
**Action:** Always consider the dominant case in a switch statement on hot paths. Explicitly `inline` small utility functions used extensively on packet processing and routing hot paths.
