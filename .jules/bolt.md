# Bolt Journal

## 2024-05-24 - Initial setup
**Learning:** Initializing Bolt journal.
**Action:** Always document critical learnings here.

## 2024-05-24 - Zig jump tables for packet classification
**Learning:** In Zig, standard `switch` statements on sequential integers compile to jump tables. On hot paths (like packet classification), if there is a dominant case (e.g. data-plane packets, which make up 99.9% of traffic), extracting it into an explicit `if` branch *before* the `switch` prevents jump table overhead and improves branch prediction.
**Action:** Always extract dominant cases from switches when on critical hot paths like packet forwarding.
