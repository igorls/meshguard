## 2024-03-22 - WireGuard Handshake Documentation Gap
**Gap:** The documentation (`docs/concepts/wire-protocol.md` and `README.md`) described a custom `0x10`/`0x11` handshake protocol, while the implementation (`src/wireguard/noise.zig`) uses the standard WireGuard Noise_IKpsk2 handshake (Types 1/2).
**Learning:** Documentation drifted because the initial design likely included a custom handshake which was replaced by standard WireGuard during implementation, but docs were not updated.
**Prevention:** Regularly audit `messages.zig` against `device.zig` packet classification logic to ensure all documented message types are actually handled.

## 2026-02-24 - CLI Flags and Default Ports Drift
**Gap:** CLI flags `--port` and `--wg-port` were documented but not implemented in `src/main.zig`. Default WireGuard port was documented as `51820` but hardcoded as `51830`.
**Learning:** `src/main.zig` uses hardcoded values and manual argument parsing instead of the `src/config.zig` struct or a centralized CLI parser, leading to drift between the config module, the main entry point, and the docs.
**Prevention:** Refactor `src/main.zig` to use a CLI library that auto-generates help text from the `Config` struct, or add a CI check that grep's `main.zig` for every flag listed in `docs/reference/cli.md`.

## 2024-05-23 - SWIM Protocol Period Drift
**Gap:** The documentation stated the SWIM protocol period was 1000ms (1s), but the implementation uses 5000ms (5s) in both `src/config.zig` and `src/discovery/swim.zig`.
**Learning:** The documentation likely reflected an early design decision or standard SWIM defaults, but the implementation settled on a more conservative 5s interval for WAN stability, and docs were not updated.
**Prevention:** Add a CI check that grep's `docs/guide/configuration.md` for values that match constants exported in `src/config.zig`.

## 2025-03-09 - Missing CLI Commands Documentation
**Gap:** Several CLI commands (`connect`, `org-keygen`, `org-sign`, `org-vouch`, `upgrade`) and the `--org` flag for `trust` were implemented in `src/main.zig` but entirely missing from the reference documentation in `docs/reference/cli.md`.
**Learning:** Adding new features to the CLI requires updating the documentation. Because command parsing and help messages are manually defined in `src/main.zig` rather than using a generator framework, the `docs/reference/cli.md` drift happens frequently if not updated in the same PR.
**Prevention:** Regularly compare the usage string in `src/main.zig` with `docs/reference/cli.md`, or ideally, auto-generate the markdown reference from the CLI parser configuration.
