## 2024-03-22 - WireGuard Handshake Documentation Gap
**Gap:** The documentation (`docs/concepts/wire-protocol.md` and `README.md`) described a custom `0x10`/`0x11` handshake protocol, while the implementation (`src/wireguard/noise.zig`) uses the standard WireGuard Noise_IKpsk2 handshake (Types 1/2).
**Learning:** Documentation drifted because the initial design likely included a custom handshake which was replaced by standard WireGuard during implementation, but docs were not updated.
**Prevention:** Regularly audit `messages.zig` against `device.zig` packet classification logic to ensure all documented message types are actually handled.

## 2026-02-24 - CLI Flags and Default Ports Drift
**Gap:** CLI flags `--port` and `--wg-port` were documented but not implemented in `src/main.zig`. Default WireGuard port was documented as `51820` but hardcoded as `51830`.
**Learning:** `src/main.zig` uses hardcoded values and manual argument parsing instead of the `src/config.zig` struct or a centralized CLI parser, leading to drift between the config module, the main entry point, and the docs.
**Prevention:** Refactor `src/main.zig` to use a CLI library that auto-generates help text from the `Config` struct, or add a CI check that grep's `main.zig` for every flag listed in `docs/reference/cli.md`.

## 2026-05-20 - Missing CLI Commands and Flags
**Gap:** `meshguard config show` command and `meshguard up --encrypt-workers` flag were implemented in `src/main.zig` but missing from `docs/reference/cli.md`.
**Learning:** Manual argument parsing in `src/main.zig` allows adding new commands/flags without any compile-time check for documentation or help text updates.
**Prevention:** Implement a centralized CLI definition or a "help" generation system that enforces documentation of all available commands and flags.
