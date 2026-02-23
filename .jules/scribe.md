## 2024-03-22 - WireGuard Handshake Documentation Gap
**Gap:** The documentation (`docs/concepts/wire-protocol.md` and `README.md`) described a custom `0x10`/`0x11` handshake protocol, while the implementation (`src/wireguard/noise.zig`) uses the standard WireGuard Noise_IKpsk2 handshake (Types 1/2).
**Learning:** Documentation drifted because the initial design likely included a custom handshake which was replaced by standard WireGuard during implementation, but docs were not updated.
**Prevention:** Regularly audit `messages.zig` against `device.zig` packet classification logic to ensure all documented message types are actually handled.
