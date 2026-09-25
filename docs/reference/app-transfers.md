# Application transfers

Verified bulk transfers for files that do not fit one application message
(screenshots, logs, patches). They reuse the authenticated `0x50` envelope, so
they take the same direct, hole-punched, and relayed paths as
[application channels](app-channels.md), and work in `--gossip-only` mode
without TUN or administrator rights.

MeshGuard guarantees that a transfer reported `delivered` was fully received and
its SHA-256 verified by the peer daemon. Durable storage and any application
receipt remain the application's responsibility (Meshrooms stores the file,
then sends its own `file-ack` on `meshrooms-v1`).

## IPC commands

Commands and responses are newline-delimited, like the rest of the control
socket. On Unix they require the daemon's owner (same uid, or root) because the
control socket is world-writable and transfers carry file contents; other local
users get `unauthorized`.

| Command | Response |
| ------- | -------- |
| `XFERINFO` | `{"protocol":1,"chunk":960,"maxBytes":33554432,"maxIo":49152}` |
| `XFERLISTEN <channel> <max_bytes>` | Accept incoming offers on `channel`, each at most `max_bytes` (capped by `maxBytes`). Re-issuing updates the cap. |
| `XFEROFFER <peer> <channel> <size> <sha256-hex> [meta-b64]` | `{"ok":true,"id":"<32 hex>"}`. Reserves `size` bytes for staging. `meta` is at most 768 opaque bytes delivered with the file. |
| `XFERPUT <id> <offset> <base64>` | `{"ok":true,"staged":<bytes>}`. At most 49,152 decoded bytes per command; offsets must be contiguous. An identical retry of an applied chunk is accepted. |
| `XFERSTART <id>` | Verifies the staged bytes against the declared SHA-256, then starts sending. |
| `XFERSTATUS <id>` | `{"ok":true,"state":"staging|sending|delivered|failed","size","staged","ackedChunks","chunks","retransmits"[,"error"]}` |
| `XFERRECV <channel>` | The oldest verified incoming transfer not yet released: `{"ok":true,"id","sender","size","sha256","meta":"<b64>"}` or `{"empty":true}`. Not destructive. |
| `XFERGET <id> <offset> <len>` | `{"ok":true,"length":n,"data":"<b64>"}` for a verified incoming transfer. |
| `XFERDONE <id>` | Release a verified incoming transfer, or forget a finished outgoing one. |
| `XFERCANCEL <id>` | Abandon a transfer in either direction. |

`APPINFO` reports `"transfers":1` when these commands exist.

## Protocol

Frames are binary `0x50` plaintext beginning with the reserved prefix `MGXF1`:
`OFFER`, `DATA` (960-byte chunks), `ACK` (cumulative point plus a 512-chunk
selective bitmap), `DONE` (verified, hash mismatch, or rejected), and `CANCEL`.

- **Admission.** A receiver answers an offer only if a local application called
  `XFERLISTEN` for its channel and the size fits that cap and the global budget;
  otherwise it replies `CANCEL` with a reason the sender reports.
- **Reliability.** The sender keeps a congestion window (slow start, additive
  increase, halving on loss), measures round trips (Karn), retransmits on timeout
  and fast-retransmits chunks overtaken by three later ones. Receivers
  acknowledge every 16 chunks, on gaps, or after 10 ms.
- **Integrity.** The receiver verifies the SHA-256 of the complete bytes before
  `DONE`. The sender verifies the staged bytes against the same hash before
  sending anything.
- **Restarts.** State is in memory. If a receiver lost a transfer, it answers
  data with `CANCEL(unknown)` and the sender offers it again from the start
  (at most three times).
- **Replay.** Frames are authenticated by the `0x50` AEAD. Offers older than one
  hour are refused, and a re-sent offer for a transfer finished in the last 512
  is answered with `DONE` instead of delivering it again. Transfer frames do
  not enter the 128-entry nonce ring that protects application messages; that
  ring is now updated only after a packet authenticates.

## Limits

| Limit | Value |
| ----- | ----- |
| Transfer size | 32 MiB |
| Concurrent transfers | 8 outgoing, 8 incoming |
| Memory held by transfers | 96 MiB each direction |
| Idle timeout (no reply / no data) | 60 s |
| Finished transfers kept for reading or status | 15 min |

## Measured

Two daemons on one Apple Silicon Mac in `--gossip-only` mode over loopback:
10 MiB delivered and verified in 369 ms (about 27 MB/s) without retransmission;
staging and reading it through the control socket took 41 ms and 34 ms. Loss,
duplication, reordering (15% loss, 5% duplication, 40 ms jitter) and receiver
restarts are covered by deterministic unit tests. Real WAN paths, relays under
load, and Windows named-pipe throughput are not yet measured.
