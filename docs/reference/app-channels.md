# Application messaging channels

Isolated MeshGuard application channels sit on top of the existing encrypted
`0x50` payload. Meshrooms uses channel `meshrooms-v1`. Room admission and
durable retry remain Meshrooms' responsibility.

This API is additive. Legacy `SEND` / `RECV` / `MSGS` keep their unframed
plaintext queue and never pop `MGAPP1` frames.

## IPC commands

Newline-delimited text commands, JSON responses (same style as `SEND`/`RECV`).

| Command | Effect |
| ------- | ------ |
| `APPSEND <peer-pubkey-hex> <channel> <payload>` | Frame as `MGAPP1`, encrypt, send on the existing `0x50`/Noise path |
| `APPRECV <channel>` | Pop the oldest message from **that channel only** |
| `APPINFO` | `{"protocol":1,"maxPayload":952}` |

`APPRECV` uses the same message / empty shapes as legacy `RECV`:

```json
{"ok":true,"sender":"<64 hex>","data":"<payload>","timestamp":<unix>}
{"empty":true}
```

CLI wrappers (`meshguard appsend`, `meshguard apprecv`, `meshguard appinfo`)
talk to the daemon through the same control socket as `send`/`recv`.

## Wire format

Inside the decrypted `0x50` plaintext:

```
MGAPP1 <channel> <payload>
```

- Reserved prefix: `MGAPP1` followed by a space (7 bytes).
- Channel: charset `[a-z0-9._-]`, length 1–64. Anything else is rejected.
- Payload may contain spaces; the first space after the prefix separates the
  channel name, the rest is the payload.
- Malformed or oversize frames are **rejected**, never truncated, and never
  placed on the legacy queue.
- Unframed / non-`MGAPP1` plaintext continues to the legacy `SEND`/`RECV`/`MSGS`
  queue (legacy `pushMessage` still truncates those to 1024 bytes).

## maxPayload

The `0x50` plaintext budget is 1024 bytes. Framing overhead is:

```
len("MGAPP1 ") + len(channel) + 1
```

`APPINFO.maxPayload` is the conservative universal maximum that still fits a
64-byte channel:

```
1024 - 7 - 64 - 1 = 952
```

`meshrooms-v1` (12 bytes) could carry 1004 bytes, but clients must not assume
that: advertise and enforce 952.

## Queue isolation

- Legacy queue: 64 messages, drop-oldest, used only by `SEND`/`RECV`/`MSGS`.
- Application queues: one bounded ring per channel (also 64, drop-oldest **on
  that channel only**). Up to 8 concurrent channels.
- `RECV`/`MSGS` never see `MGAPP1` frames.
- `APPRECV A` never pops channel `B`.
- Demux happens when decrypted plaintext is pushed, not at pop time.

## Isolated test endpoints

Candidate daemons can run beside live workers without stealing sockets or the
default gossip port.

| Name | Where | Default when unset |
| ---- | ----- | ------------------ |
| `MESHGUARD_CONTROL_PATH` | Listener bind **and** CLI connect | `/run/meshguard/meshguard.sock` (Linux; XDG fallback) or `\\.\pipe\meshguard` (Windows) |
| `--control-path <path>` | `meshguard up` only (overrides env for the daemon) | same as above |
| `--gossip-port <port>` | `meshguard up` and `meshguard connect` | `51821` |
| `MESHGUARD_GOSSIP_PORT` | Same commands when the flag is omitted | `51821` |

When `MESHGUARD_CONTROL_PATH` is set, the client connects **only** to that path
and does not fall back to the production socket. CLI `SEND`/`RECV`/`APP*` and
`status`/`down` all honor it.

Example (does not stop a production worker):

```bash
export MESHGUARD_CONTROL_PATH=/tmp/meshguard-candidate.sock
export MESHGUARD_GOSSIP_PORT=51921
meshguard up --gossip-only --open --gossip-port 51921 --control-path /tmp/meshguard-candidate.sock
meshguard appinfo
meshguard apprecv meshrooms-v1
```
