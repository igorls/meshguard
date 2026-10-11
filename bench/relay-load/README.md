# Relay load harness

Measures a relay's authenticated forwarding (`meshguard up --relay`) with
many simulated clients on one Linux host.

`relay-loadgen` gives every client its own UDP socket on its own loopback
address (`127.a.b.c`), so per-address limits apply as they would on the
internet. Each client behaves like a mobile context with a pinned relay:

- pings with its signed WireGuard binding and answers relay pings,
- proves its endpoint with a Noise handshake, retrying until it succeeds,
  and re-proves every `--reproof` seconds (15, as mobile contexts do),
- sends app frames to `--contacts` peers at a Poisson `--rate` per second.

Frames carry a cleartext measurement header (sender, sequence, send time)
where ciphertext would be. The relay never decrypts, so this measures the
relay's work without spending the generator's CPU on sealing.

Adversaries:

| Option | Behavior |
|---|---|
| `--flooders N --flood-pps R` | proven clients sending far above their budget |
| `--spoofers N --spoof-pps R` | unproven sockets naming honest clients as sender |
| `--storm-at S` | every honest client moves to a new source port S seconds into the run |

## Running

```bash
zig build -Doptimize=ReleaseFast
zig build relay-loadgen -Doptimize=ReleaseFast
python3 bench/relay-load/run.py --clients 10000 --rate 0.1 --duration 60 --warmup 120
```

`run.py` starts a gossip-only `--relay` daemon in a scratch config, runs the
generator, and prints one JSON report: proof times, frames sent and
received, loss, latency percentiles, flood and spoof counts, and the relay's
CPU time, peak RSS and `status` counters. Pass relay options with
`--relay-flag=--client-pps=100`. `--max-loss F` makes the run fail when
honest loss exceeds `F`, a client never proves, or a spoofed frame arrives;
CI uses it for a small smoke run.

Loss counts frames sent during the measurement window to contacts that had
proven their endpoint; frames still in flight get one second to arrive.
Latency is send to receive on the same host.
