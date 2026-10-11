"""Run one relay load scenario on loopback and print a JSON report.

Starts `meshguard up --gossip-only --relay` in a scratch config, drives it with
relay-loadgen, and adds the relay's CPU time, peak memory and forwarding
counters to the generator's results. Linux only.

  zig build -Doptimize=ReleaseFast relay-loadgen install
  python3 bench/relay-load/run.py --clients 10000 --rate 0.1 --duration 60

Options not listed below are passed to relay-loadgen unchanged.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CLOCK_TICKS = os.sysconf("SC_CLK_TCK")


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / CLOCK_TICKS


def peak_rss_mib(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) / 1024
    return None


def relay_status(control):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(str(control))
        s.sendall(b"STATUS\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", default=str(ROOT / "zig-out/bin/meshguard"))
    parser.add_argument("--loadgen", default=str(ROOT / "zig-out/bin/relay-loadgen"))
    parser.add_argument("--clients", type=int, default=1000)
    parser.add_argument("--relay-flag", action="append", default=[],
                        help="extra flag for meshguard up, e.g. --relay-flag=--client-pps=100")
    parser.add_argument("--max-loss", type=float, default=None,
                        help="exit non-zero when honest loss exceeds this fraction or any spoofed frame arrives")
    args, passthrough = parser.parse_known_args()

    with tempfile.TemporaryDirectory(prefix="meshguard-relay-load-") as temp:
        root = Path(temp)
        env = {k: v for k, v in os.environ.items() if not k.startswith("MESHGUARD_")}
        env["MESHGUARD_CONFIG_DIR"] = str(root / "config")
        subprocess.run([args.binary, "keygen"], env=env, check=True, capture_output=True, timeout=30)
        relay_key = base64.b64decode((root / "config" / "identity.pub").read_text().strip())
        port = free_udp_port()
        control = root / "control.sock"
        relay_flags = []
        for flag in args.relay_flag:
            relay_flags.extend(flag.split("=", 1))
        max_clients = max(1024, int(args.clients * 1.25))
        command = [args.binary, "up", "--gossip-only", "--open", "--relay", "--announce", "127.0.0.1",
                   "--gossip-port", str(port), "--control-path", str(control),
                   "--max-clients", str(max_clients), *relay_flags]
        with open(root / "relay.log", "w") as log:
            relay = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while not control.exists():
                    if time.monotonic() > deadline or relay.poll() is not None:
                        raise RuntimeError("relay did not start: " + (root / "relay.log").read_text()[-2000:])
                    time.sleep(0.05)
                cpu_before = cpu_seconds(relay.pid)
                started = time.monotonic()
                result = subprocess.run(
                    [args.loadgen, "--relay", f"127.0.0.1:{port}",
                     "--relay-key", base64.b64encode(relay_key).decode(),
                     "--clients", str(args.clients), *passthrough],
                    capture_output=True, text=True, timeout=3600)
                wall = time.monotonic() - started
                if result.returncode != 0:
                    raise RuntimeError("relay-loadgen failed: " + result.stderr[-2000:])
                report = json.loads(result.stdout)
                report["relay"] = {
                    "cpu_seconds": round(cpu_seconds(relay.pid) - cpu_before, 3),
                    "cpu_cores_avg": round((cpu_seconds(relay.pid) - cpu_before) / wall, 3),
                    "peak_rss_mib": peak_rss_mib(relay.pid),
                    "status": relay_status(control).get("relay"),
                    "flags": command[2:],
                }
            finally:
                relay.terminate()
                try:
                    relay.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    relay.kill()
    json.dump(report, sys.stdout, indent=2)
    print()
    if args.max_loss is not None:
        if report["proven"] < report["clients"] or report["loss"] > args.max_loss or report["spoof_delivered"] > 0:
            sys.exit("relay load check failed")


if __name__ == "__main__":
    main()
