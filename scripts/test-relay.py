"""Relay integration on loopback: a gossip-only daemon with --relay forwards
sealed app frames between mobile FFI contexts that proved their endpoints, and
refuses frames from anywhere else.

Usage: python3 scripts/test-relay.py <meshguard binary> <libmeshguard-ffi.so>
"""
import ctypes as c
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = Path(sys.argv.pop(1)).resolve()
LIBRARY = Path(sys.argv.pop(1)).resolve()

lib = c.CDLL(str(LIBRARY))


def bind(name, args, result=None):
    f = getattr(lib, name)
    f.argtypes = args
    f.restype = result
    return f


init = bind("meshguard_init", [c.c_void_p, c.c_uint16], c.c_void_p)
set_app_relay = bind("meshguard_set_app_relay", [c.c_void_p, c.c_void_p, c.c_bool], c.c_int)
join = bind("meshguard_join", [c.c_void_p, c.c_void_p, c.c_uint16], c.c_int)
send = bind("meshguard_send", [c.c_void_p, c.c_void_p, c.c_void_p, c.c_uint32], c.c_int)
recv = bind("meshguard_recv", [c.c_void_p] * 4, c.c_int)
pubkey = bind("meshguard_get_pubkey", [c.c_void_p, c.c_void_p])
wg_pubkey = bind("meshguard_get_wg_pubkey", [c.c_void_p, c.c_void_p])
set_org_cert = bind("meshguard_set_org_cert", [c.c_void_p, c.c_void_p, c.c_uint32], c.c_int)
peer_count = bind("meshguard_peer_count", [c.c_void_p], c.c_uint32)
route_stats = bind("meshguard_app_route_stats", [c.c_void_p, c.c_void_p])
destroy = bind("meshguard_destroy", [c.c_void_p])


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, seconds, what):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


class Relay:
    def __init__(self, root, *flags, open_trust=True):
        self.root = Path(root)
        self.port = free_udp_port()
        self.control = self.root / "control.sock"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("MESHGUARD_")}
        self.env["MESHGUARD_CONFIG_DIR"] = str(self.root / "config")
        subprocess.run([BINARY, "keygen"], env=self.env, check=True, capture_output=True, timeout=30)
        import base64
        self.pubkey = base64.b64decode((self.root / "config" / "identity.pub").read_text().strip())
        self.log = open(self.root / "relay.log", "w")
        self.process = subprocess.Popen(
            [BINARY, "up", "--gossip-only", *(["--open"] if open_trust else []), "--announce", "127.0.0.1",
             "--gossip-port", str(self.port), "--control-path", str(self.control), *flags],
            env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        wait_for(lambda: self.control.exists(), 20, "relay control socket")

    def status(self):
        return self.command(b"STATUS\n")

    def command(self, line):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(self.control))
            s.sendall(line)
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        return json.loads(data)

    def stop(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.log.close()


class Client:
    def __init__(self, seed_byte, relay):
        self.ctx = init(bytes([seed_byte]) * 32, 0)
        if not self.ctx:
            raise RuntimeError("meshguard_init failed")
        key = c.create_string_buffer(32)
        pubkey(self.ctx, key)
        self.pubkey = key.raw
        wg = c.create_string_buffer(32)
        wg_pubkey(self.ctx, wg)
        self.wg_pubkey = wg.raw
        if set_app_relay(self.ctx, relay.pubkey, True) != 0:
            raise RuntimeError("meshguard_set_app_relay failed")

    def join(self, relay):
        if join(self.ctx, bytes([127, 0, 0, 1]), relay.port) != 0:
            raise RuntimeError("meshguard_join failed")

    def install(self, cert):
        buf = c.create_string_buffer(cert)
        rc = set_org_cert(self.ctx, buf, len(cert))
        if rc != 0:
            raise RuntimeError(f"meshguard_set_org_cert failed: {rc}")

    def receive(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            out = c.create_string_buffer(1024)
            length = c.c_uint32()
            sender = c.create_string_buffer(32)
            if recv(self.ctx, out, c.byref(length), sender) == 0:
                return sender.raw, out.raw[:length.value]
            time.sleep(0.02)
        return None

    def send_until_received(self, other, payload, seconds=20):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            data = c.create_string_buffer(payload)
            send(self.ctx, other.pubkey, data, len(payload))
            got = other.receive(0.5)
            if got:
                return got
        return None

    def direct_sends(self):
        out = c.create_string_buffer(32)
        route_stats(self.ctx, out)
        return int.from_bytes(out.raw[0:8], "little")

    def close(self):
        destroy(self.ctx)


class RelayForwarding(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="meshguard-relay-")
        self.addCleanup(self.temp.cleanup)

    def start(self, *flags):
        relay = Relay(self.temp.name, *flags)
        self.addCleanup(relay.stop)
        alice = Client(0x31, relay)
        self.addCleanup(alice.close)
        bob = Client(0x32, relay)
        self.addCleanup(bob.close)
        alice.join(relay)
        bob.join(relay)
        wait_for(lambda: peer_count(alice.ctx) >= 2 and peer_count(bob.ctx) >= 2, 30, "clients to see each other")
        return relay, alice, bob

    def test_authenticated_relay_forwards_between_proven_clients_only(self):
        relay, alice, bob = self.start("--relay")
        self.assertEqual(relay.status()["relay"]["forwarding"], "authenticated")
        wait_for(lambda: relay.status()["relay"]["proven"] >= 2, 40, "both clients to prove their endpoints")

        got = alice.send_until_received(bob, b"hello through an authenticated relay")
        self.assertEqual(got, (alice.pubkey, b"hello through an authenticated relay"))
        got = bob.send_until_received(alice, b"and back")
        self.assertEqual(got, (bob.pubkey, b"and back"))
        self.assertEqual(alice.direct_sends(), 0)
        self.assertEqual(bob.direct_sends(), 0)

        # A third party naming Alice as sender from its own socket is refused.
        before = relay.status()["relay"]["dropped"]["unproven_sender"]
        frame = b"\x50" + bob.pubkey + alice.pubkey + bytes(12) + b"forged" + bytes(16)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(frame, ("127.0.0.1", relay.port))
        wait_for(lambda: relay.status()["relay"]["dropped"]["unproven_sender"] > before, 10, "the forged frame to be refused")
        self.assertIsNone(bob.receive(1))

    def test_default_daemon_still_relays_for_known_clients(self):
        relay, alice, bob = self.start()
        self.assertEqual(relay.status()["relay"]["forwarding"], "endpoint_match")
        got = alice.send_until_received(bob, b"hello through a default relay")
        self.assertEqual(got, (alice.pubkey, b"hello through a default relay"))


class RelayPasses(unittest.TestCase):
    """A closed relay admits holders of passes from an organization it trusts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="meshguard-passes-")
        self.addCleanup(self.temp.cleanup)
        self.issuer = {k: v for k, v in os.environ.items() if not k.startswith("MESHGUARD_")}
        self.issuer["MESHGUARD_CONFIG_DIR"] = str(Path(self.temp.name) / "issuer")
        subprocess.run([BINARY, "org-keygen"], env=self.issuer, check=True, capture_output=True, timeout=30)

    def issue(self, client, name):
        import base64
        expires = int(time.time()) + 3600
        subprocess.run([BINARY, "org-sign", base64.b64encode(client.pubkey).decode(), "--name", name,
                        "--wg-pubkey", base64.b64encode(client.wg_pubkey).decode(), "--expires", str(expires)],
                       env=self.issuer, check=True, capture_output=True, timeout=30)
        return (Path(self.issuer["MESHGUARD_CONFIG_DIR"]) / f"{name}.cert").read_bytes()

    def test_closed_relay_admits_pass_holders_after_reload(self):
        relay = Relay(Path(self.temp.name) / "relay", "--relay", open_trust=False)
        self.addCleanup(relay.stop)
        alice = Client(0x41, relay)
        self.addCleanup(alice.close)
        bob = Client(0x42, relay)
        self.addCleanup(bob.close)
        alice.install(self.issue(alice, "alice"))
        bob.install(self.issue(bob, "bob"))
        alice.join(relay)
        bob.join(relay)

        # Trusting nobody yet, the relay refuses everyone: fail closed.
        time.sleep(3)
        self.assertEqual(relay.status()["relay"]["proven"], 0)

        org_pub = (Path(self.issuer["MESHGUARD_CONFIG_DIR"]) / "org" / "org.pub").read_text()
        trusted = Path(relay.env["MESHGUARD_CONFIG_DIR"]) / "trusted_orgs"
        trusted.mkdir(parents=True, exist_ok=True)
        (trusted / "issuer.org").write_text(org_pub)
        self.assertTrue(relay.command(b"RELOAD\n")["reloading"])

        wait_for(lambda: relay.status()["relay"]["proven"] >= 2, 40, "pass holders to prove their endpoints")
        got = alice.send_until_received(bob, b"admitted by pass")
        self.assertEqual(got, (alice.pubkey, b"admitted by pass"))

        # A client without a pass is still refused.
        carol = Client(0x43, relay)
        self.addCleanup(carol.close)
        carol.join(relay)
        time.sleep(3)
        self.assertEqual(relay.status()["relay"]["proven"], 2)


if __name__ == "__main__":
    unittest.main()
