"""Relay integration on loopback: a gossip-only daemon with --relay forwards
sealed app frames between mobile FFI contexts that proved their endpoints, and
refuses frames from anywhere else.

Usage: python3 scripts/test-relay.py <meshguard binary> <FFI library>

The FFI library is libmeshguard-ffi.so on Linux, libmeshguard-ffi.dylib on
macOS and meshguard-ffi.dll on Windows, where the daemon's control endpoint is
a named pipe instead of a Unix socket.
"""
import ctypes as c
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

WINDOWS = sys.platform == "win32"

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
add_contact = bind("meshguard_add_contact", [c.c_void_p, c.c_void_p, c.c_void_p], c.c_int)
set_contacts_only = bind("meshguard_set_contacts_only", [c.c_void_p, c.c_bool])
send_ex = bind("meshguard_send_ex", [c.c_void_p, c.c_void_p, c.c_void_p, c.c_uint32, c.c_void_p], c.c_int)
STATUS_CALLBACK = c.CFUNCTYPE(None, c.c_void_p, c.c_void_p, c.c_uint8)
set_on_delivery_status = bind("meshguard_set_on_delivery_status", [c.c_void_p, STATUS_CALLBACK])
recv_delivery_status = bind("meshguard_recv_delivery_status", [c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p], c.c_int)
switch_relay = bind("meshguard_switch_relay", [c.c_void_p, c.c_void_p, c.c_bool, c.c_void_p, c.c_uint16], c.c_int)
peer_count = bind("meshguard_peer_count", [c.c_void_p], c.c_uint32)
tunnel_open = bind("meshguard_tunnel_open", [c.c_void_p, c.c_void_p], c.c_int)
tunnel_send = bind("meshguard_tunnel_send", [c.c_void_p, c.c_void_p, c.c_void_p, c.c_uint32], c.c_int)
tunnel_recv = bind("meshguard_tunnel_recv", [c.c_void_p] * 4, c.c_int)
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


def pipe_exists(path):
    # Listing the pipe namespace does not connect to the pipe; opening or
    # stat-ing it would take the daemon's only pipe instance.
    return path.rsplit("\\", 1)[1] in os.listdir(r"\\.\pipe\\")


if WINDOWS:
    import msvcrt

    kernel32 = c.WinDLL("kernel32", use_last_error=True)
    kernel32.PeekNamedPipe.argtypes = [c.c_void_p, c.c_void_p, c.c_uint32, c.c_void_p, c.POINTER(c.c_uint32), c.c_void_p]
    kernel32.PeekNamedPipe.restype = c.c_int


def pipe_request(path, line, seconds=5):
    """One request on the daemon's named pipe: write a line, read a line.
    Fails after `seconds`, like the Unix socket's timeout."""
    end = time.monotonic() + seconds
    while True:
        try:
            pipe = open(path, "r+b", buffering=0)
            break
        except OSError as err:
            # 2: not created yet. 231 ERROR_PIPE_BUSY: serving another client.
            if getattr(err, "winerror", None) not in (2, 231) or time.monotonic() > end:
                raise
            time.sleep(0.05)
    with pipe:
        pipe.write(line)
        handle = msvcrt.get_osfhandle(pipe.fileno())
        data = b""
        while not data.endswith(b"\n"):
            # Read only what is waiting, so a daemon that never answers
            # cannot block the test.
            available = c.c_uint32()
            if not kernel32.PeekNamedPipe(handle, None, 0, None, c.byref(available), None):
                break  # the daemon closed the pipe
            if available.value:
                data += pipe.read(available.value)
            elif time.monotonic() > end:
                raise TimeoutError(f"no reply on {path}")
            else:
                time.sleep(0.01)
    return data


class Relay:
    def __init__(self, root, *flags, open_trust=True):
        self.root = Path(root)
        self.port = free_udp_port()
        if WINDOWS:
            self.control = rf"\\.\pipe\meshguard-test-{uuid.uuid4().hex}"
        else:
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
        if WINDOWS:
            wait_for(lambda: pipe_exists(self.control), 20, "relay control pipe")
        else:
            wait_for(lambda: self.control.exists(), 20, "relay control socket")

    def status(self):
        return self.command(b"STATUS\n")

    def command(self, line):
        if WINDOWS:
            return json.loads(pipe_request(self.control, line))
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

    def tunnel_until_received(self, other, payload, seconds=20):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            tunnel_send(self.ctx, other.pubkey, c.create_string_buffer(payload), len(payload))
            until = time.monotonic() + 0.3
            while time.monotonic() < until:
                out, length, sender = c.create_string_buffer(1500), c.c_uint32(), c.create_string_buffer(32)
                if tunnel_recv(other.ctx, out, c.byref(length), sender) == 0:
                    return sender.raw, out.raw[:length.value]
                time.sleep(0.01)
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

    def test_clients_that_met_through_a_relay_open_a_tunnel(self):
        relay, alice, bob = self.start()
        # -4 until Alice has learned Bob's WireGuard key, which can follow his first ack.
        wait_for(lambda: tunnel_open(alice.ctx, bob.pubkey) == 0, 20, "a tunnel to open")
        self.assertEqual(alice.tunnel_until_received(bob, b"through the tunnel"), (alice.pubkey, b"through the tunnel"))
        self.assertEqual(bob.tunnel_until_received(alice, b"and back"), (bob.pubkey, b"and back"))


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


class OpaqueRelay(unittest.TestCase):
    """Clients of an opaque relay learn nothing about each other from it and talk as contacts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="meshguard-opaque-")
        self.addCleanup(self.temp.cleanup)

    def test_contacts_reach_each_other_and_absent_contacts_report_offline(self):
        relay = Relay(self.temp.name, "--opaque")
        self.addCleanup(relay.stop)
        alice = Client(0x51, relay)
        self.addCleanup(alice.close)
        bob = Client(0x52, relay)
        self.addCleanup(bob.close)
        carol = Client(0x53, relay)  # registered as a contact but never joins
        self.addCleanup(carol.close)
        statuses = []
        callback = STATUS_CALLBACK(lambda dest, nonce, code: statuses.append((c.string_at(dest, 32), c.string_at(nonce, 12), code)))
        set_on_delivery_status(alice.ctx, callback)
        alice.join(relay)
        bob.join(relay)
        wait_for(lambda: relay.status()["relay"]["proven"] >= 2, 40, "both clients to prove their endpoints")

        # The relay describes only itself: nobody sees the other client.
        time.sleep(1)
        self.assertEqual(peer_count(alice.ctx), 1)
        self.assertEqual(peer_count(bob.ctx), 1)
        self.assertEqual(relay.status()["peers"]["alive"], 0)

        for me, other in ((alice, bob), (bob, alice), (alice, carol)):
            self.assertEqual(add_contact(me.ctx, other.pubkey, other.wg_pubkey), 0)
        set_contacts_only(bob.ctx, True)
        got = alice.send_until_received(bob, b"hello as a contact")
        self.assertEqual(got, (alice.pubkey, b"hello as a contact"))
        got = bob.send_until_received(alice, b"and back as a contact")
        self.assertEqual(got, (bob.pubkey, b"and back as a contact"))
        self.assertEqual(alice.direct_sends(), 0)
        self.assertEqual(bob.direct_sends(), 0)

        nonce = c.create_string_buffer(12)
        payload = c.create_string_buffer(b"are you there")
        self.assertEqual(send_ex(alice.ctx, carol.pubkey, payload, 13, nonce), 0)
        wait_for(lambda: any(s[1] == nonce.raw for s in statuses), 10, "an offline status for the absent contact")
        status = next(s for s in statuses if s[1] == nonce.raw)
        self.assertEqual(status[0], carol.pubkey)
        self.assertEqual(status[2], 1)  # offline

        # Polling hosts see the same statuses.
        dest, polled_nonce, code = c.create_string_buffer(32), c.create_string_buffer(12), c.c_uint8()
        polled = []
        while recv_delivery_status(alice.ctx, dest, polled_nonce, c.byref(code)) == 0:
            polled.append((dest.raw, polled_nonce.raw, code.value))
        self.assertIn((carol.pubkey, nonce.raw, 1), polled)


class SeveralRelays(unittest.TestCase):
    """One identity can hold a context per relay, or move between relays."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="meshguard-relays-")
        self.addCleanup(self.temp.cleanup)

    def relay(self, name):
        relay = Relay(Path(self.temp.name) / name, "--opaque")
        self.addCleanup(relay.stop)
        return relay

    def client(self, seed, relay, *contacts):
        client = Client(seed, relay)
        self.addCleanup(client.close)
        return client

    def test_contexts_per_relay_and_switching(self):
        first, second = self.relay("first"), self.relay("second")
        alice = self.client(0x61, first)
        bob = self.client(0x62, second)
        carol_first = self.client(0x63, first)
        carol_second = self.client(0x63, second)  # same identity, other relay
        dave = self.client(0x64, first)
        self.assertEqual(carol_first.pubkey, carol_second.pubkey)
        for client, relay in ((alice, first), (bob, second), (carol_first, first), (carol_second, second), (dave, first)):
            client.join(relay)
        wait_for(lambda: first.status()["relay"]["proven"] >= 3 and second.status()["relay"]["proven"] >= 2, 40, "clients on both relays to prove their endpoints")

        def befriend(a, b):
            self.assertEqual(add_contact(a.ctx, b.pubkey, b.wg_pubkey), 0)
            self.assertEqual(add_contact(b.ctx, a.pubkey, a.wg_pubkey), 0)

        befriend(alice, carol_first)
        befriend(bob, carol_second)
        befriend(bob, dave)
        self.assertEqual(alice.send_until_received(carol_first, b"via the first relay"), (alice.pubkey, b"via the first relay"))
        self.assertEqual(bob.send_until_received(carol_second, b"via the second relay"), (bob.pubkey, b"via the second relay"))

        # Dave moves to the second relay, keeping his contacts, and reaches Bob there.
        self.assertEqual(switch_relay(dave.ctx, second.pubkey, True, bytes([127, 0, 0, 1]), second.port), 0)
        wait_for(lambda: second.status()["relay"]["proven"] >= 3, 40, "the moved client to prove its endpoint on the second relay")
        self.assertEqual(dave.send_until_received(bob, b"after switching"), (dave.pubkey, b"after switching"))


class ExportedSymbols(unittest.TestCase):
    """The library exports every C function the FFI source declares."""

    def test_every_export_resolves(self):
        source = Path(__file__).resolve().parent.parent / "src" / "meshguard_ffi.zig"
        names = re.findall(r"^export fn (meshguard_\w+)", source.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertGreater(len(names), 40)
        self.assertEqual([name for name in names if not hasattr(lib, name)], [])


if __name__ == "__main__":
    unittest.main()
