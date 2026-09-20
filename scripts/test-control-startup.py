"""Exercise startup validation using only isolated paths and no daemon starts."""
import os
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = Path(sys.argv.pop(1)).resolve()


class ControlStartup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="meshguard-startup-")
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "not-created"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("MESHGUARD_")}
        self.env["MESHGUARD_CONFIG_DIR"] = str(self.config)
        self.env["MESHGUARD_CONTROL_PATH"] = (
            r"\\.\pipe" + "\\" + Path(self.temp.name).name
            if os.name == "nt" else str(Path(self.temp.name) / "missing.sock")
        )

    def rejected(self, args, expected):
        result = subprocess.run([str(BINARY), *args], env=self.env, capture_output=True,
                                text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stdout + result.stderr)
        self.assertFalse(self.config.exists(), "invalid startup mutated the config directory")

    def test_empty_control_override(self):
        self.env["MESHGUARD_CONTROL_PATH"] = ""
        # Read-only even on a regressed binary: never send STOP to a default socket.
        self.rejected(["appinfo"], "InvalidControlPath")
        self.rejected(["up", "--kernel"], "InvalidControlPath")

    def test_blank_control_override(self):
        self.env["MESHGUARD_CONTROL_PATH"] = " \t"
        self.rejected(["appinfo"], "InvalidControlPath")

    def test_invalid_control_flag(self):
        for args in (["up", "--kernel", "--control-path", ""], ["up", "--control-path"]):
            with self.subTest(args=args):
                self.rejected(args, "InvalidControlPath")

    def test_bad_gossip_port_precedes_identity_and_interface_setup(self):
        for value in ("", "0", "65536", "invalid"):
            with self.subTest(value=value):
                self.env["MESHGUARD_GOSSIP_PORT"] = value
                self.rejected(["up", "--kernel"], "invalid --gossip-port")
        self.env.pop("MESHGUARD_GOSSIP_PORT")
        self.rejected(["up", "--kernel", "--gossip-port"], "invalid --gossip-port")
        self.rejected(["up", "--kernel", "--gossip-port", "0"], "invalid --gossip-port")

    def test_explicit_unavailable_socket_cannot_fall_back_to_kernel_interface(self):
        # On a regressed Linux binary `down` can remove mg0. Refuse live hosts.
        if sys.platform.startswith("linux") and Path("/sys/class/net/mg0").exists():
            self.skipTest("run this check in an isolated host without mg0")
        for command in ("appinfo", "status", "down"):
            with self.subTest(command=command):
                self.rejected([command], "ExplicitControlSocketUnavailable")

    def test_hyphen_prefixed_channels_are_positional(self):
        for channel in ("-alerts", "--wait"):
            with self.subTest(channel=channel):
                self.rejected(["apprecv", channel], "ExplicitControlSocketUnavailable")

    def receive_fixture(self, fragmented):
        payload = "\x01" * 948 + "\U0001f680"  # exactly 952 UTF-8 bytes
        response = (json.dumps({"ok": True, "sender": "a" * 64, "data": payload,
                                "timestamp": 1}) + "\n").encode()
        self.assertGreater(len(response), 4096)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.settimeout(3)
        server.bind(self.env["MESHGUARD_CONTROL_PATH"])
        server.listen(1)
        commands = []

        def serve():
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(3)
                    command = b""
                    while not command.endswith(b"\n"):
                        chunk = conn.recv(1024)
                        if not chunk:
                            return
                        command += chunk
                    commands.append(command)
                    if fragmented:
                        conn.sendall(response[:113])
                        time.sleep(0.03)
                        conn.sendall(response[113:])
                    else:
                        conn.sendall(response)
            except OSError:
                # A regressed client may close early; stdout assertions catch it.
                pass

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            result = subprocess.run([str(BINARY), "apprecv", "meshrooms-v1"], env=self.env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=10)
        finally:
            worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(commands, [b"APPRECV meshrooms-v1\n"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "From: " + "a" * 64 + "\nChannel: meshrooms-v1\nPayload:\n" + payload + "\n")

    @unittest.skipIf(os.name == "nt", "Unix stream fixture; Windows CLI parsing is checked separately")
    def test_worst_case_escaped_apprecv(self):
        self.receive_fixture(False)

    @unittest.skipIf(os.name == "nt", "Unix stream fixture; Windows uses message-mode pipes")
    def test_fragmented_apprecv(self):
        self.receive_fixture(True)


if __name__ == "__main__":
    unittest.main()
