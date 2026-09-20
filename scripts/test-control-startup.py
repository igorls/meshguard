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


class WindowsPipe:
    """A byte-mode pipe matching the daemon, with the socket fixture interface."""
    def __init__(self, path):
        import ctypes
        from ctypes import wintypes as wt
        self.ctypes = ctypes
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD,
                                            wt.DWORD, wt.DWORD, wt.DWORD, wt.LPVOID]
        self.api.CreateNamedPipeW.restype = wt.HANDLE
        self.api.ConnectNamedPipe.argtypes = [wt.HANDLE, wt.LPVOID]
        self.api.ReadFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
        self.api.WriteFile.argtypes = self.api.ReadFile.argtypes
        self.api.FlushFileBuffers.argtypes = [wt.HANDLE]
        self.api.DisconnectNamedPipe.argtypes = [wt.HANDLE]
        self.api.CloseHandle.argtypes = [wt.HANDLE]
        self.handle = self.api.CreateNamedPipeW(path, 3, 0, 1, 4096, 4096, 5000, None)
        if self.handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())

    def accept(self):
        if not self.api.ConnectNamedPipe(self.handle, None) and self.ctypes.get_last_error() != 535:
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        return self, None

    def settimeout(self, seconds):
        pass  # The fixture thread and client process have bounded waits.

    def recv(self, size):
        buf = self.ctypes.create_string_buffer(size)
        count = self.ctypes.c_ulong()
        if not self.api.ReadFile(self.handle, buf, size, self.ctypes.byref(count), None):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        return buf.raw[:count.value]

    def sendall(self, data):
        buf = self.ctypes.create_string_buffer(data)
        count = self.ctypes.c_ulong()
        if not self.api.WriteFile(self.handle, buf, len(data), self.ctypes.byref(count), None):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        if count.value != len(data):
            raise OSError("short fixture write")

    def close(self):
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.api.FlushFileBuffers(self.handle)
        self.api.DisconnectNamedPipe(self.handle)


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

    @unittest.skipIf(os.name == "nt", "Unix filesystem socket paths only")
    def test_control_path_preserves_existing_files(self):
        sentinel = Path(self.temp.name) / "important.txt"
        sentinel.write_bytes(b"must survive startup and cleanup")
        link = Path(self.temp.name) / "linked.sock"
        link.symlink_to(sentinel)
        for path in (sentinel, link, Path(self.temp.name)):
            with self.subTest(path=path):
                self.env["MESHGUARD_CONTROL_PATH"] = str(path)
                self.rejected(["appinfo"], "InvalidControlPath")
                self.rejected(["up", "--kernel"], "InvalidControlPath")
                self.rejected(["up", "--kernel", "--control-path", str(path)], "InvalidControlPath")
                self.assertEqual(sentinel.read_bytes(), b"must survive startup and cleanup")
                self.assertTrue(link.is_symlink())

    def receive_fixture(self, fragmented):
        payload = "\x01" * 948 + "\U0001f680"  # exactly 952 UTF-8 bytes
        response = (json.dumps({"ok": True, "sender": "a" * 64, "data": payload,
                                "timestamp": 1}) + "\n").encode()
        self.assertGreater(len(response), 4096)
        if os.name == "nt":
            server = WindowsPipe(self.env["MESHGUARD_CONTROL_PATH"])
        else:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(self.env["MESHGUARD_CONTROL_PATH"])
            server.listen(1)
        self.addCleanup(server.close)
        server.settimeout(3)
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

    def test_worst_case_escaped_apprecv(self):
        self.receive_fixture(False)

    def test_fragmented_apprecv(self):
        self.receive_fixture(True)


if __name__ == "__main__":
    unittest.main()
