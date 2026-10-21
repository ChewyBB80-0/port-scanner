"""Unit tests for scanner.py.

Network tests only touch throwaway servers on 127.0.0.1, never a real target.
The SYN-scan tests swap in a fake Scapy, so they need neither root nor Scapy.

Run:  python -m unittest discover -s tests -v
"""
import errno
import socket
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scanner  # noqa: E402


# ---------- helpers: tiny local servers ----------
class LocalServer:
    """A listening socket on 127.0.0.1 that runs `handler(conn)` for each connection."""

    def __init__(self, handler=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return                      # socket closed: test is over
            with conn:
                if self.handler:
                    try:
                        self.handler(conn)
                    except OSError:
                        pass

    def close(self):
        self.sock.close()


def free_closed_port():
    """A port nothing is listening on: bind it, note the number, release it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------- connect scan ----------
class ConnectScanTests(unittest.TestCase):
    def test_open_port(self):
        srv = LocalServer()
        self.addCleanup(srv.close)
        self.assertEqual(scanner.scan_port("127.0.0.1", srv.port), "open")

    def test_closed_port(self):
        self.assertEqual(scanner.scan_port("127.0.0.1", free_closed_port()), "closed")

    def test_filtered_when_no_answer(self):
        # A timeout code (no SYN/ACK, no RST) must read as filtered, not closed.
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ETIMEDOUT
        with mock.patch.object(scanner.socket, "socket", return_value=fake):
            self.assertEqual(scanner.scan_port("192.0.2.1", 80), "filtered")


# ---------- banner grabbing ----------
class BannerTests(unittest.TestCase):
    def test_service_that_speaks_first(self):
        srv = LocalServer(lambda conn: conn.sendall(b"SSH-2.0-TestServer\r\n"))
        self.addCleanup(srv.close)
        self.assertEqual(scanner.grab_banner("127.0.0.1", srv.port), "SSH-2.0-TestServer")

    def test_silent_service_gets_http_probe(self):
        def http(conn):
            if conn.recv(1024).startswith(b"HEAD"):
                conn.sendall(b"HTTP/1.0 200 OK\r\nServer: test\r\n\r\n")
        srv = LocalServer(http)
        self.addCleanup(srv.close)
        banner = scanner.grab_banner("127.0.0.1", srv.port)
        self.assertTrue(banner.startswith("HTTP/1.0 200 OK"), banner)

    def test_closed_port_has_no_banner(self):
        self.assertIsNone(scanner.grab_banner("127.0.0.1", free_closed_port()))


# ---------- SYN scan flag logic (fake Scapy) ----------
class _Pkt:
    """Stands in for scapy's IP()/TCP(): records fields and supports the / operator."""

    def __init__(self, **fields):
        self.fields = fields

    def __truediv__(self, other):
        return {**self.fields, **other.fields}


class _Reply:
    def __init__(self, flags):
        self._tcp = types.SimpleNamespace(flags=flags)

    def haslayer(self, layer):
        return True

    def __getitem__(self, layer):
        return self._tcp


def fake_scapy(reply):
    sent = []
    mod = types.ModuleType("scapy.all")
    mod.IP = mod.TCP = _Pkt
    mod.sr1 = lambda pkt, timeout=None: reply
    mod.send = lambda pkt, verbose=0: sent.append(pkt)
    mod.conf = types.SimpleNamespace(verb=1)
    pkg = types.ModuleType("scapy")
    pkg.all = mod
    return {"scapy": pkg, "scapy.all": mod}, sent


class SynScanTests(unittest.TestCase):
    def syn(self, reply):
        modules, sent = fake_scapy(reply)
        with mock.patch.dict(sys.modules, modules):
            return scanner.syn_scan("192.0.2.1", 22), sent

    def test_syn_ack_is_open_and_torn_down(self):
        state, sent = self.syn(_Reply(0x12))
        self.assertEqual(state, "open")
        self.assertEqual(len(sent), 1, "an open port must get exactly one RST")
        self.assertEqual(sent[0]["flags"], "R")

    def test_rst_ack_is_closed(self):
        state, sent = self.syn(_Reply(0x14))
        self.assertEqual(state, "closed")
        self.assertEqual(sent, [])

    def test_no_reply_is_filtered(self):
        state, sent = self.syn(None)
        self.assertEqual(state, "filtered")
        self.assertEqual(sent, [])


# ---------- resolution + the orchestrator ----------
class ScanTests(unittest.TestCase):
    def test_unresolvable_host_is_skipped(self):
        # .invalid is reserved by RFC 2606 and can never resolve.
        self.assertEqual(scanner.resolve(["127.0.0.1", "no-such-host.invalid"]), ["127.0.0.1"])

    def test_scan_reports_open_and_closed(self):
        srv = LocalServer()
        self.addCleanup(srv.close)
        closed = free_closed_port()
        open_by_host, counts, ips = scanner.scan(["127.0.0.1"], [srv.port, closed], workers=4)
        self.assertEqual(ips, ["127.0.0.1"])
        self.assertEqual(open_by_host["127.0.0.1"], [srv.port])
        self.assertEqual(counts["open"], 1)
        self.assertEqual(counts["closed"], 1)


if __name__ == "__main__":
    unittest.main()
