import socket
import threading
import unittest

from port_scanner.scanner import (
    PortScanner, needs_authorization_warning, parse_ports, scan_port, service_name,
)


def start_server(banner: bytes = b"SSH-2.0-TestServer\r\n") -> tuple[socket.socket, int]:
    """Abre un servidor TCP local en un puerto libre que saluda con un banner."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.sendall(banner)

    threading.Thread(target=serve, daemon=True).start()
    return server, port


def free_port() -> int:
    """Un puerto que sabemos que está cerrado."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestParsePorts(unittest.TestCase):
    def test_list_and_ranges(self):
        self.assertEqual(parse_ports("22, 80,79-81"), [22, 79, 80, 81])

    def test_reversed_range(self):
        self.assertEqual(parse_ports("5-3"), [3, 4, 5])

    def test_invalid(self):
        for bad in ["", "abc", "0", "70000", "10-x"]:
            with self.assertRaises(ValueError):
                parse_ports(bad)


class TestScan(unittest.TestCase):
    def setUp(self):
        self.server, self.open_port = start_server()

    def tearDown(self):
        self.server.close()

    def test_open_port_with_banner(self):
        result = scan_port("127.0.0.1", self.open_port, timeout=1)
        self.assertIsNotNone(result)
        self.assertEqual(result.banner, "SSH-2.0-TestServer")

    def test_closed_port(self):
        self.assertIsNone(scan_port("127.0.0.1", free_port(), timeout=1))

    def test_scanner_finds_only_open_ports(self):
        closed = free_port()
        progress = []
        results = PortScanner(threads=10, timeout=1).scan(
            "127.0.0.1", [self.open_port, closed],
            on_progress=lambda done, total: progress.append((done, total)),
        )
        self.assertEqual([r.port for r in results], [self.open_port])
        self.assertEqual(progress[-1], (2, 2))

    def test_stop(self):
        scanner = PortScanner(threads=1, timeout=1)
        results = scanner.scan(
            "127.0.0.1", [self.open_port] + [free_port() for _ in range(50)],
            on_progress=lambda done, total: scanner.stop(),
        )
        self.assertTrue(scanner.stopped)
        self.assertLessEqual(len(results), 1)


class TestHelpers(unittest.TestCase):
    def test_service_name(self):
        self.assertEqual(service_name(22), "SSH")
        self.assertEqual(service_name(3389), "RDP")

    def test_authorization_warning(self):
        self.assertFalse(needs_authorization_warning("localhost", "127.0.0.1"))
        self.assertFalse(needs_authorization_warning("router", "192.168.1.1"))
        self.assertFalse(needs_authorization_warning("scanme.nmap.org", "45.33.32.156"))
        self.assertTrue(needs_authorization_warning("example.com", "93.184.216.34"))


if __name__ == "__main__":
    unittest.main()
