import contextlib
import io
import sys
import unittest
from unittest.mock import MagicMock, patch

from endoscan import (
    MAX_TIMEOUT,
    MAX_WORKERS,
    VERSION,
    main,
    parse_ports,
    resolve_target,
    scan_port,
    scan_ports,
)


class TestParsePorts(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_port_range(self):
        self.assertEqual(parse_ports("20-25"), [20, 21, 22, 23, 24, 25])

    def test_comma_separated_ports_are_trimmed_and_sorted(self):
        self.assertEqual(parse_ports(" 443, 22,80 "), [22, 80, 443])

    def test_duplicate_ports_removed(self):
        self.assertEqual(parse_ports("80,80,443"), [80, 443])

    def test_boundary_ports_accepted(self):
        self.assertEqual(parse_ports("1,65535"), [1, 65535])

    def test_out_of_range_ports_rejected(self):
        for value in ("0", "65536", "0-80", "80-65536", "22,65536"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)

    def test_reversed_range_rejected(self):
        with self.assertRaisesRegex(ValueError, "start port"):
            parse_ports("100-20")

    def test_invalid_numeric_syntax_rejected(self):
        for value in ("", "abc", "22,,80", "22-", "1-2-3", "22,80-82"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)

    def test_invalid_large_range_is_rejected_before_expansion(self):
        with self.assertRaisesRegex(ValueError, "999999999"):
            parse_ports("1-999999999")


class TestResolveTarget(unittest.TestCase):
    @patch("endoscan.socket.gethostbyname", return_value="192.0.2.10")
    def test_hostname_resolves_to_ipv4_address(self, gethostbyname):
        self.assertEqual(resolve_target("example.test"), "192.0.2.10")
        gethostbyname.assert_called_once_with("example.test")

    @patch("endoscan.socket.gethostbyname", side_effect=OSError)
    def test_non_dns_os_error_is_not_misreported(self, _gethostbyname):
        with self.assertRaises(OSError):
            resolve_target("example.test")

    @patch("endoscan.socket.gethostbyname")
    def test_resolution_failure_has_clear_error(self, gethostbyname):
        import socket

        gethostbyname.side_effect = socket.gaierror("not found")
        with self.assertRaisesRegex(ValueError, "Could not resolve target"):
            resolve_target("missing.invalid")

    @patch("endoscan.socket.gethostbyname", side_effect=UnicodeError)
    def test_invalid_hostname_encoding_has_clear_error(self, _gethostbyname):
        with self.assertRaisesRegex(ValueError, "Could not resolve target"):
            resolve_target("invalid-hostname")


class TestScanPort(unittest.TestCase):
    def test_real_loopback_listener_is_open(self):
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            self.assertEqual(scan_port("127.0.0.1", port, 1.0), "OPEN")

    def _scan_with_connect_effect(self, effect=None):
        fake_socket = MagicMock()
        fake_socket.connect.side_effect = effect

        with patch("endoscan.socket.socket", return_value=fake_socket):
            result = scan_port("192.0.2.1", 443, 0.25)

        fake_socket.settimeout.assert_called_once_with(0.25)
        fake_socket.connect.assert_called_once_with(("192.0.2.1", 443))
        fake_socket.close.assert_called_once_with()
        return result

    def test_success_is_open_and_socket_is_closed(self):
        self.assertEqual(self._scan_with_connect_effect(), "OPEN")

    def test_refused_connection_is_closed_and_socket_is_closed(self):
        self.assertEqual(
            self._scan_with_connect_effect(ConnectionRefusedError()), "CLOSED"
        )

    def test_socket_timeout_is_timeout_and_socket_is_closed(self):
        import socket

        self.assertEqual(self._scan_with_connect_effect(socket.timeout()), "TIMEOUT")

    def test_other_os_error_is_error_and_socket_is_closed(self):
        self.assertEqual(self._scan_with_connect_effect(OSError()), "ERROR")

    @patch("endoscan.socket.socket", side_effect=OSError("socket unavailable"))
    def test_socket_creation_failure_is_error(self, _socket_factory):
        self.assertEqual(scan_port("192.0.2.1", 443, 0.25), "ERROR")

    @patch("endoscan.socket.socket")
    def test_invalid_socket_timeout_is_error_and_socket_is_closed(self, socket_factory):
        socket_factory.return_value.settimeout.side_effect = OverflowError
        self.assertEqual(scan_port("192.0.2.1", 443, 1e300), "ERROR")
        socket_factory.return_value.close.assert_called_once_with()


class TestScanPorts(unittest.TestCase):
    @patch("endoscan.scan_port")
    def test_results_are_deduplicated_and_deterministically_ordered(self, scan):
        scan.side_effect = lambda _target, port, _timeout: f"STATE-{port}"

        results = scan_ports("192.0.2.1", [443, 22, 443, 80], 1.0, 2)

        self.assertEqual(list(results), [22, 80, 443])
        self.assertEqual(results[80], "STATE-80")

    def test_empty_port_collection_returns_empty_result(self):
        self.assertEqual(scan_ports("192.0.2.1", [], 1.0, 2), {})

    def test_invalid_worker_counts_rejected(self):
        for workers in (0, MAX_WORKERS + 1):
            with self.subTest(workers=workers), self.assertRaises(ValueError):
                scan_ports("192.0.2.1", [80], 1.0, workers)


class TestCli(unittest.TestCase):
    def _run_main(self, arguments):
        stderr = io.StringIO()
        with patch.object(sys, "argv", ["endoscan.py", *arguments]):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exit_context:
                    main()
        return exit_context.exception.code, stderr.getvalue()

    def test_invalid_timeouts_exit_with_usage_error(self):
        for timeout in ("nan", "inf", "0", "-1", str(MAX_TIMEOUT + 1)):
            with self.subTest(timeout=timeout):
                code, error = self._run_main(
                    ["127.0.0.1", "-p", "80", "-t", timeout]
                )
                self.assertEqual(code, 2)
                self.assertIn("Timeout must be greater than 0 and at most", error)

    def test_worker_limit_exit_with_usage_error(self):
        code, error = self._run_main(
            ["127.0.0.1", "-p", "80", "-w", str(MAX_WORKERS + 1)]
        )
        self.assertEqual(code, 2)
        self.assertIn(f"Workers must be between 1 and {MAX_WORKERS}", error)

    def test_invalid_ports_exit_with_usage_error(self):
        code, error = self._run_main(["127.0.0.1", "-p", "22,,80"])
        self.assertEqual(code, 2)
        self.assertIn("Invalid comma-separated port list", error)

    @patch("endoscan.resolve_target", side_effect=ValueError("DNS failed"))
    def test_dns_failure_exits_with_usage_error(self, _resolve_target):
        code, error = self._run_main(["example.test", "-p", "80"])
        self.assertEqual(code, 2)
        self.assertIn("DNS failed", error)

    def test_version_matches_module_version(self):
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["endoscan.py", "--version"]):
            with contextlib.redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as exit_context:
                    main()

        self.assertEqual(exit_context.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), f"EndoScan {VERSION}")


if __name__ == "__main__":
    unittest.main()
