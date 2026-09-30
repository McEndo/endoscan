import unittest

from endoscan import parse_ports, resolve_target


class TestParsePorts(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_port_range(self):
        self.assertEqual(
            parse_ports("20-25"),
            [20, 21, 22, 23, 24, 25]
        )

    def test_comma_separated_ports(self):
        self.assertEqual(
            parse_ports("22,80,443"),
            [22, 80, 443]
        )

    def test_duplicate_ports_removed(self):
        self.assertEqual(
            parse_ports("80,80,443"),
            [80, 443]
        )

    def test_port_zero_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_port_above_65535_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("65536")

    def test_reversed_range_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("100-20")

    def test_non_numeric_port_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("abc")

    def test_double_comma_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("22,,80")


class TestResolveTarget(unittest.TestCase):

    def test_localhost_resolves(self):
        self.assertEqual(
            resolve_target("127.0.0.1"),
            "127.0.0.1"
        )

    def test_invalid_hostname_rejected(self):
        with self.assertRaises(ValueError):
            resolve_target("this-host-should-not-exist.invalid")


if __name__ == "__main__":
    unittest.main()