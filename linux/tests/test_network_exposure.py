import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fieldkit_linux.checks.network_exposure import listening_sockets
from fieldkit_linux.common import Host, Unavailable, run_check


class SocketTests(unittest.TestCase):
    def result(self, sockets, addresses="[]"):
        host = Host()
        with patch.object(host, "command", side_effect=[sockets, addresses]):
            return listening_sockets(host)

    def test_loopback_and_wildcards(self):
        result = self.result(
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
            "tcp LISTEN 0 128 [::]:22 [::]:*\n"
            "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
            "udp UNCONN 0 0 *:111 *:*"
        )
        self.assertEqual(result.Status, "INFO")
        for label in (
            "IPv4 wildcard",
            "IPv6 wildcard",
            "loopback",
            "family unspecified",
        ):
            self.assertIn(label, result.Detail)

    def test_tailnet_requires_interface_evidence(self):
        socket = "tcp LISTEN 0 128 100.64.0.1:443 0.0.0.0:*"
        addresses = json.dumps(
            [
                {
                    "ifname": "tailscale0",
                    "addr_info": [{"family": "inet", "local": "100.64.0.1"}],
                }
            ]
        )
        self.assertIn("interfaces=tailscale0", self.result(socket, addresses).Detail)
        self.assertEqual(self.result(socket).Status, "UNKN")

    def test_scoped_ipv6(self):
        addresses = json.dumps(
            [{"ifname": "eth0", "addr_info": [{"family": "inet6", "local": "fe80::1"}]}]
        )
        self.assertIn(
            "interfaces=eth0",
            self.result("udp UNCONN 0 0 [fe80::1%eth0]:123 [::]:*", addresses).Detail,
        )
        self.assertEqual(
            self.result("udp UNCONN 0 0 [fe80::1%eth1]:123 [::]:*", addresses).Status,
            "UNKN",
        )

    def test_malformed_output_unknown(self):
        self.assertEqual(self.result("nonsense").Status, "UNKN")
        self.assertEqual(self.result("", "{}").Status, "UNKN")
        self.assertEqual(
            self.result("tcp LISTEN 0 128 0.0.0.0:99999 *:*").Status, "UNKN"
        )

    def test_missing_tools_and_permission_unknown(self):
        host = Host()
        with patch.object(
            host, "command", side_effect=Unavailable("missing binary: ss")
        ):
            self.assertEqual(
                run_check("Network", "Sockets", lambda: listening_sockets(host)).Status,
                "UNKN",
            )
        with patch.object(
            host,
            "command",
            side_effect=["tcp LISTEN 0 128 127.0.0.1:22 *:*", PermissionError()],
        ):
            result = listening_sockets(host)
            self.assertEqual(result.Status, "UNKN")
            self.assertIn("loopback", result.Detail)

    def test_empty_and_deterministic(self):
        self.assertEqual(self.result("").Status, "INFO")
        a = "tcp LISTEN 0 128 127.0.0.1:22 *:*"
        b = "tcp LISTEN 0 128 [::1]:80 *:*"
        self.assertEqual(
            self.result(a + "\n" + b).Detail, self.result(b + "\n" + a).Detail
        )
