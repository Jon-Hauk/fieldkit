import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.firewall import (
    host_firewall,
    nft_policy,
    ufw_policy,
)
from fieldkit_linux.common import Unavailable


def ruleset(families=("inet",), policy="drop", expressions=None):
    entries = [
        {
            "chain": {
                "family": family,
                "table": "filter",
                "name": "input",
                "hook": "input",
                "type": "filter",
                "policy": policy,
            }
        }
        for family in families
    ]
    if expressions is not None:
        entries.append(
            {
                "rule": {
                    "family": families[0],
                    "table": "filter",
                    "chain": "input",
                    "expr": expressions,
                }
            }
        )
    return json.dumps({"nftables": entries})


class FirewallTests(unittest.TestCase):
    def test_dual_stack_drop(self):
        self.assertEqual(nft_policy(ruleset()).Status, "PASS")
        self.assertEqual(nft_policy(ruleset(("ip", "ip6"))).Status, "PASS")

    def test_single_family_is_not_full_pass(self):
        self.assertEqual(nft_policy(ruleset(("ip",))).Status, "WARN")

    def test_accept_policy_and_empty_ruleset_warn(self):
        self.assertEqual(nft_policy(ruleset(policy="accept")).Status, "WARN")
        self.assertEqual(nft_policy('{"nftables": []}').Status, "WARN")

    def test_unconditional_accept_warns(self):
        self.assertEqual(
            nft_policy(ruleset(expressions=[{"counter": {}}, {"accept": None}])).Status,
            "WARN",
        )

    def test_conditional_accept_retains_explicit_scope(self):
        result = nft_policy(ruleset(expressions=[{"match": {}}, {"accept": None}]))
        self.assertEqual(result.Status, "PASS")
        self.assertIn("conditional rules", result.Detail)

    def test_malformed_json_and_schema_unknown(self):
        for text in (
            "bad",
            "[]",
            "{}",
            '{"nftables": [null]}',
            '{"nftables": [{"chain": null}]}',
        ):
            self.assertEqual(nft_policy(text).Status, "UNKN")

    def test_ufw_active_deny(self):
        self.assertEqual(
            ufw_policy(
                "Status: active\nDefault: deny (incoming), allow (outgoing)",
                "IPV6=yes\n",
            ).Status,
            "PASS",
        )

    def test_ufw_disabled_and_allow_warn(self):
        self.assertEqual(ufw_policy("Status: inactive", "").Status, "WARN")
        self.assertEqual(
            ufw_policy("Status: active\nDefault: allow (incoming)", "IPV6=yes").Status,
            "WARN",
        )

    def test_ufw_ipv6_disabled_warns_unknown_value_unknown(self):
        text = "Status: active\nDefault: deny (incoming)"
        self.assertEqual(ufw_policy(text, "IPV6=no").Status, "WARN")
        self.assertEqual(ufw_policy(text, "").Status, "UNKN")

    def test_denied_and_missing_tools_unknown(self):
        class Host:
            def command(self, args):
                raise PermissionError()

        result = host_firewall(Host())
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("needs root to read", result.Detail)

        class Missing:
            def command(self, args):
                raise Unavailable("missing binary: " + args[0])

        self.assertEqual(host_firewall(Missing()).Status, "UNKN")

    def test_ufw_root_message_maps_to_permission_unknown(self):
        class Host:
            def command(self, args):
                raise Unavailable("You need to be root to run this script")

        self.assertIn("needs root to read", host_firewall(Host()).Detail)


if __name__ == "__main__":
    unittest.main()
