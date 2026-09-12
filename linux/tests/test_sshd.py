import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.hardening import sshd_configuration
from fieldkit_linux.common import Host, Unavailable, run_check


class SshHost:
    def __init__(self, root="no", password="no", pubkey="yes"):
        self.output = (
            f"permitrootlogin {root}\npasswordauthentication {password}\n"
            f"pubkeyauthentication {pubkey}\n"
        )

    def command(self, args):
        if args != ["sshd", "-T"]:
            raise AssertionError("Unexpected command")
        return self.output


class SshTests(unittest.TestCase):
    def test_restrictive_global_config_passes_with_scope(self):
        result = sshd_configuration(SshHost())
        self.assertEqual(result.Status, "PASS")
        self.assertIn("Match rules", result.Detail)
        self.assertIn("does not prove key-only", result.Detail)

    def test_unrestricted_root_login_fails(self):
        self.assertEqual(sshd_configuration(SshHost(root="yes")).Status, "FAIL")

    def test_restricted_root_login_still_needs_review(self):
        for value in ("prohibit-password", "without-password", "forced-commands-only"):
            self.assertEqual(sshd_configuration(SshHost(root=value)).Status, "WARN")

    def test_password_and_disabled_pubkey_warn(self):
        self.assertEqual(sshd_configuration(SshHost(password="yes")).Status, "WARN")
        self.assertEqual(sshd_configuration(SshHost(pubkey="no")).Status, "WARN")

    def test_missing_duplicate_and_malformed_are_unknown(self):
        for output in (
            "",
            "permitrootlogin\n",
            "pubkeyauthentication maybe\n",
            "permitrootlogin no\npermitrootlogin yes\n",
        ):
            host = SshHost()
            host.output = output
            self.assertEqual(sshd_configuration(host).Status, "UNKN")

    def test_unrelated_values_are_not_reported(self):
        host = SshHost()
        host.output += "banner PRIVATE_PATH\n"
        self.assertNotIn("PRIVATE_PATH", sshd_configuration(host).Detail)

    def test_missing_binary_is_unknown(self):
        with patch("shutil.which", return_value=None):
            result = run_check("Hardening", "SSH", lambda: sshd_configuration(Host()))
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("missing binary: sshd", result.Detail)

    def test_no_hostkeys_is_unknown_not_a_policy_failure(self):
        host = SshHost()
        host.command = lambda args: (_ for _ in ()).throw(
            Unavailable("no hostkeys available")
        )
        result = run_check("Hardening", "SSH", lambda: sshd_configuration(host))
        self.assertEqual(result.Status, "UNKN")


if __name__ == "__main__":
    unittest.main()
