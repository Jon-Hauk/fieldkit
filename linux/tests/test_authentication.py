import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.authentication import (
    directory_enrollment,
    pam_mfa,
    ssh_authentication,
)
from fieldkit_linux.common import Host, Unavailable


class AuthenticationTests(unittest.TestCase):
    def test_pam_reference_and_bypass_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/pam.d").mkdir(parents=True)
            source = root / "etc/pam.d/sshd"
            source.write_text(
                "auth required pam_google_authenticator.so SECRET\n", encoding="utf-8"
            )
            result = pam_mfa(Host(root))
            self.assertEqual(result.Status, "INFO")
            self.assertNotIn("SECRET", result.Detail)
            source.write_text(
                "auth required pam_google_authenticator.so nullok\n", encoding="utf-8"
            )
            self.assertEqual(pam_mfa(Host(root)).Status, "WARN")

    def test_comment_does_not_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/pam.d").mkdir(parents=True)
            (root / "etc/pam.d/sshd").write_text(
                "# auth optional pam_duo.so\n", encoding="utf-8"
            )
            self.assertIn("none observed", pam_mfa(Host(root)).Detail)

    def test_ssh_key_only_requires_other_methods_disabled(self):
        output = (
            "pubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication no\n"
            "gssapiauthentication no\nhostbasedauthentication no\nauthenticationmethods any\n"
        )
        host = Host()
        with patch.object(host, "command", return_value=output):
            self.assertEqual(ssh_authentication(host).Status, "PASS")
        with patch.object(
            host,
            "command",
            return_value=output.replace(
                "kbdinteractiveauthentication no", "kbdinteractiveauthentication yes"
            ),
        ):
            self.assertEqual(ssh_authentication(host).Status, "INFO")
        with patch.object(host, "command", return_value="pubkeyauthentication yes"):
            self.assertEqual(ssh_authentication(host).Status, "UNKN")

    def test_directory_metadata_is_not_join_proof(self):
        host = Host()
        with patch.object(
            host,
            "command",
            side_effect=[
                "LoadState=loaded\nActiveState=active\nSubState=running",
                "private.example\n",
            ],
        ):
            result = directory_enrollment(host)
        self.assertEqual(result.Status, "INFO")
        self.assertIn("realmd-listed realms=1", result.Detail)
        self.assertNotIn("private.example", result.Detail)

    def test_directory_missing_tools_unknown(self):
        host = Host()
        with patch.object(host, "command", side_effect=Unavailable("missing binary")):
            self.assertEqual(directory_enrollment(host).Status, "UNKN")


if __name__ == "__main__":
    unittest.main()
