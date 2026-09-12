import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.identity import (
    privileged_accounts,
    sudo_policy,
)
from fieldkit_linux.common import Host


class AccountsHost:
    def __init__(self, duplicate=False):
        self.passwd = (
            "root:x:0:0::/root:/bin/bash\nalice:x:1000:27::/home/alice:/bin/bash\n"
        )
        if duplicate:
            self.passwd += "other:x:0:0::/root:/bin/bash\n"

    def read_text(self, path):
        return self.passwd if path == "/etc/passwd" else "sudo:x:27:bob\n"


class IdentityTests(unittest.TestCase):
    def test_primary_and_supplementary_groups(self):
        result = privileged_accounts(AccountsHost())
        self.assertEqual(result.Status, "INFO")
        self.assertIn("sudo=[alice, bob]", result.Detail)

    def test_duplicate_uid_zero_fails(self):
        self.assertEqual(privileged_accounts(AccountsHost(True)).Status, "FAIL")

    def test_sudo_include_and_no_secret_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/sudoers.d").mkdir(parents=True)
            (root / "etc/sudoers").write_text(
                "@includedir /etc/sudoers.d\n", encoding="utf-8"
            )
            (root / "etc/sudoers.d/local").write_text(
                "alice ALL=(ALL) NOPASSWD: /bin/tool SECRET\n", encoding="utf-8"
            )
            (root / "etc/sudoers.d/ignored.bak").write_text("bad", encoding="utf-8")
            result = sudo_policy(Host(root))
            self.assertEqual(result.Status, "WARN")
            self.assertIn("/etc/sudoers.d/local:1", result.Detail)
            self.assertNotIn("SECRET", result.Detail)
            self.assertIn("inspected/attempted=2", result.Detail)

    def test_denied_sudoers_unknown(self):
        class Denied:
            def read_text(self, path):
                raise PermissionError()

        result = sudo_policy(Denied())
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("needs root to read", result.Detail)

    def test_comment_not_bypass(self):
        class Host:
            def read_text(self, path):
                return "# root ALL=NOPASSWD: ALL\nroot ALL=(ALL) ALL\n"

        self.assertEqual(sudo_policy(Host()).Status, "INFO")

    def test_include_cycle_unknown(self):
        class Host:
            def read_text(self, path):
                return "@include /etc/sudoers\n"

        self.assertEqual(sudo_policy(Host()).Status, "UNKN")

    def test_no_authenticate_warns(self):
        class Host:
            def read_text(self, path):
                return "Defaults !authenticate\n"

        self.assertEqual(sudo_policy(Host()).Status, "WARN")

    @unittest.skipIf(os.geteuid() == 0, "requires unprivileged file permissions")
    def test_real_unreadable_sudoers_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            source = root / "etc/sudoers"
            source.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
            source.chmod(0)
            try:
                result = sudo_policy(Host(root))
                self.assertEqual(result.Status, "UNKN")
                self.assertIn("needs root to read", result.Detail)
            finally:
                source.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
