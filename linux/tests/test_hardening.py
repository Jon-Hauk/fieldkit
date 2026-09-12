import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.hardening import mac_enforcement
from fieldkit_linux.common import Host, run_check


class HostFixture:
    def __init__(
        self, modules="capability,apparmor", profiles="fixture (enforce)\n", mode="1"
    ):
        self.files = {
            "/sys/kernel/security/lsm": modules,
            "/sys/kernel/security/apparmor/profiles": profiles,
            "/sys/fs/selinux/enforce": mode,
        }

    def read_text(self, path):
        value = self.files[path]
        if isinstance(value, Exception):
            raise value
        return value


class MacTests(unittest.TestCase):
    def test_apparmor_enforcing(self):
        self.assertEqual(mac_enforcement(HostFixture()).Status, "PASS")

    def test_apparmor_non_enforcing_is_warn(self):
        for mode in ("complain", "unconfined", "prompt"):
            finding = mac_enforcement(
                HostFixture(profiles=f"a (enforce)\nb ({mode})\n")
            )
            self.assertEqual(finding.Status, "WARN")

    def test_empty_profiles_are_warn(self):
        self.assertEqual(mac_enforcement(HostFixture(profiles="")).Status, "WARN")

    def test_kill_mode_enforces(self):
        self.assertEqual(
            mac_enforcement(HostFixture(profiles="a (kill)\n")).Status, "PASS"
        )

    def test_unknown_mode_is_unknown(self):
        self.assertEqual(
            mac_enforcement(HostFixture(profiles="a (future)\n")).Status, "UNKN"
        )

    def test_selinux_enforcing_and_permissive(self):
        for mode, expected in (("1", "PASS"), ("0", "WARN"), ("bad", "UNKN")):
            self.assertEqual(
                mac_enforcement(
                    HostFixture(modules="capability,selinux", mode=mode)
                ).Status,
                expected,
            )

    def test_inactive_frameworks_fail(self):
        self.assertEqual(
            mac_enforcement(HostFixture(modules="capability,yama")).Status, "FAIL"
        )

    def test_missing_interface_unknown(self):
        result = mac_enforcement(HostFixture(profiles=FileNotFoundError()))
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("kernel interface unavailable", result.Detail)

    def test_permission_denial_unknown(self):
        result = mac_enforcement(HostFixture(profiles=PermissionError()))
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("needs root to read", result.Detail)

    def test_unreadable_lsm_list_unknown(self):
        host = HostFixture(modules=PermissionError())
        self.assertEqual(
            run_check("s", "n", lambda: mac_enforcement(host)).Status, "UNKN"
        )

    def test_empty_lsm_list_unknown(self):
        self.assertEqual(mac_enforcement(HostFixture(modules="")).Status, "UNKN")

    def test_partial_state_does_not_pass(self):
        result = mac_enforcement(
            HostFixture(modules="apparmor,selinux", profiles=PermissionError())
        )
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("SELinux global mode: enforcing", result.Detail)

    @unittest.skipIf(os.geteuid() == 0, "requires an unprivileged process")
    def test_real_unreadable_file_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            security = root / "sys/kernel/security"
            security.mkdir(parents=True)
            source = security / "lsm"
            source.write_text("apparmor", encoding="utf-8")
            source.chmod(0)
            try:
                result = run_check(
                    "Hardening", "MAC", lambda: mac_enforcement(Host(root))
                )
                self.assertEqual(result.Status, "UNKN")
                self.assertEqual(result.Detail, "needs root to read")
            finally:
                source.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
