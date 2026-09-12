import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.audit import (
    audit_trail,
    journal_settings,
    persistent_journal_present,
)
from fieldkit_linux.common import Host, Unavailable


class AuditHost:
    def __init__(self):
        self.config = (
            "[Journal]\nStorage=persistent\nMaxRetentionSec=30day\nSystemMaxUse=1G\n"
        )
        self.service = "LoadState=loaded\nActiveState=active\nSubState=running\n"

    def command(self, args):
        return self.config if args[0] == "systemd-analyze" else self.service


class AuditTests(unittest.TestCase):
    def check_host(self, host, present=True):
        with patch(
            "fieldkit_linux.checks.audit.persistent_journal_present",
            return_value=present,
        ):
            return audit_trail(host)

    def test_configured_retention_is_info_not_guaranteed_days(self):
        result = self.check_host(AuditHost())
        self.assertEqual(result.Status, "INFO")
        self.assertIn("not guaranteed retained days", result.Detail)

    def test_inactive_audit_warns(self):
        host = AuditHost()
        host.service = "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
        self.assertEqual(self.check_host(host).Status, "WARN")

    def test_volatile_and_missing_retention_warn(self):
        for config in ("[Journal]\nStorage=volatile", "[Journal]\nStorage=persistent"):
            host = AuditHost()
            host.config = config
            self.assertEqual(self.check_host(host).Status, "WARN")

    def test_missing_files_warn(self):
        self.assertEqual(self.check_host(AuditHost(), present=False).Status, "WARN")

    def test_denied_files_unknown(self):
        with patch(
            "fieldkit_linux.checks.audit.persistent_journal_present",
            side_effect=PermissionError(),
        ):
            result = audit_trail(AuditHost())
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("needs root to read", result.Detail)

    def test_missing_tool_unknown(self):
        host = AuditHost()
        host.command = lambda args: (_ for _ in ()).throw(
            Unavailable("missing binary: " + args[0])
        )
        self.assertEqual(self.check_host(host).Status, "UNKN")

    def test_comments_sections_and_dropin_overrides(self):
        text = "# Storage=volatile\n[Journal]\nStorage=auto\n[Other]\nStorage=none\n[Journal]\nStorage=persistent\n"
        self.assertEqual(journal_settings(text), {"Storage": "persistent"})

    def test_current_machine_files_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/machine-id").write_text("a" * 32, encoding="utf-8")
            journals = root / "var/log/journal" / ("a" * 32)
            journals.mkdir(parents=True)
            self.assertFalse(persistent_journal_present(Host(root)))
            (journals / "system.journal").write_bytes(b"")
            self.assertTrue(persistent_journal_present(Host(root)))


if __name__ == "__main__":
    unittest.main()
