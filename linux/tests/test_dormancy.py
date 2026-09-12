import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.dormancy import dormant_accounts, login_state
from fieldkit_linux.common import Host, Unavailable

NOW = datetime(2026, 9, 8, tzinfo=timezone.utc)


class DormancyTests(unittest.TestCase):
    def test_recent_old_and_never(self):
        header = "Username Port From Latest\n"
        self.assertEqual(
            login_state(header + "a pts/0 h Mon Sep  7 12:00:00 +0000 2026", 90, NOW),
            "within threshold",
        )
        self.assertEqual(
            login_state(header + "a pts/0 h Thu Jan  1 12:00:00 +0000 2026", 90, NOW),
            "older than threshold",
        )
        self.assertEqual(
            login_state(header + "a **Never logged in**", 90, NOW), "no recorded login"
        )

    def test_malformed_and_future_unknown(self):
        for output in (
            "",
            "Username\na missing",
            "Username\na Tue Sep  8 12:00:00 +0000 2027",
        ):
            with self.assertRaises(Unavailable):
                login_state(output, 90, NOW)

    def test_stale_account_keys_warn_and_missing_tool_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host(directory)
            with (
                patch(
                    "fieldkit_linux.checks.dormancy.local_accounts",
                    return_value=[("a", 1000, 1000, "/home/a", "/bin/bash")],
                ),
                patch.object(host, "read_text", return_value="/bin/bash\n"),
                patch.object(
                    host,
                    "command",
                    return_value="Username Latest\na **Never logged in**",
                ),
                patch(
                    "fieldkit_linux.checks.dormancy.standard_key_count", return_value=2
                ),
            ):
                result = dormant_accounts(host, now=NOW)
                self.assertEqual(result.Status, "WARN")
                self.assertIn("authorized-key entries=2", result.Detail)
            with (
                patch(
                    "fieldkit_linux.checks.dormancy.local_accounts",
                    return_value=[("a", 1000, 1000, "/home/a", "/bin/bash")],
                ),
                patch.object(host, "read_text", return_value="/bin/bash\n"),
                patch.object(
                    host, "command", side_effect=Unavailable("missing binary: lastlog")
                ),
            ):
                self.assertEqual(dormant_accounts(host, now=NOW).Status, "UNKN")

    def test_orphan_home_key_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host(directory)
            (Path(directory) / "home/olduser").mkdir(parents=True)
            with (
                patch("fieldkit_linux.checks.dormancy.local_accounts", return_value=[]),
                patch.object(host, "read_text", return_value="/bin/bash\n"),
                patch(
                    "fieldkit_linux.checks.dormancy.standard_key_count", return_value=1
                ),
            ):
                result = dormant_accounts(host, now=NOW)
                self.assertEqual(result.Status, "WARN")
                self.assertIn("no local account uses this home", result.Detail)


if __name__ == "__main__":
    unittest.main()
