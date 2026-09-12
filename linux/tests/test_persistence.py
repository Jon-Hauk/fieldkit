import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.persistence import (
    package_owned,
    persistence_paths,
    persistence_surface,
)
from fieldkit_linux.common import Host, Unavailable


class PersistenceTests(unittest.TestCase):
    def test_file_sources_and_user_homes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = (
                "etc/systemd/system/local.service",
                "etc/systemd/system/local.timer",
                "etc/systemd/system/local.service.d/override.conf",
                "etc/cron.d/local",
                "etc/rc.local",
                "var/spool/cron/crontabs/alice",
                "home/alice/.config/systemd/user/local.service",
            )
            for path in files:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("", encoding="utf-8")
            (root / "etc/passwd").write_text(
                "alice:x:1000:1000::/home/alice:/bin/bash\n", encoding="utf-8"
            )
            paths, gaps = persistence_paths(Host(root))
            self.assertEqual(paths, sorted("/" + path for path in files))
            self.assertEqual(gaps, [])

    def test_package_owned_and_missing(self):
        host = Host()
        with patch.object(host, "command", return_value="package: /etc/crontab\n"):
            self.assertTrue(package_owned(host, "/etc/crontab"))
        with patch.object(
            host, "command", side_effect=Unavailable("no path found matching pattern")
        ):
            self.assertFalse(package_owned(host, "/etc/crontab"))

    def test_similar_package_path_is_not_exact_ownership(self):
        host = Host()
        with (
            patch.object(host, "command", return_value="package: /etc/crontab.other\n"),
            self.assertRaises(Unavailable),
        ):
            package_owned(host, "/etc/crontab")

    def test_package_queries_are_cached_per_directory(self):
        host = Host()
        cache = {}
        with patch.object(
            host,
            "command",
            return_value=(
                "package: /etc/systemd/system/a.service\n"
                "package: /etc/systemd/system/b.service\n"
            ),
        ) as command:
            self.assertTrue(package_owned(host, "/etc/systemd/system/a.service", cache))
            self.assertTrue(package_owned(host, "/etc/systemd/system/b.service", cache))
            self.assertFalse(
                package_owned(host, "/etc/systemd/system/local.service", cache)
            )
            command.assert_called_once()

    def test_unowned_warn_and_owned_info(self):
        host = Host()
        with (
            patch(
                "fieldkit_linux.checks.persistence.persistence_paths",
                return_value=(["/etc/rc.local"], []),
            ),
            patch.object(host, "which", return_value="/bin/dpkg-query"),
            patch(
                "fieldkit_linux.checks.persistence.package_owned", return_value=False
            ),
        ):
            self.assertEqual(persistence_surface(host).Status, "WARN")
        with (
            patch(
                "fieldkit_linux.checks.persistence.persistence_paths",
                return_value=(["/etc/rc.local"], []),
            ),
            patch.object(host, "which", return_value="/bin/dpkg-query"),
            patch("fieldkit_linux.checks.persistence.package_owned", return_value=True),
        ):
            self.assertEqual(persistence_surface(host).Status, "INFO")

    def test_missing_tool_and_unreadable_inventory_unknown(self):
        host = Host()
        with (
            patch(
                "fieldkit_linux.checks.persistence.persistence_paths",
                return_value=([], []),
            ),
            patch.object(host, "which", return_value=None),
        ):
            self.assertEqual(persistence_surface(host).Status, "UNKN")
        with (
            patch(
                "fieldkit_linux.checks.persistence.persistence_paths",
                return_value=([], ["needs root to read"]),
            ),
            patch.object(host, "which", return_value="/bin/dpkg-query"),
        ):
            self.assertEqual(persistence_surface(host).Status, "UNKN")


if __name__ == "__main__":
    unittest.main()
