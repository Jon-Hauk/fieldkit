import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.updates import automatic_updates
from fieldkit_linux.common import Unavailable


class UpdateHost:
    def __init__(self):
        self.config = (
            'APT::Periodic::Unattended-Upgrade "1";\n'
            'APT::Periodic::Update-Package-Lists "1";\n'
            'Unattended-Upgrade::Allowed-Origins:: "Ubuntu:jammy-security";\n'
        )
        self.package = "install ok installed"
        self.timer = "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n"
        self.log = "INFO All upgrades installed"

    def command(self, args):
        return {
            "dpkg-query": self.package,
            "apt-config": self.config,
            "systemctl": self.timer,
        }[args[0]]

    def read_text(self, path):
        if isinstance(self.log, Exception):
            raise self.log
        return self.log


class UpdateTests(unittest.TestCase):
    def test_configured_scheduled_and_executed_passes(self):
        result = automatic_updates(UpdateHost())
        self.assertEqual(result.Status, "PASS")
        self.assertIn("does not prove recent success", result.Detail)

    def test_installed_without_execution_warns(self):
        host = UpdateHost()
        host.log = "INFO Starting unattended upgrades script"
        self.assertEqual(automatic_updates(host).Status, "WARN")

    def test_disabled_periodic_warns(self):
        host = UpdateHost()
        host.config += 'APT::Periodic::Enable "0";\n'
        self.assertEqual(automatic_updates(host).Status, "WARN")

    def test_disabled_timer_warns(self):
        host = UpdateHost()
        host.timer = host.timer.replace("enabled", "disabled")
        self.assertEqual(automatic_updates(host).Status, "WARN")

    def test_missing_logs_warn(self):
        host = UpdateHost()
        host.log = FileNotFoundError()
        self.assertEqual(automatic_updates(host).Status, "WARN")

    def test_denied_logs_unknown(self):
        host = UpdateHost()
        host.log = PermissionError()
        result = automatic_updates(host)
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("needs root to read", result.Detail)

    def test_missing_tool_unknown(self):
        host = UpdateHost()
        host.command = lambda args: (_ for _ in ()).throw(
            Unavailable("missing binary: " + args[0])
        )
        self.assertEqual(automatic_updates(host).Status, "UNKN")

    def test_no_security_origin_warns(self):
        host = UpdateHost()
        host.config = host.config.replace("jammy-security", "jammy-updates")
        self.assertEqual(automatic_updates(host).Status, "WARN")

    def test_malformed_interval_unknown(self):
        host = UpdateHost()
        host.config += 'APT::Periodic::Enable "invalid";\n'
        self.assertEqual(automatic_updates(host).Status, "UNKN")

    def test_security_pattern_and_noop(self):
        host = UpdateHost()
        host.config = host.config.replace(
            'Allowed-Origins:: "Ubuntu:jammy-security"',
            'Origins-Pattern:: "origin=Ubuntu,archive=jammy-security"',
        )
        host.log = "INFO No packages found that can be upgraded unattended"
        self.assertEqual(automatic_updates(host).Status, "PASS")


if __name__ == "__main__":
    unittest.main()
