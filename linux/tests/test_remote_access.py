import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.remote_access import (
    remote_access,
    unit_candidates,
)
from fieldkit_linux.common import Unavailable


class HostFixture:
    def __init__(self, text="", binary=None, error=None):
        self.text = text
        self.binary = binary
        self.error = error

    def exists(self, path):
        return False

    def which(self, binary):
        if binary == "systemctl" and isinstance(self.error, Unavailable):
            return None
        return "/bin/" + binary if binary in ("systemctl", self.binary) else None

    def command(self, args):
        if self.error:
            raise self.error
        if args[1] == "list-unit-files":
            return "support.service enabled enabled\n"
        if args[1] == "list-units":
            return "support.service loaded active running Support\n"
        return self.text


class RemoteAccessTests(unittest.TestCase):
    def test_reverse_forward_variants_and_redaction(self):
        for command in (
            "/usr/bin/ssh -NT -R 2222:localhost:22 secret@private-host",
            "/usr/bin/autossh -fNR2222:localhost:22 secret@private-host",
            '/usr/bin/ssh -o "RemoteForward=2222 localhost:22" secret@private-host',
            '/bin/sh -c "ssh -R 2222:localhost:22 secret@private-host"',
            "/usr/bin/ssh -N \\\n+              -R 2222:localhost:22 secret@private-host",
        ):
            text = (
                "# /etc/systemd/system/support.service\n[Service]\nExecStart=" + command
            )
            result = remote_access(HostFixture(text=text))
            self.assertEqual(result.Status, "WARN", command)
            self.assertIn("SSH reverse-forward candidate", result.Detail)
            self.assertNotIn("secret@private-host", result.Detail)
            self.assertNotIn("2222", result.Detail)

    def test_comments_description_and_local_forward_are_not_reverse_forward(self):
        text = """# /etc/systemd/system/support.service
[Unit]
Description=ssh -R example
[Service]
# ExecStart=/bin/ssh -R 1234:h:22
; ExecStart=/bin/ngrok secret
ExecStart=/bin/ssh -L 1234:h:22 user@host
"""
        self.assertEqual(unit_candidates(text), set())

    def test_dropin_candidate_is_not_claimed_effective(self):
        text = """# /usr/lib/systemd/system/support.service
[Service]
ExecStart=/bin/ngrok --authtoken SUPERSECRET
# /etc/systemd/system/support.service.d/override.conf
[Service]
ExecStart=
ExecStart=/bin/true
"""
        result = remote_access(HostFixture(text=text))
        self.assertEqual(result.Status, "WARN")
        self.assertIn("may be overridden", result.Detail)
        self.assertNotIn("SUPERSECRET", result.Detail)

    def test_known_binary_needs_authorization_review(self):
        for binary in ("teamviewer", "anydesk", "rustdesk", "ngrok"):
            result = remote_access(HostFixture(binary=binary))
            self.assertEqual(result.Status, "WARN")
            self.assertIn("does not prove authorization", result.Detail)

    def test_absence_is_scoped_information(self):
        result = remote_access(HostFixture())
        self.assertEqual(result.Status, "INFO")
        self.assertIn("User services", result.Detail)

    def test_missing_command_preserves_detected_tool(self):
        result = remote_access(
            HostFixture(binary="rustdesk", error=Unavailable("missing"))
        )
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("RustDesk", result.Detail)
        self.assertIn("missing binary: systemctl", result.Detail)

    def test_permission_denial_is_unknown(self):
        result = remote_access(HostFixture(error=PermissionError("private")))
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("needs root to read", result.Detail)

    def test_unavailable_does_not_echo_stderr(self):
        host = HostFixture()
        host.command = lambda args: (_ for _ in ()).throw(Unavailable("SECRET"))
        result = remote_access(host)
        self.assertEqual(result.Status, "UNKN")
        self.assertNotIn("SECRET", result.Detail)

    def test_masked_and_not_found_units_are_not_queried(self):
        host = HostFixture()
        calls = []

        def command(args):
            calls.append(args)
            if args[1] == "list-unit-files":
                return (
                    "masked.service masked enabled\nsupport.service enabled enabled\n"
                )
            if args[1] == "list-units":
                return (
                    "masked.service masked inactive dead Masked\n"
                    "missing.service not-found inactive dead Missing\n"
                )
            return "# /etc/systemd/system/support.service\n[Service]\nExecStart=/bin/true\n"

        host.command = command
        self.assertEqual(remote_access(host).Status, "INFO")
        cat_calls = [args for args in calls if args[1] == "cat"]
        self.assertEqual(len(cat_calls), 1)
        self.assertEqual(cat_calls[0][4:], ["support.service"])

    def test_unreadable_fragment_is_unknown(self):
        host = HostFixture()
        original = host.command

        def command(args):
            if args[1] == "cat":
                raise PermissionError()
            return original(args)

        host.command = command
        self.assertEqual(remote_access(host).Status, "UNKN")


if __name__ == "__main__":
    unittest.main()
