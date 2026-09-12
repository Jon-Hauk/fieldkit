import ast
import contextlib
import io
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux import cli
from fieldkit_linux.checks.device_management import config_management
from fieldkit_linux.common import (
    Finding,
    Host,
    Unavailable,
    Verdict,
    run_check,
)
from fieldkit_linux.report import export, render


class FakeHost:
    def __init__(self, paths=(), binaries=(), installed="", runtime="", error=None):
        self.paths = paths
        self.binaries = binaries
        self.installed = installed
        self.runtime = runtime
        self.error = error

    def which(self, binary):
        return "/usr/bin/" + binary if binary in self.binaries else None

    def exists(self, path):
        return path in self.paths

    def command(self, args):
        if self.error:
            raise self.error
        return self.installed if args[1] == "list-unit-files" else self.runtime


class ContractTests(unittest.TestCase):
    def test_none_and_exception_are_loud_unknowns(self):
        self.assertEqual(
            run_check("s", "n", lambda: None).Detail, "check returned nothing"
        )

        def broken():
            raise ValueError("broken\nparser")

        self.assertEqual(
            run_check("s", "n", broken).Detail, "check errored: broken parser"
        )
        self.assertEqual(
            run_check("s", "n", lambda: Verdict("GREEN", "")).Status, "UNKN"
        )

    def test_permission_is_not_a_failure(self):
        def blocked():
            raise PermissionError("private data")

        finding = run_check("s", "n", blocked)
        self.assertEqual(
            (finding.Status, finding.Detail), ("UNKN", "needs root to read")
        )

    def test_missing_binary_never_executes(self):
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run") as command,
        ):
            finding = run_check("s", "n", lambda: Host().command(["absent-tool"]))
        command.assert_not_called()
        self.assertEqual(finding.Status, "UNKN")
        self.assertIn("missing binary", finding.Detail)

    def test_denied_command_and_timeout(self):
        result = subprocess.CompletedProcess([], 1, "", "Operation not permitted")
        with (
            patch("shutil.which", return_value="/usr/bin/systemctl"),
            patch("subprocess.run", return_value=result),
        ):
            finding = run_check("s", "n", lambda: Host().command(["systemctl"]))
            self.assertEqual(finding.Detail, "needs root to read")
        with (
            patch("shutil.which", return_value="/usr/bin/systemctl"),
            patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("systemctl", 15)
            ),
        ):
            finding = run_check("s", "n", lambda: Host().command(["systemctl"]))
            self.assertEqual(finding.Status, "UNKN")
            self.assertIn("timed out", finding.Detail)

    def test_missing_path_is_absent(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertFalse(Host(root).exists("/no-such-agent"))


class ManagementTests(unittest.TestCase):
    def test_agent_presence_does_not_prove_ownership(self):
        host = FakeHost(
            paths=("/etc/puppetlabs",),
            binaries=("puppet",),
            installed="puppet.service enabled enabled\n",
            runtime="puppet.service loaded active running Puppet\n",
        )
        verdict = config_management(host)
        self.assertEqual(verdict.Status, "INFO")
        self.assertIn("puppet.service=loaded/active/running", verdict.Detail)
        self.assertIn("does not prove enrollment", verdict.Detail)

    def test_stopped_agent_is_not_pass(self):
        verdict = config_management(
            FakeHost(
                installed="puppet.service disabled enabled\n",
                runtime="puppet.service loaded inactive dead Puppet\n",
            )
        )
        self.assertEqual(verdict.Status, "INFO")
        self.assertIn("inactive/dead", verdict.Detail)

    def test_missing_tool_preserves_partial_evidence(self):
        verdict = config_management(
            FakeHost(
                paths=("/etc/cloud",), error=Unavailable("missing binary: systemctl")
            )
        )
        self.assertEqual(verdict.Status, "UNKN")
        self.assertIn("cloud-init", verdict.Detail)
        self.assertIn("missing binary", verdict.Detail)

    def test_denied_path_preserves_evidence(self):
        host = FakeHost(binaries=("puppet",))
        host.exists = lambda path: (_ for _ in ()).throw(PermissionError())
        verdict = config_management(host)
        self.assertEqual(verdict.Status, "UNKN")
        self.assertIn("binary puppet", verdict.Detail)
        self.assertIn("needs root to read", verdict.Detail)

    def test_no_evidence_is_not_unmanaged_failure(self):
        self.assertEqual(config_management(FakeHost()).Status, "UNKN")

    def test_order_is_deterministic(self):
        first = "puppet.service enabled enabled\nchef-client.service disabled enabled\n"
        second = "\n".join(reversed(first.splitlines()))
        self.assertEqual(
            config_management(FakeHost(installed=first)),
            config_management(FakeHost(installed=second)),
        )


class ReportTests(unittest.TestCase):
    def test_escape_and_conditional_remediation(self):
        findings = [
            Finding("s", "<script>|name", "INFO", "<img src=x>", "HIDDEN"),
            Finding("s", "bad", "WARN", "review", "SHOWN"),
        ]
        md, html = render(findings, "<script>alert(1)</script>", "h", False)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x>", html)
        self.assertIn("\\|name", md)
        for report in (md, html):
            self.assertNotIn("HIDDEN", report)
            self.assertIn("SHOWN", report)

    def test_reports_are_stable_private_and_not_overwritten(self):
        findings = [Finding("s", "n", "INFO", "evidence")]
        with tempfile.TemporaryDirectory() as directory:
            first = export(findings, "client", "../../host", False, directory)
            second = export(findings, "client", "../../host", False, directory)
            self.assertNotEqual(first, second)
            for a, b in zip(first, second):
                self.assertEqual(a.read_bytes(), b.read_bytes())
                self.assertEqual(stat.S_IMODE(a.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(a.parent.stat().st_mode), 0o700)
                self.assertEqual(a.parent.parent, Path(directory))

    def test_report_order_is_stable(self):
        findings = [Finding("z", "n", "INFO", "b"), Finding("a", "n", "INFO", "a")]
        self.assertEqual(
            render(findings, "c", "h", False),
            render(list(reversed(findings)), "c", "h", False),
        )

    def test_one_privilege_hint_and_unknown_exit_zero(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(cli, "Host", return_value=FakeHost(error=PermissionError())),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["--report-path", directory]), 0)
            self.assertEqual(output.getvalue().count("Re-run with sudo"), 1)

    def test_export_failure_returns_two(self):
        with (
            patch.object(cli, "Host", return_value=FakeHost()),
            patch.object(cli, "export", side_effect=PermissionError("denied")),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()) as error,
        ):
            self.assertEqual(cli.main([]), 2)
            self.assertNotIn("Traceback", error.getvalue())

    def test_fail_returns_one(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(cli, "Host", return_value=FakeHost()),
            patch.object(
                cli, "config_management", return_value=Verdict("FAIL", "fixture")
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.main(["--report-path", directory]), 1)

    def test_unsupported_platform_does_not_collect(self):
        with (
            patch.object(cli.platform, "system", return_value="Darwin"),
            patch.object(cli, "Host") as host,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(cli.main([]), 2)
            host.assert_not_called()

    def test_python38_syntax(self):
        # Scoped to what actually ships. The 3.8 floor exists because the tool
        # runs on a client's Ubuntu 20.04 server having installed nothing; the
        # test suite never leaves this repo, and it runs on CI and on the Linux
        # development box (3.10) where 3.9+ syntax is fine.
        #
        # This is deliberately a package walk, not an exclusion list. Anything
        # added under fieldkit_linux/ is covered the moment it exists, so the
        # gate cannot silently stop covering a new check the way an explicit
        # skip list would.
        root = Path(__file__).resolve().parents[1]
        # Runtime targets 3.8; development tests use the host interpreter.
        sources = list((root / "fieldkit_linux").rglob("*.py")) + [
            root / "fieldkit-linux"
        ]
        self.assertGreater(len(sources), 15, "source walk found nothing to check")
        for source in sources:
            ast.parse(source.read_text(), filename=str(source), feature_version=(3, 8))


if __name__ == "__main__":
    unittest.main()
