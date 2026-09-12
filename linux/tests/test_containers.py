import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.containers import ContainerPosture
from fieldkit_linux.common import Host, Unavailable, run_check


class ContainerTests(unittest.TestCase):
    def posture(self, rows=None):
        posture = ContainerPosture(Host())
        posture.cache["containers"] = [] if rows is None else rows
        posture.cache["info"] = (["name=seccomp"], False, "json-file")
        posture.cache["config"] = ({}, {})
        return posture

    def row(self):
        return [
            "a" * 64,
            False,
            [],
            "",
            "",
            "bridge",
            [],
            "1000",
            "sha256:" + "b" * 64,
            "no",
            "example@sha256:" + "c" * 64,
            "",
        ]

    def test_absent_docker_all_docker_checks_unknown(self):
        host = Host()
        with patch.object(host, "which", return_value=None):
            results = ContainerPosture(host).findings()
        self.assertEqual(len(results), 12)
        for finding in results[:-1]:
            self.assertEqual(
                (finding.Status, finding.Detail), ("UNKN", "docker not installed")
            )

    def test_permission_message_and_no_remote_context(self):
        host = Host()
        with patch.object(host, "which", return_value="/usr/bin/docker"):  # noqa: SIM117 - Python 3.8 syntax
            with patch.object(
                host, "command", side_effect=PermissionError()
            ) as command:
                findings = ContainerPosture(host).findings()
        self.assertTrue(all(f.Status == "UNKN" for f in findings[:-1]))
        self.assertIn("needs docker group or root to read", findings[0].Detail)
        self.assertEqual(
            command.call_args_list[0].args[0][:3],
            ["docker", "--host", "unix:///var/run/docker.sock"],
        )

    def test_rootful_rootless_remap(self):
        posture = self.posture()
        self.assertEqual(posture.isolation().Status, "WARN")
        posture.cache["info"] = (["name=userns"], True, "local")
        self.assertIn("userns-remap=enabled", posture.isolation().Detail)
        self.assertEqual(posture.isolation().Status, "WARN")
        posture.cache["info"] = (["name=rootless"], True, "local")
        self.assertEqual(posture.isolation().Status, "INFO")

    def test_privilege_namespaces_and_added_capabilities(self):
        row = self.row()
        row[1:6] = [
            True,
            ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"],
            "host",
            "host",
            "host",
        ]
        row[11] = "host"
        verdict = self.posture([row]).workloads("privilege")
        self.assertEqual(verdict.Status, "WARN")
        for text in (
            "privileged",
            "SYS_ADMIN",
            "NET_ADMIN",
            "SYS_PTRACE",
            "pid=host",
            "ipc=host",
            "network=host",
            "userns=host",
        ):
            self.assertIn(text, verdict.Detail)

    def test_socket_readonly_parent_and_sensitive_binds(self):
        for source in ("/var/run/docker.sock", "/run/docker.sock", "/var/run", "/"):
            row = self.row()
            row[6] = [{"Type": "bind", "Source": source, "RW": False}]
            self.assertEqual(self.posture([row]).workloads("socket").Status, "WARN")
        for source in ("/etc/ssh", "/home/example/.ssh", "/root/.ssh", "/"):
            row[6] = [{"Type": "bind", "Source": source, "RW": True}]
            self.assertEqual(self.posture([row]).workloads("mounts").Status, "WARN")

    def test_restart_and_floating_images(self):
        row = self.row()
        posture = self.posture([row])
        self.assertEqual(posture.workloads("provenance").Status, "PASS")
        row[10] = "example:latest"
        row[9] = "unless-stopped"
        self.assertEqual(posture.workloads("provenance").Status, "WARN")
        self.assertIn("persistence.py", posture.workloads("restart").Detail)
        self.assertEqual(posture.workloads("restart").Status, "WARN")
        row[10] = "example:v1"
        self.assertEqual(posture.workloads("provenance").Status, "WARN")

    def test_configured_uid_zero_and_unresolved_name(self):
        row = self.row()
        posture = self.posture([row])
        posture.cache["image:" + row[8]] = "1000"
        self.assertEqual(posture.workloads("uid").Status, "PASS")
        row[7] = "app"
        self.assertEqual(posture.workloads("uid").Status, "UNKN")
        row[7] = "0:1000"
        self.assertEqual(posture.workloads("uid").Status, "WARN")
        row[7] = "1000"
        posture.cache["image:" + row[8]] = ""
        self.assertEqual(posture.workloads("uid").Status, "WARN")

    def test_local_image_user_without_running_containers(self):
        posture = self.posture()
        identifier = "sha256:" + "a" * 64
        with patch.object(posture, "docker", side_effect=[identifier, '"root"']):
            verdict = posture.users()
        self.assertEqual(verdict.Status, "WARN")
        self.assertIn("Local images=1; configured UID 0=1", verdict.Detail)

    def test_empty_workloads_are_not_pass(self):
        for kind in ("privilege", "socket", "mounts", "uid", "restart", "provenance"):
            self.assertEqual(self.posture().workloads(kind).Status, "INFO")

    def test_hardening_effective_flags_and_uncapped_logs(self):
        posture = self.posture()
        self.assertEqual(posture.hardening().Status, "WARN")
        posture.cache["info"] = (["name=no-new-privileges"], True, "json-file")
        posture.cache["config"] = ({}, {"--log-opt": ["max-size=10m", "max-file=3"]})
        self.assertEqual(posture.hardening().Status, "INFO")
        for size in ("0", "-1", "invalid"):
            posture.cache["config"] = ({"log-opts": {"max-size": size}}, {})
            self.assertEqual(posture.hardening().Status, "WARN")

    def test_tcp_from_process_flags_and_standard_ports(self):
        posture = self.posture()
        posture.cache["config"] = ({}, {"-H": ["tcp://0.0.0.0:4243"]})
        with patch.object(posture.host, "command", return_value=""):
            self.assertEqual(posture.exposure().Status, "WARN")
        posture.cache["config"] = ({}, {})
        with patch.object(
            posture.host, "command", return_value="LISTEN 0 128 0.0.0.0:2376 *:*\n"
        ):
            verdict = posture.exposure()
        self.assertEqual(verdict.Status, "WARN")
        self.assertIn("do not prove authentication", verdict.Detail)
        with patch.object(
            posture.host, "command", side_effect=Unavailable("missing binary: ss")
        ):
            self.assertEqual(run_check("s", "n", posture.exposure).Status, "UNKN")

    def test_proc_flags_override_disk_without_echoing_other_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "proc/123").mkdir(parents=True)
            (root / "etc/docker").mkdir(parents=True)
            (root / "proc/123/comm").write_text("dockerd\n")
            (root / "proc/123/cmdline").write_text(
                "dockerd\0-H\0tcp://127.0.0.1:4243\0--log-opt=max-size=10m\0"
            )
            (root / "etc/docker/daemon.json").write_text(
                json.dumps({"live-restore": False, "irrelevant": "DO_NOT_REPORT"})
            )
            posture = ContainerPosture(Host(root))
            posture.cache["info"] = ([], False, "json-file")
            _config, flags = posture.config()
            self.assertEqual(flags["-H"], ["tcp://127.0.0.1:4243"])
            self.assertNotIn("DO_NOT_REPORT", posture.hardening().Detail)

    def test_compose_candidates_no_content_disclosure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compose.yaml").write_text(
                "services:\n  example:\n    volumes:\n      - /var/run/docker.sock:/socket:ro\n# DO_NOT_REPORT\n"
            )
            posture = ContainerPosture(Host(), compose_roots=[root])
            with patch.object(posture, "docker", return_value="Docker version"):
                verdict = posture.compose()
            self.assertEqual(verdict.Status, "WARN")
            self.assertIn("literal socket references=1", verdict.Detail)
            self.assertNotIn("DO_NOT_REPORT", verdict.Detail)

    def test_inspect_is_selected_metadata_and_cached(self):
        posture = ContainerPosture(Host())
        row = self.row()
        with patch.object(
            posture, "docker", side_effect=[row[0], json.dumps(row)]
        ) as command:
            self.assertEqual(posture.workloads("privilege").Status, "PASS")
            self.assertEqual(posture.workloads("restart").Status, "PASS")
        self.assertEqual(command.call_count, 2)
        template = command.call_args_list[-1].args[0][3]
        self.assertNotIn(".Config.Env", template)
        self.assertNotIn(".Config.Labels", template)

    def test_malformed_output_and_disappearing_container_are_unknown(self):
        for output in ("not-an-id", "a" * 64):
            posture = ContainerPosture(Host())
            with patch.object(
                posture,
                "docker",
                side_effect=[output, Unavailable("container disappeared")],
            ):
                self.assertEqual(
                    run_check(
                        "s", "n", lambda posture=posture: posture.workloads("privilege")
                    ).Status,
                    "UNKN",
                )


if __name__ == "__main__":
    unittest.main()
