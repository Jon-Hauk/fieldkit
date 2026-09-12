"""Local Docker metadata only: never execute workloads or read Docker credentials."""

import json
import os
import re
import stat
from pathlib import Path

from ..common import Unavailable, Verdict, run_check


class ContainerPosture:
    """One lazy snapshot; explicit Unix endpoint ignores remote CLI contexts."""

    def __init__(self, host, socket="/var/run/docker.sock", compose_roots=()):
        self.host = host
        self.socket = socket
        self.compose_roots = compose_roots
        self.cache = {}

    def docker(self, args):
        if not self.host.which("docker"):
            raise Unavailable("docker not installed")
        if not self.socket.startswith("/") or "\x00" in self.socket:
            raise Unavailable("Docker socket must be an absolute local path")
        try:
            return self.host.command(
                ["docker", "--host", "unix://" + self.socket] + args
            )
        except PermissionError:
            raise Unavailable("needs docker group or root to read")

    def cached(self, key, collect):
        if key not in self.cache:
            try:
                self.cache[key] = collect()
            except (
                Unavailable,
                PermissionError,
                ValueError,
                KeyError,
                TypeError,
            ) as exc:
                self.cache[key] = exc
        value = self.cache[key]
        if isinstance(value, Exception):
            raise value
        return value

    def info(self):
        def collect():
            # Select fields at source: never collect registry credentials or labels.
            output = self.docker(
                [
                    "info",
                    "--format",
                    (
                        "[{{json .SecurityOptions}},{{json .LiveRestoreEnabled}},"
                        "{{json .LoggingDriver}}]"
                    ),
                ]
            )
            security, live, logging = json.loads(output)
            if not isinstance(security, list) or not isinstance(live, bool):
                raise Unavailable("unrecognized Docker info metadata")
            return security, live, logging

        return self.cached("info", collect)

    def containers(self):
        def collect():
            ids = self.docker(["ps", "--quiet", "--no-trunc"]).split()
            if len(ids) > 200:
                raise Unavailable(
                    "running container inventory exceeds 200-container limit"
                )
            rows = []
            for identifier in sorted(set(ids)):
                if not re.fullmatch(r"[a-f0-9]{64}", identifier):
                    raise Unavailable("invalid container identifier")
                template = (
                    "[{{json .Id}},{{json .HostConfig.Privileged}},"
                    "{{json .HostConfig.CapAdd}},{{json .HostConfig.PidMode}},"
                    "{{json .HostConfig.IpcMode}},{{json .HostConfig.NetworkMode}},"
                    "{{json .Mounts}},{{json .Config.User}},{{json .Image}},"
                    "{{json .HostConfig.RestartPolicy.Name}},"
                    "{{json .Config.Image}},{{json .HostConfig.UsernsMode}}]"
                )
                row = json.loads(
                    self.docker(
                        [
                            "container",
                            "inspect",
                            "--format",
                            template,
                            identifier,
                        ]
                    )
                )
                if not isinstance(row, list) or len(row) != 12:
                    raise Unavailable("unrecognized container inspection metadata")
                rows.append(row)
            return rows

        return self.cached("containers", collect)

    def config(self):
        def collect():
            # Running argv includes systemd drop-in arguments without reading unit Env.
            proc = self.host.root / "proc"
            matches = []
            for directory in proc.iterdir():
                if not directory.name.isdigit():
                    continue
                try:
                    if (
                        self.host.read_text("/proc/" + directory.name + "/comm").strip()
                        != "dockerd"
                    ):
                        continue
                    args = self.host.read_text(
                        "/proc/" + directory.name + "/cmdline"
                    ).split("\0")
                    matches.append(args[1:])
                except FileNotFoundError:
                    continue
            if len(matches) != 1:
                raise Unavailable(
                    "cannot attribute config: expected one visible dockerd process"
                )
            args = matches[0]
            flags = {}
            index = 0
            while index < len(args):
                arg = args[index]
                index += 1
                if not arg.startswith("-"):
                    continue
                key, sep, value = arg.partition("=")
                if not sep:
                    value = "true"
                    if (
                        index < len(args)
                        and args[index]
                        and not args[index].startswith("-")
                    ):
                        value = args[index]
                        index += 1
                flags.setdefault(key, []).append(value)
            rootless = any("name=rootless" in s for s in self.info()[0])
            default = (
                str(Path.home() / ".config/docker/daemon.json")
                if rootless
                else "/etc/docker/daemon.json"
            )
            path = flags.get("--config-file", [default])[-1]
            try:
                config = json.loads(self.host.read_text(path))
            except FileNotFoundError:
                if "--config-file" in flags:
                    raise Unavailable("explicit daemon config file missing")
                config = {}
            if not isinstance(config, dict):
                raise Unavailable("invalid daemon configuration")
            return config, flags

        return self.cached("config", collect)

    def exposure(self):
        self.info()
        config, flags = self.config()
        hosts = (
            list(config.get("hosts", []))
            + flags.get("-H", [])
            + flags.get("--host", [])
        )
        listeners = self.host.command(["ss", "-H", "-lntp"])
        tcp = [h for h in hosts if h.startswith("tcp://")]
        observed = []
        for line in listeners.splitlines():
            fields = line.split()
            if len(fields) < 5:
                raise Unavailable("unrecognized TCP listener row")
            if fields[3].rsplit(":", 1)[-1] in ("2375", "2376") or '"dockerd"' in line:
                observed.append(fields[3])
        if tcp or observed:
            tls = flags.get(
                "--tlsverify", [str(config.get("tlsverify", False)).lower()]
            )[-1]
            return Verdict(
                "WARN",
                "Docker TCP configuration/listener candidates="
                + str(len(tcp) + len(observed))
                + "; tlsverify="
                + tls
                + ". Port numbers do not prove authentication; confirm daemon attribution, client certificates and firewall reachability.",
            )
        return Verdict(
            "INFO",
            "No configured TCP hosts or standard-port/attributed dockerd TCP listeners observed. Unix endpoint queried. Process-hidden listeners on other ports, socket activation and other network namespaces remain unverified; on-disk config may differ from loaded state.",
        )

    def socket_access(self):
        self.docker(["--version"])
        metadata = (self.host.root / self.socket.lstrip("/")).stat()
        if not stat.S_ISSOCK(metadata.st_mode):
            raise Unavailable("selected path is not a Unix socket")
        groups = self.host.command(["getent", "group", "docker"]).strip().split(":")
        if len(groups) != 4:
            raise Unavailable("docker group lookup incomplete")
        members = set(filter(None, groups[3].split(",")))
        for line in self.host.command(["getent", "passwd"]).splitlines():
            parts = line.split(":")
            if len(parts) == 7 and parts[3] == groups[2]:
                members.add(parts[0])
        mode = stat.S_IMODE(metadata.st_mode)
        detail = "Socket mode={:04o}, uid={}, gid={}; docker members={}. ".format(
            mode, metadata.st_uid, metadata.st_gid, ",".join(sorted(members)) or "none"
        )
        detail += "Access to a rootful daemon is root-equivalent: callers can mount and modify the host filesystem. ACLs and external identity membership may extend access."
        return Verdict("WARN" if members or mode & 0o022 else "INFO", detail)

    def isolation(self):
        security = self.info()[0]
        rootless = any("name=rootless" in item for item in security)
        remap = any("name=userns" in item for item in security)
        return Verdict(
            "INFO" if rootless else "WARN",
            "Daemon={}; userns-remap={}. ".format(
                "rootless" if rootless else "rootful",
                "enabled" if remap else "not reported",
            )
            + "Rootless UID 0 maps to the daemon owner; rootful remapping uses subordinate IDs but leaves the daemon privileged. Bind-mount ownership and per-container userns=host exceptions require review.",
        )

    def workloads(self, kind):
        rows = self.containers()
        if not rows:
            return Verdict(
                "INFO",
                "No running containers to evaluate; stopped containers are outside this check.",
            )
        findings = []
        unknown = []
        for row in rows:
            (
                identifier,
                privileged,
                caps,
                pid,
                ipc,
                network,
                mounts,
                user,
                image_id,
                restart,
                image_ref,
                userns,
            ) = row
            issues = []
            if kind == "privilege":
                if privileged:
                    issues.append("privileged")
                issues.extend("cap=" + cap for cap in (caps or []))
                issues.extend(
                    key + "=host"
                    for key, value in (
                        ("pid", pid),
                        ("ipc", ipc),
                        ("network", network),
                        ("userns", userns),
                    )
                    if value == "host"
                )
            elif kind in ("socket", "mounts"):
                for mount in mounts:
                    if mount.get("Type") != "bind":
                        continue
                    source = os.path.normpath(mount["Source"])
                    socket = source.endswith("/docker.sock") or source == self.socket
                    # Mounting a parent directory exposes sockets below it too.
                    socket = (
                        socket
                        or self.socket.startswith(source.rstrip("/") + "/")
                        or "/run/docker.sock".startswith(source.rstrip("/") + "/")
                    )
                    sensitive = (
                        source == "/"
                        or any(
                            source == p or source.startswith(p + "/")
                            for p in ("/etc", "/run", "/var/run", "/home", "/root")
                        )
                        or "/.ssh" in source
                    )
                    if (kind == "socket" and socket) or (
                        kind == "mounts" and sensitive
                    ):
                        issues.append(
                            "socket exposure"
                            if kind == "socket"
                            else "sensitive bind ({} access)".format(
                                "rw" if mount.get("RW") else "ro"
                            )
                        )
            elif kind == "uid":
                image_user = self.cached(
                    "image:" + image_id,
                    lambda image_id=image_id: json.loads(
                        self.docker(
                            [
                                "image",
                                "inspect",
                                "--format",
                                "{{json .Config.User}}",
                                image_id,
                            ]
                        )
                    ),
                )
                for label, value in (("container", user), ("image", image_user)):
                    uid = value.split(":", 1)[0]
                    if uid in ("", "root") or (uid.isdigit() and int(uid) == 0):
                        issues.append(label + " configured UID 0")
                    elif not uid.isdigit():
                        unknown.append(
                            label
                            + " named user cannot be resolved without reading image contents"
                        )
            elif kind == "restart" and restart in ("always", "unless-stopped"):
                issues.append("restart=" + restart)
            elif kind == "provenance" and not re.search(
                r"@sha256:[a-fA-F0-9]{64}$", image_ref
            ):
                issues.append("image reference not pinned by sha256 digest")
            if issues:
                findings.append(identifier[:12] + ": " + ", ".join(issues))
        detail = (
            "; ".join(findings)
            or f"No matching risk indicators in {len(rows)} running containers."
        )
        if kind == "socket":
            detail += " Rootful socket access is a path to host root even with a read-only socket bind; rootless sockets confer daemon-owner authority."
        if kind == "uid":
            detail += " Configured users only: entrypoints may change UID; host UID mapping and actual process credentials are not established."
        if kind == "restart":
            detail += " Complements Persistence and audit / Persistence surface (persistence.py); daemon boot enablement is not established here."
        if kind == "provenance":
            detail += " Digest pinning does not prove publisher identity, signature validity or absence of vulnerabilities."
        if unknown:
            detail += " Visibility gaps: " + "; ".join(sorted(set(unknown)))
        return Verdict("WARN" if findings else "UNKN" if unknown else "PASS", detail)

    def users(self):
        verdict = self.workloads("uid")
        identifiers = self.docker(["image", "ls", "--quiet", "--no-trunc"]).split()
        if len(set(identifiers)) > 200:
            raise Unavailable("local image inventory exceeds 200-image limit")
        roots = 0
        named = 0
        for identifier in sorted(set(identifiers)):
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", identifier):
                raise Unavailable("invalid image identifier")
            user = self.cached(
                "image:" + identifier,
                lambda identifier=identifier: json.loads(
                    self.docker(
                        [
                            "image",
                            "inspect",
                            "--format",
                            "{{json .Config.User}}",
                            identifier,
                        ]
                    )
                ),
            )
            uid = user.split(":", 1)[0]
            if uid in ("", "root") or (uid.isdigit() and int(uid) == 0):
                roots += 1
            elif not uid.isdigit():
                named += 1
        status = (
            "WARN"
            if roots or verdict.Status == "WARN"
            else "UNKN"
            if named
            else verdict.Status
        )
        return Verdict(
            status,
            verdict.Detail
            + f" Local images={len(set(identifiers))}; configured UID 0={roots}; unresolved named users={named}.",
        )

    def compose(self):
        self.docker(["--version"])
        if not self.compose_roots:
            return Verdict(
                "UNKN",
                "Compose files not inspected: supply --compose-root for approved directories. No filesystem-wide search or YAML execution is performed.",
            )
        count = 0
        candidates = 0
        gaps = []
        visited = 0

        def denied(error):
            gaps.append("unreadable directory")

        for root in self.compose_roots:
            if not root.is_dir():
                gaps.append("compose root missing or unreadable")
                continue
            for directory, dirs, files in os.walk(
                str(root), followlinks=False, onerror=denied
            ):
                dirs[:] = sorted(
                    d for d in dirs if d not in (".git", ".venv", "node_modules")
                )
                visited += 1
                if visited > 2000:
                    gaps.append("2000-directory limit reached")
                    break
                for filename in sorted(files):
                    if not re.fullmatch(
                        r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml", filename
                    ):
                        continue
                    count += 1
                    if count > 100:
                        gaps.append("100-file limit reached")
                        break
                    try:
                        path = Path(directory) / filename
                        if path.is_symlink():
                            gaps.append("symlinked Compose file skipped")
                            continue
                        content = self.host.read_text(str(path))
                        candidates += len(
                            re.findall(
                                r"(?:/var)?/run/(?:user/\d+/)?docker\.sock", content
                            )
                        )
                    except (OSError, Unavailable):
                        gaps.append("Compose file unreadable")
                if count > 100:
                    break
        detail = f"Compose lexical scan: files={min(count, 100)}, literal socket references={candidates}. "
        detail += "Candidates only, including comments; YAML aliases, interpolation, parent-directory mounts, includes and custom socket names are not resolved. File contents are never reported."
        if gaps:
            detail += " Gaps: " + "; ".join(sorted(set(gaps)))
        return Verdict("WARN" if candidates else "UNKN", detail)

    def hardening(self):
        security, live, driver = self.info()
        config, flags = self.config()
        nnp = any("name=no-new-privileges" in item for item in security)
        configured = flags.get(
            "--no-new-privileges", [str(config.get("no-new-privileges", False)).lower()]
        )[-1]
        options = dict(config.get("log-opts", {}))
        for option in flags.get("--log-opt", []):
            key, _, value = option.partition("=")
            options[key] = value
        capped = bool(
            re.fullmatch(r"[1-9]\d*(?:[kmgKMG])?", str(options.get("max-size", "")))
        )
        risks = []
        if not nnp:
            risks.append("no-new-privileges not reported effective")
        if not live:
            risks.append("live-restore disabled")
        if driver == "json-file" and not capped:
            risks.append("json-file has no positive configured max-size")
        detail = "; ".join(risks) or "Selected daemon defaults have no risk indicators."
        detail += f" no-new-privileges configured={configured}; log driver={driver}; configured positive max-size={capped}. "
        detail += "Disk config is not proof of loaded logging options; existing container overrides, remote logging retention and non-json-file budgets require separate review."
        return Verdict("WARN" if risks else "INFO", detail)

    def findings(self):
        checks = [
            ("Daemon network exposure", self.exposure),
            ("Docker socket and group access", self.socket_access),
            ("Daemon root and user namespaces", self.isolation),
            (
                "Container privilege and host namespaces",
                lambda: self.workloads("privilege"),
            ),
            ("Container Docker socket mounts", lambda: self.workloads("socket")),
            ("Compose Docker socket candidates", self.compose),
            ("Container and image configured users", self.users),
            ("Sensitive host bind mounts", lambda: self.workloads("mounts")),
            ("Container restart persistence", lambda: self.workloads("restart")),
            ("Image reference provenance", lambda: self.workloads("provenance")),
            ("Daemon hardening defaults", self.hardening),
        ]
        result = [
            run_check(
                "Container posture",
                name,
                check,
                "Have the operator review the reported container configuration and access against approved workloads before planning changes.",
            )
            for name, check in checks
        ]
        result.append(
            run_check(
                "Container posture",
                "Podman coverage",
                lambda: Verdict(
                    "INFO",
                    "Podman present; not inspected."
                    if self.host.which("podman")
                    else "Podman binary not found; no Podman inspection performed.",
                ),
            )
        )
        return result
