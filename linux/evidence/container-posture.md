<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Container posture validation

[VERIFIED] 2026-09-08, commands from the repository root:

```bash
python3 -B -m unittest discover -s linux/tests -q
python3 -B linux/fieldkit-linux --containers-only --compose-root /home/operator/fieldkit/packaging --report-path /tmp/fieldkit-container-validation/host
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --containers-only --report-path /tmp/fieldkit-container-validation/absent
python3 -B linux/fieldkit-linux --containers-only --compose-root /home/operator/fieldkit/packaging --report-path /tmp/fieldkit-container-validation/sandbox
python3 -B linux/fieldkit-linux --report-path /tmp/fieldkit-container-validation/full
```

[VERIFIED] 146 tests passed, including 15 container fixture tests. Runtime
Python 3.8 syntax is checked independently of development-test syntax; an
existing guard previously parsed tests that already used Python 3.9 syntax.
Actual execution on Python 3.8 was [UNVERIFIED] until 2026-09-12; see
"Reproduced in CI" at the end of this file. The full host runner
emitted 31 findings, Markdown and HTML: 1 PASS, 0 FAIL, 7 WARN, 12 UNKN,
11 INFO, with no `check errored` or `check returned nothing` findings.
Verification: full-run command above and
`rg 'check errored|check returned nothing|PASS,|Report:' /tmp/fieldkit-container-validation/full.txt`,
2026-09-08.

[VERIFIED] Host runs were executed outside the agent sandbox as the existing
unprivileged user with Docker access. Socket-denied runs were inside the
sandbox with effective supplementary Docker access removed; UID/GID metadata
is remapped there. `id` established the differing groups on 2026-09-08.
This is not represented as a separate host-user acceptance run.

[VERIFIED] Operator completed root and separate non-member-account validation
on 2026-09-08 using `bash /tmp/fieldkit-container-validation/validate-privileges.sh`.
The commands executed by that script were:

```bash
sudo /usr/bin/python3 -B /tmp/fieldkit-container-validation/runner/fieldkit-linux --containers-only --report-path /tmp/fieldkit-container-root
sudo -u nobody id
sudo -u nobody /usr/bin/python3 -B /tmp/fieldkit-container-validation/runner/fieldkit-linux --containers-only --report-path /tmp/fieldkit-container-nobody
```

[VERIFIED] Root returned 4 WARN, 1 UNKN and 7 INFO; the separate `nobody`
account returned 1 WARN, 10 UNKN and 1 INFO. Neither run returned FAIL or a
check error. Docker queries denied to `nobody` return the required
`UNKN "needs docker group or root to read"`; public socket/group metadata
remains readable. Compose inspection remains explicitly unknown because no
search directory was supplied. Both runs emitted Markdown and HTML reports.
Verification: operator-supplied console output and captured `root.txt`,
`nobody-id.txt`, `nobody.txt` under `/tmp/fieldkit-container-validation/`,
read with `cat` on 2026-09-08. No authentication material was handled by the agent.

[VERIFIED] The temporary runtime used by the operator matches the source being
committed. These commands returned no differences on 2026-09-08:

```bash
diff -qr linux/fieldkit_linux /tmp/fieldkit-container-validation/runner/fieldkit_linux
cmp linux/fieldkit-linux /tmp/fieldkit-container-validation/runner/fieldkit-linux
```

[VERIFIED] Required live execution modes are now recorded: Docker-access user,
root, missing binary and separate account without Docker access. Workload risk
branches are fixture-tested: the host had no running containers, so live workload
findings remain INFO rather than invented PASS results. The limitations below
remain part of the accepted scope. Commands and date are recorded above.

[VERIFIED] Fixture coverage includes privileged/cap-added workloads, host
namespaces, read-only socket and parent-directory mounts, sensitive binds,
root/named users, rootful/rootless/remapped daemon reports, floating references,
restart policies, log caps, process-argument TCP configuration, Compose literal
references, Docker absence, denied access, disappearing containers and malformed
IDs. Command: test command above, 2026-09-08. No live workloads were created.

[UNVERIFIED] TLS authentication, remote reachability, real process UIDs, complete
Compose expansion, external group membership, socket ACLs, rootless installations
and effective workload log budgets are not established. Selected daemon config
and listener observations are not a blanket claim of effective hardening.

Technical semantics checked against primary references on 2026-09-08:
[Docker daemon options](https://docs.docker.com/reference/cli/dockerd/),
[Docker group privileges](https://docs.docker.com/engine/install/linux-postinstall/),
[user namespace remapping](https://docs.docker.com/engine/security/userns-remap/),
[rootless UID mapping](https://docs.docker.com/engine/security/rootless/uid-gid-mapping/),
[logging defaults and existing containers](https://docs.docker.com/engine/logging/configure/).

Console records below retain check output and omit only remediation duplicates
and generated report paths. Full local logs and reports are in
`/tmp/fieldkit-container-validation/`; they are not committed.

## Host user with Docker access

[VERIFIED] Command and date recorded above.

```text
[INFO] Daemon network exposure: No configured TCP hosts or standard-port/attributed dockerd TCP listeners observed. Unix endpoint queried. Process-hidden listeners on other ports, socket activation and other network namespaces remain unverified; on-disk config may differ from loaded state.
[WARN] Docker socket and group access: Socket mode=0660, uid=0, gid=994; docker members=operator. Access to a rootful daemon is root-equivalent: callers can mount and modify the host filesystem. ACLs and external identity membership may extend access.
[WARN] Daemon root and user namespaces: Daemon=rootful; userns-remap=not reported. Rootless UID 0 maps to the daemon owner; rootful remapping uses subordinate IDs but leaves the daemon privileged. Bind-mount ownership and per-container userns=host exceptions require review.
[INFO] Container privilege and host namespaces: No running containers to evaluate; stopped containers are outside this check.
[INFO] Container Docker socket mounts: No running containers to evaluate; stopped containers are outside this check.
[UNKN] Compose Docker socket candidates: Compose lexical scan: files=0, literal socket references=0. Candidates only, including comments; YAML aliases, interpolation, parent-directory mounts, includes and custom socket names are not resolved. File contents are never reported.
[WARN] Container and image configured users: No running containers to evaluate; stopped containers are outside this check. Local images=4; configured UID 0=4; unresolved named users=0.
[INFO] Sensitive host bind mounts: No running containers to evaluate; stopped containers are outside this check.
[INFO] Container restart persistence: No running containers to evaluate; stopped containers are outside this check.
[INFO] Image reference provenance: No running containers to evaluate; stopped containers are outside this check.
[WARN] Daemon hardening defaults: no-new-privileges not reported effective; live-restore disabled; json-file has no positive configured max-size no-new-privileges configured=false; log driver=json-file; configured positive max-size=False. Disk config is not proof of loaded logging options; existing container overrides, remote logging retention and non-json-file budgets require separate review.
[INFO] Podman coverage: Podman binary not found; no Podman inspection performed.
0 PASS, 0 FAIL, 4 WARN, 1 UNKN, 7 INFO
```

## Docker binary not resolvable

[VERIFIED] Command and date recorded above.

```text
[UNKN] Daemon network exposure: docker not installed
[UNKN] Docker socket and group access: docker not installed
[UNKN] Daemon root and user namespaces: docker not installed
[UNKN] Container privilege and host namespaces: docker not installed
[UNKN] Container Docker socket mounts: docker not installed
[UNKN] Compose Docker socket candidates: docker not installed
[UNKN] Container and image configured users: docker not installed
[UNKN] Sensitive host bind mounts: docker not installed
[UNKN] Container restart persistence: docker not installed
[UNKN] Image reference provenance: docker not installed
[UNKN] Daemon hardening defaults: docker not installed
[INFO] Podman coverage: Podman binary not found; no Podman inspection performed.
0 PASS, 0 FAIL, 0 WARN, 11 UNKN, 1 INFO
```

## Sandbox without effective socket access

[VERIFIED] Command and date recorded above.

```text
[UNKN] Daemon network exposure: needs docker group or root to read
[WARN] Docker socket and group access: Socket mode=0660, uid=65534, gid=65534; docker members=operator. Access to a rootful daemon is root-equivalent: callers can mount and modify the host filesystem. ACLs and external identity membership may extend access.
[UNKN] Daemon root and user namespaces: needs docker group or root to read
[UNKN] Container privilege and host namespaces: needs docker group or root to read
[UNKN] Container Docker socket mounts: needs docker group or root to read
[UNKN] Compose Docker socket candidates: Compose lexical scan: files=0, literal socket references=0. Candidates only, including comments; YAML aliases, interpolation, parent-directory mounts, includes and custom socket names are not resolved. File contents are never reported.
[UNKN] Container and image configured users: needs docker group or root to read
[UNKN] Sensitive host bind mounts: needs docker group or root to read
[UNKN] Container restart persistence: needs docker group or root to read
[UNKN] Image reference provenance: needs docker group or root to read
[UNKN] Daemon hardening defaults: needs docker group or root to read
[INFO] Podman coverage: Podman binary not found; no Podman inspection performed.
Some controls need root to read. Re-run with sudo to read this; Fieldkit never elevates itself.
0 PASS, 0 FAIL, 1 WARN, 10 UNKN, 1 INFO
```

## Operator root run

[VERIFIED] Operator-run command and date recorded above.

```text
[INFO] Daemon network exposure: No configured TCP hosts or standard-port/attributed dockerd TCP listeners observed. Unix endpoint queried. Process-hidden listeners on other ports, socket activation and other network namespaces remain unverified; on-disk config may differ from loaded state.
[WARN] Docker socket and group access: Socket mode=0660, uid=0, gid=994; docker members=operator. Access to a rootful daemon is root-equivalent: callers can mount and modify the host filesystem. ACLs and external identity membership may extend access.
[WARN] Daemon root and user namespaces: Daemon=rootful; userns-remap=not reported. Rootless UID 0 maps to the daemon owner; rootful remapping uses subordinate IDs but leaves the daemon privileged. Bind-mount ownership and per-container userns=host exceptions require review.
[INFO] Container privilege and host namespaces: No running containers to evaluate; stopped containers are outside this check.
[INFO] Container Docker socket mounts: No running containers to evaluate; stopped containers are outside this check.
[UNKN] Compose Docker socket candidates: Compose files not inspected: supply --compose-root for approved directories. No filesystem-wide search or YAML execution is performed.
[WARN] Container and image configured users: No running containers to evaluate; stopped containers are outside this check. Local images=4; configured UID 0=4; unresolved named users=0.
[INFO] Sensitive host bind mounts: No running containers to evaluate; stopped containers are outside this check.
[INFO] Container restart persistence: No running containers to evaluate; stopped containers are outside this check.
[INFO] Image reference provenance: No running containers to evaluate; stopped containers are outside this check.
[WARN] Daemon hardening defaults: no-new-privileges not reported effective; live-restore disabled; json-file has no positive configured max-size no-new-privileges configured=false; log driver=json-file; configured positive max-size=False. Disk config is not proof of loaded logging options; existing container overrides, remote logging retention and non-json-file budgets require separate review.
[INFO] Podman coverage: Podman binary not found; no Podman inspection performed.
0 PASS, 0 FAIL, 4 WARN, 1 UNKN, 7 INFO
```

## Separate host account without Docker access

[VERIFIED] Operator-run command and date recorded above.

```text
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
[UNKN] Daemon network exposure: needs docker group or root to read
[WARN] Docker socket and group access: Socket mode=0660, uid=0, gid=994; docker members=operator. Access to a rootful daemon is root-equivalent: callers can mount and modify the host filesystem. ACLs and external identity membership may extend access.
[UNKN] Daemon root and user namespaces: needs docker group or root to read
[UNKN] Container privilege and host namespaces: needs docker group or root to read
[UNKN] Container Docker socket mounts: needs docker group or root to read
[UNKN] Compose Docker socket candidates: Compose files not inspected: supply --compose-root for approved directories. No filesystem-wide search or YAML execution is performed.
[UNKN] Container and image configured users: needs docker group or root to read
[UNKN] Sensitive host bind mounts: needs docker group or root to read
[UNKN] Container restart persistence: needs docker group or root to read
[UNKN] Image reference provenance: needs docker group or root to read
[UNKN] Daemon hardening defaults: needs docker group or root to read
[INFO] Podman coverage: Podman binary not found; no Podman inspection performed.
Some controls need root to read. Re-run with sudo to read this; Fieldkit never elevates itself.
0 PASS, 0 FAIL, 1 WARN, 10 UNKN, 1 INFO
```

## Live misconfigured workload

[VERIFIED] 2026-09-09. Until this run, the six workload checks had **never
evaluated a running container on a real daemon** — every prior host run
reported "No running containers to evaluate" and the workload branches were
covered only by fixtures. This run closes that gap with a deliberately
misconfigured container, and returns the host to its prior state afterwards.

Commands, from the repository root on `example-host` (aarch64, Docker 29.8.0):

```bash
python3 -B linux/fieldkit-linux --containers-only --report-path /tmp/fieldkit-live-validation/baseline

docker tag alpine:3.20 fieldkit-badpost:latest
docker run -d --name fieldkit-badpost \
  --privileged --pid=host --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/hostetc:ro \
  --user 0:0 \
  fieldkit-badpost:latest sleep 3600

python3 -B linux/fieldkit-linux --containers-only --report-path /tmp/fieldkit-live-validation/badworkload

docker rm -f fieldkit-badpost
docker rmi fieldkit-badpost:latest
python3 -B linux/fieldkit-linux --containers-only --report-path /tmp/fieldkit-live-validation/after
```

[VERIFIED] Severity counts across the three runs, which are a negative control
on both sides: **baseline 4 WARN / 1 UNKN / 7 INFO → workload 9 WARN / 1 UNKN /
2 INFO → after teardown 4 WARN / 1 UNKN / 7 INFO.** The host returned exactly
to its prior state; no check held stale results.

[VERIFIED] All six previously-unexercised checks fired, each naming the
specific condition rather than a generic warning. Container `26a26aaad614`:

| Check | Baseline | With the workload |
|---|---|---|
| Container privilege and host namespaces | INFO, nothing to evaluate | WARN `privileged, pid=host` |
| Container Docker socket mounts | INFO, nothing to evaluate | WARN `socket exposure` |
| Container and image configured users | WARN, images only | WARN `container configured UID 0, image configured UID 0` |
| Sensitive host bind mounts | INFO, nothing to evaluate | WARN `sensitive bind (ro access), sensitive bind (rw access)` |
| Container restart persistence | INFO, nothing to evaluate | WARN `restart=always` |
| Image reference provenance | INFO, nothing to evaluate | WARN `image reference not pinned by sha256 digest` |

[VERIFIED] The floating-reference case was produced by re-tagging a local
`alpine:3.20` as `fieldkit-badpost:latest`. Nothing was pulled; the image list
returned to its original four entries after teardown.

[UNVERIFIED] This establishes that the checks *detect* these conditions on a
live daemon. It does not establish detection of conditions not present in this
container: user-namespace-remapped workloads, rootless daemons, Podman
workloads, capability-added-but-unprivileged containers, TLS-exposed daemons,
or containers whose entrypoint changes UID at runtime. Those remain
fixture-covered only.

[UNVERIFIED] No FAIL result was produced by any run, including one with a
privileged container holding a rootful Docker socket. Whether that is the
intended severity ceiling is a design question, not a defect observed here —
see the review note accompanying this change.

## Reproduced in CI

[VERIFIED] 2026-09-12. Everything above was done by hand, once. The live
workload experiment is now `tests/live/container-workload.sh`, run on every
change on a hosted `ubuntu-latest` runner (rootful Docker 28.0.4, runner user
in the `docker` group, no userns-remap) under **Python 3.8.18 and 3.12**. It
passes only if all six workload checks name their condition, WARN rises by
exactly five, and the post-teardown run reproduces the baseline line for line.

First run, private monorepo, both interpreters:

```text
baseline: 0 PASS, 0 FAIL, 4 WARN, 1 UNKN, 7 INFO
workload: 0 PASS, 0 FAIL, 9 WARN, 1 UNKN, 2 INFO
after:    0 PASS, 0 FAIL, 4 WARN, 1 UNKN, 7 INFO
Proven: six workload checks fired on a live daemon, +5 WARN / -5 INFO, and the host returned to baseline.
```

Identical counts to the 2026-09-09 hand run on a different host, architecture
(x86-64 vs aarch64) and Docker version. Verification: run 34687669205, jobs
`fieldkit-containers (3.8)` and `(3.12)`; the public repository's first run
(34687948365, jobs `containers (3.8)` and `(3.12)`) reproduced it again.

[UNVERIFIED] This proves the container section on 3.8. The other sections have
not executed on 3.8; their coverage remains the 3.12 unit tests and the 3.10
host runs above.
