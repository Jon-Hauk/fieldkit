# Fieldkit Linux

[VERIFIED] The Linux implementation provides the Python runner, five-verdict
finding contract, private HTML/Markdown reports, and config-management
inventory, remote-access review, MAC enforcement, SSH configuration, and automatic
security-update, firewall-default, persistence, audit-retention and disk-encryption
checks, removable-storage and local-privilege inventory, and a separate
key-escrow question, SSH authorized-key metadata, dormancy/key correlation, PAM MFA references,
SSH authentication methods, directory-integration evidence and socket bindings. Validation:
`python3 -B -m unittest discover -s linux/tests -v`
from the repository root, 2026-09-08. Live evidence is in
[validation.md](evidence/validation.md).

[VERIFIED] All 15 numbered areas in the port brief (kept with the private working notes) have scoped
implementations, producing 19 findings. Root and non-root validation is recorded
in the evidence files linked below. Final operator command, 2026-09-08:
`sudo /usr/bin/python3 -B /home/operator/fieldkit/linux/fieldkit-linux --client-name "operator root validation"`.
See [final root evidence](evidence/network-exposure.md).

[UNVERIFIED] Execution on Python 3.8, other distributions and a separate clean
Ubuntu installation has not been tested. Findings are scoped observations;
this is not a complete security audit or proof of fleet administration.

## Run from the checkout

From the repository root:

```bash
python3 -B linux/fieldkit-linux --client-name "Example client"
```

[VERIFIED] The executable entry point also disables Python bytecode writes.
The runner uses the standard library and writes only beneath its report
directory. No installation is needed. Validation: the above command and the
unit-test command, 2026-09-07.

[VERIFIED] Output defaults to `fieldkit/reports/<host>-linux-<unique-id>/`.
Each run creates `report.html` and `report.md` in a new mode-0700 directory;
both files have mode 0600. Report contents omit collection timestamps and
sort findings, so unchanged observations can be compared without filename
churn entering the diff. Validation: `python3 -B -m unittest discover -s
linux/tests -v`, 2026-09-07.

To choose a writable report directory:

```bash
python3 -B linux/fieldkit-linux --client-name "Example client" \
  --report-path /path/to/private/reports
```

## What the first check establishes

[VERIFIED] The collector inventories known binary names, filesystem paths,
systemd unit-file states, and runtime states for cloud-init, Ansible pull,
Puppet, Chef, Salt, Landscape, osquery/Fleet, and JumpCloud. It does not open
agent configuration files or collect enrollment secrets. Validation:
`python3 -B -m unittest discover -s linux/tests -v`, 2026-09-07;
implementation: `fieldkit_linux/checks/device_management.py`.

[VERIFIED] Presence yields `INFO`, never proof that a console owns the device.
Missing visibility yields `UNKN` with any evidence already collected. No
known agent also yields `UNKN`: custom management is possible. Permission
denial produces one rerun hint; the program never invokes sudo. A stopped
agent remains an observation, because this inventory has no client-specific
policy requiring that agent. Validation: the unit-test command above,
2026-09-07.

[ASSUMED] The intended next increments follow the port brief's order:
the remaining hardening checks, persistence/audit, DLP, identity, then listening sockets.
SSH-key/offboarding correlation, native audit trails, and readable access
policy are the planned Linux strengths; none is evidenced by this preview.

## Remote-access review

[VERIFIED] The second check looks for TeamViewer, AnyDesk, RustDesk, ngrok,
and SSH reverse-forwarding candidates in system-manager service fragments
and drop-ins. Candidate presence produces `WARN` for authorization review;
absence is scoped `INFO`, not a security pass. Incomplete collection is
`UNKN`. The report omits command lines, arguments and tokens. Validation:
`python3 -B -m unittest discover -s linux/tests -v` and
`linux/fieldkit-linux --client-name 'operator remote-access validation'`,
2026-09-07. See [remote-access evidence](evidence/remote-access.md).

[UNVERIFIED] This does not inventory user services, containers, cron,
referenced scripts, SSH configuration, or dynamically constructed commands.
Fragment matches can be overridden by drop-ins and are not evidence of a
running connection. Client authorization cannot be inferred from host state.

## MAC framework enforcement

[VERIFIED] The third check reads the kernel's active LSM list and the active
framework's runtime interfaces. It returns `WARN` for SELinux permissive mode,
AppArmor complain/unconfined/prompt profiles, or an empty AppArmor profile
list. Unreadable interfaces produce `UNKN`; neither framework in a readable
active list produces `FAIL`. No binaries are needed for this check. Validation:
`python3 -B -m unittest discover -s linux/tests -v`, 2026-09-07.

[VERIFIED] The live non-root run reported SELinux permissive mode on operator
(`linux/fieldkit-linux --client-name 'operator MAC validation'`,
2026-09-07). See [MAC evidence and source references](evidence/mac-enforcement.md).

[UNVERIFIED] A `PASS` establishes framework enforcement only. SELinux
per-domain permissive exceptions and workload policy coverage are not
inspected. AppArmor profile presence does not prove every workload is confined.

## Check scope and limits

[VERIFIED] Socket inventory distinguishes wildcard, loopback and specific local
address bindings, mapping addresses to interface names (including tailscale0).
Unresolved addresses and unavailable commands produce UNKN. Validation:
`python3 -B -m unittest discover -s linux/tests -q`, 2026-09-08.
See [socket evidence](evidence/network-exposure.md).

[UNVERIFIED] Binding is not reachability or proof of overlay-only access.
Other namespaces, firewall/NAT policy, IPv6 dual-stack behavior and process
ownership are outside this inventory. No connection probes are sent.


[VERIFIED] Authentication inventory reports recognized PAM module locations,
optional/sufficient/nullok review candidates, global SSH authentication methods
and SSSD/realmd evidence. Missing visibility remains UNKN. Validation:
`python3 -B -m unittest discover -s linux/tests -q`, 2026-09-08.
See [authentication evidence](evidence/authentication.md).

[UNVERIFIED] PAM enforcement, actual MFA enrollment, connection-specific SSH
policy and directory trust health are not established. No login or join is attempted.

[VERIFIED] Dormancy review queries lastlog for local accounts with login
shells listed in /etc/shells. Old or missing login records are review
candidates, correlated with conventional authorized-key entries. Immediate
/home directories without a matching local account are also checked for
leftover keys. Unreadable evidence yields UNKN. Validation:
`python3 -B -m unittest discover -s linux/tests -q`, 2026-09-08.
See [dormancy evidence](evidence/dormancy.md).

[ASSUMED] The default review threshold is 90 days; set `--dormant-days N` to
match the engagement. Old/missing lastlog records do not prove inactivity or
offboarding. [UNVERIFIED] Nested/alternate key sources, nonlocal identities,
account-lock state and actual key acceptance are not correlated here.

[VERIFIED] SSH-key inventory reports file owner, parsed key counts/types,
weak-key candidates and group/other write permissions. It searches conventional
and nested authorized_keys/authorized_keys2 files under local root/UID>=1000
homes and immediate /home directories. Unreadable or unsupported records
produce UNKN while preserving collected metadata. Validation:
`python3 -B -m unittest discover -s linux/tests -q`, 2026-09-08.
See [SSH-key evidence](evidence/ssh-keys.md).

[ASSUMED] RSA below 2048 bits and DSA require review. The ssh-rsa public-key
type alone is not treated as proof that a deprecated signature was used.
[UNVERIFIED] Certificates/security-key records, alternate sshd key sources,
key options and actual login acceptance are not evaluated. Discovery stops
after 100000 entries with an explicit unknown, avoids symlinks and omits key
blobs/comments from reports. Private-key files are not read.

[VERIFIED] Local-privilege inventory reports UID 0 accounts and primary/
supplementary sudo, wheel and admin group members. Duplicate UID 0 accounts
produce FAIL. A separate sudoers inventory follows local includes and reports
grant/bypass source locations; NOPASSWD and !authenticate candidates produce
WARN, unreadable coverage UNKN. Validation: `python3 -B -m unittest discover
-s linux/tests -q`, 2026-09-08.
See [privilege evidence](evidence/local-privilege.md).

[UNVERIFIED] Directory identities, effective sudo authorization, aliases,
tag overrides and command restrictions are not evaluated. Source locations
are review pointers; no password hashes or sudo command arguments are copied
into reports. Host-dependent include expansions remain unknown.

[VERIFIED] Removable-storage inventory reads USBGuard runtime defaults and
looks for narrow udev mass-storage deauthorization signatures. Permissive
runtime defaults produce WARN, missing visibility UNKN, and observed
restrictive defaults INFO with explicit limits. Configuration candidates do
not prove effective device blocking. Validation: `python3 -B -m unittest
discover -s linux/tests -q`, 2026-09-08.
See [removable-storage evidence](evidence/removable-storage.md).

[UNVERIFIED] USBGuard allow exceptions, already-connected devices, UAS,
actual udev execution and removable-media access are not evaluated. No USB
device is blocked, authorized, disconnected or otherwise changed by collection.

[VERIFIED] Disk inventory walks `lsblk`'s mounted block-device ancestry,
requiring a LUKS signature and crypt mapping before reporting observed LUKS
coverage. No observed LUKS layer yields WARN; missing root coverage or ambiguous
encryption yields UNKN. Key escrow is a separate UNKN requiring operator
evidence. Validation: `python3 -B -m unittest discover -s linux/tests
-q`, 2026-09-08. See [disk evidence](evidence/disk-encryption.md).

[UNVERIFIED] Unmounted volumes, alternate mounts, network/overlay filesystems,
file-level/hardware encryption and cipher strength are not inspected. Boot,
loop and optical devices are excluded. No keys, recovery secrets, filesystem
contents or disk changes are involved.

[VERIFIED] Audit collection reads auditd/journald service state, merged journal
configuration, retention caps and current-machine persistent `.journal` file
presence. It warns about inactive services, volatile storage, missing
persistent-file evidence or incomplete explicit age/space budgets. Unreadable
sources produce `UNKN`. Configured caps alone produce `INFO`, not a retention
guarantee. Validation: `python3 -B -m unittest discover -s linux/tests
-q`, 2026-09-08. See [audit evidence](evidence/audit-retention.md).

[UNVERIFIED] Actual oldest retained events, loaded-daemon configuration, audit
rules/loss/rotation and off-host log copies are not established. Retention caps
are upper limits, not minimum evidence windows. No logging policy is changed.

[VERIFIED] Persistence inventory covers unit/timer files, drop-ins, cron
directories/spools, crontab, anacrontab, rc.local and user units under local
root/UID>=1000 homes. It compares paths with the installed dpkg database,
flags unowned paths for review, and marks unreadable coverage `UNKN`.
Regular files precede symlinks in the capped 40-path display. Validation:
`python3 -B -m unittest discover -s linux/tests -q`, 2026-09-07.
See [persistence evidence](evidence/persistence.md).

[UNVERIFIED] Package ownership does not establish vendor provenance, intact
contents or approved execution. Generated files and enablement symlinks can
be legitimate. Symlinked directories and transient in-memory units are not
inspected. Collection is capped at 2000 files and reports incomplete coverage
as unknown. Ctrl-C stops collection with exit 130 and a short message.

[VERIFIED] Firewall collection first inspects `nft -j list ruleset`, looking
for input drop defaults covering IPv4 and IPv6 and simple unconditional accept
rules. If this does not establish the baseline, it checks `ufw status verbose`
and UFW's configured IPv6 support. Unreadable sources remain `UNKN`.
Validation: `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-07. See [firewall evidence](evidence/firewall.md).

[UNVERIFIED] Firewall `PASS` is scoped to observed defaults. Conditional
exceptions, jump chains, sets, other namespaces, and actual remote
reachability are not evaluated. UFW's IPv6 configuration is not proof of
kernel IPv6 state. No packets are sent and no firewall rules are changed.

[VERIFIED] Automatic-update collection checks the unattended-upgrades package,
effective APT periodic settings, an explicit security origin, enabled/active
APT timers, and completion/no-op markers in current and previous plain-text
logs. Installed-but-no-run-evidence and disabled schedules produce `WARN`;
unreadable sources produce `UNKN`. Validation:
`python3 -B -m unittest discover -s linux/tests -q`, 2026-09-07.
See [automatic-update evidence](evidence/automatic-updates.md).

[UNVERIFIED] Update coverage outside standard Ubuntu/Debian APT timers,
custom origin patterns, compressed/translated logs, recent success, current
patch status and repository trust are not established by this check.

[VERIFIED] The SSH check uses `sshd -T` to parse the default on-disk global
configuration. Unrestricted root login produces `FAIL`; restricted root login,
password authentication, or disabled public-key authentication produce `WARN`
for review. Missing tools, parse failures and unavailable host keys produce
`UNKN`. Validation: `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-07. See [SSH validation](evidence/sshd.md).

[UNVERIFIED] Connection-specific Match rules, alternate daemon configuration
paths and running-daemon reload state are not evaluated. Disabling password
authentication alone does not prove key-only login or MFA enforcement.

[VERIFIED] `0` means no `FAIL` findings, including runs containing `UNKN`;
it does not certify security or completeness. `1` means at least one `FAIL`.
`2` means an unsupported platform or report-export failure. Individual
exceptions become `UNKN "check errored: ..."`; empty checks become `UNKN
"check returned nothing"`. Validation: the unit-test command above and
inspection of `fieldkit_linux/cli.py`, 2026-09-07.

[ASSUMED] An operator should review unknowns and confirm management ownership
in the relevant console before writing client recommendations. This tool
does not change services, policies, packages, network rules, or credentials.
There are no cloud resources or API costs in this procedure.

## Validation and manual root handoff

Run fixtures without installing dependencies:

```bash
python3 -B -m unittest discover -s linux/tests -v
```

Exercise a genuinely missing command on the local host:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux \
  --client-name "operator missing-tool validation"
```

[VERIFIED: operator-supplied output of the following command, 2026-09-07 through 2026-09-08]
Jon completed root validation for checks 1 through 15. Root resolves visibility
gaps in SSH, firewall, persistence, sudoers, key and dormancy checks; absent
optional tools and questions requiring operator evidence remain unknown.
For future validation, run manually from the repository root and
retain the console output and generated reports locally:

```bash
sudo /usr/bin/python3 -B linux/fieldkit-linux \
  --client-name "operator root validation"
```

[ASSUMED] Compare root and non-root evidence, explain any visibility
differences, and review the results before marking this check accepted.
Keep client reports out of Git; only reviewed local-lab validation belongs in
the evidence record. Public pushes are left to the operator.

## Container posture

[VERIFIED] The runner adds 12 container findings covering the ten areas in the
[container brief](../../docs/tasks/fieldkit-container-posture.md), with separate
Compose coverage and Podman presence. Validation:
`python3 -B -m unittest discover -s linux/tests -q`, 2026-09-08
(146 tests). See [container evidence](evidence/container-posture.md).

```bash
python3 -B linux/fieldkit-linux --containers-only \
  --compose-root /path/to/approved/projects --report-path /tmp/fieldkit-reports
```

[VERIFIED] Docker queries explicitly use `/var/run/docker.sock`; CLI contexts
and `DOCKER_HOST` cannot redirect the scan to another machine. Select another
local Unix endpoint, including a rootless daemon, with `--docker-socket`.
No container is started, entered, stopped, built or pulled. Inspection selects
posture fields rather than collecting environment variables, labels or full
image/container configurations. Command: the test command above, 2026-09-08.

[VERIFIED] Running containers and locally stored image user defaults are
inspected separately. Empty workload inventories produce `INFO`; unreadable
Docker queries produce `UNKN`; observed privilege, sensitive binds, restart
persistence and unpinned references produce `WARN`. Podman presence is reported
without inspection. Command: the test command above, 2026-09-08.

[UNVERIFIED] Compose support is a bounded lexical candidate scan, not a YAML
interpreter. Repeat `--compose-root` for approved directories. It scans at most
2000 directories and 100 files, skips symlinked directories/files and common
vendor directories, and reports literal socket references without file contents.
Comments can produce candidates; interpolation, aliases, includes, parent mounts
and custom socket names can hide them. A scan without candidates remains `UNKN`.
Running-container/image inventories are each capped at 200; stopped containers
are excluded. Inventory races and unreadable sources remain unknown.

[UNVERIFIED] Daemon config attribution requires one visible dockerd process;
process arguments include systemd-supplied flags, but on-disk settings are not
proof of loaded state. TCP ports alone cannot establish authentication or
remote reachability. Named users cannot be resolved to numeric UIDs without
reading workload contents; configured users do not prove actual process UIDs.
Rootless mappings, ACLs, workload log overrides and image signatures require
further review. The kit reports posture; it does not secure container fleets.

[VERIFIED] Root and separate non-member-user validation completed on 2026-09-08:
`bash /tmp/fieldkit-container-validation/validate-privileges.sh`, executed by the
operator. Root produced four warnings; `nobody` received the required unknown
verdicts for denied Docker queries. Both runs emitted HTML and Markdown.
Exact commands, output, runtime-copy comparison and remaining limitations are
recorded in [container evidence](evidence/container-posture.md).
