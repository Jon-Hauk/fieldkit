"""Inventory persistence files and installed-package ownership, not intent."""

import glob
import os
from pathlib import Path

from ..common import Unavailable, Verdict

SYSTEMD_ROOTS = (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/etc/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
)
CRON_ROOTS = (
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
)


def persistence_paths(host):
    files = set()
    gaps = set()
    roots = [(path, True) for path in SYSTEMD_ROOTS] + [
        (path, False) for path in CRON_ROOTS
    ]
    try:
        for line in host.read_text("/etc/passwd").splitlines():
            fields = line.split(":")
            if len(fields) != 7 or not fields[2].isdigit():
                gaps.add("local home inventory: malformed passwd record")
                continue
            if (int(fields[2]) == 0 or int(fields[2]) >= 1000) and fields[5].startswith(
                "/"
            ):
                roots.append((fields[5].rstrip("/") + "/.config/systemd/user", True))
    except PermissionError:
        gaps.add("local home inventory: needs root to read")
    except (OSError, Unavailable):
        gaps.add("local home inventory: unavailable")

    visited = set()
    examined = 0
    for root, units_only in sorted(set(roots)):
        real = host.root / root.lstrip("/")
        try:
            identity = real.stat()
            key = (identity.st_dev, identity.st_ino)
            if key in visited:
                continue
            visited.add(key)

            def onerror(error):
                if isinstance(error, PermissionError):
                    gaps.add(root + ": needs root to read")  # noqa: B023 - onerror is consumed by os.walk within this iteration
                else:
                    gaps.add(root + ": directory unavailable")  # noqa: B023 - same

            for directory, dirs, names in os.walk(
                str(real), onerror=onerror, followlinks=False
            ):
                dirs.sort()
                for name in sorted(names):
                    examined += 1
                    if examined > 2000:
                        gaps.add("persistence inventory exceeds 2000-file limit")
                        return sorted(files), sorted(gaps)
                    path = Path(directory) / name
                    if units_only and not (
                        name.endswith((".service", ".timer"))
                        or (name.endswith(".conf") and path.parent.name.endswith(".d"))
                    ):
                        continue
                    files.add("/" + str(path.relative_to(host.root)))
        except FileNotFoundError:
            continue
        except PermissionError:
            gaps.add(root + ": needs root to read")
        except OSError:
            gaps.add(root + ": directory unavailable")
    for path in ("/etc/crontab", "/etc/anacrontab", "/etc/rc.local"):
        try:
            if host.exists(path):
                files.add(path)
        except PermissionError:
            gaps.add(path + ": needs root to read")
        except OSError:
            gaps.add(path + ": unavailable")
    return sorted(files), sorted(gaps)


def package_owned(host, path, cache=None):
    if cache is None:
        cache = {}
    candidates = [path]
    # Merged-/usr systems can store /lib paths in dpkg while exposing /usr/lib.
    if path.startswith(("/usr/lib/", "/lib/")):
        alternate = path[4:] if path.startswith("/usr/") else "/usr" + path
        try:
            if os.path.samefile(
                host.root / path.lstrip("/"), host.root / alternate.lstrip("/")
            ):
                candidates.append(alternate)
        except FileNotFoundError:
            pass
    for candidate in candidates:
        pattern = glob.escape(candidate)
        broad = False
        for root in SYSTEMD_ROOTS + CRON_ROOTS:
            if candidate.startswith(root + "/"):
                pattern = glob.escape(root) + "/*"
                broad = True
                break
        if pattern not in cache:
            try:
                output = host.command(["dpkg-query", "-S", "--", pattern])
            except Unavailable as exc:
                if "no path found matching pattern" in str(exc):
                    cache[pattern] = set()
                    continue
                raise
            cache[pattern] = {
                line.rsplit(": ", 1)[1] for line in output.splitlines() if ": " in line
            }
            if not cache[pattern] or (not broad and candidate not in cache[pattern]):
                raise Unavailable(
                    "package ownership query returned no exact path match"
                )
        if candidate in cache[pattern]:
            return True
    return False


def persistence_surface(host):
    paths, gaps = persistence_paths(host)
    unowned = []
    owned = 0
    ownership_cache = {}
    if not host.which("dpkg-query"):
        gaps.append("missing binary: dpkg-query")
    else:
        for path in paths:
            try:
                if package_owned(host, path, ownership_cache):
                    owned += 1
                else:
                    unowned.append(path)
            except PermissionError:
                gaps.append("package ownership: needs root to read")
                break
            except (Unavailable, OSError):
                gaps.append("package ownership query unavailable; inventory incomplete")
                break
    unowned.sort(key=lambda path: ((host.root / path.lstrip("/")).is_symlink(), path))
    detail = f"Persistence files inventoried={len(paths)}; package-owned={owned}; not package-owned={len(unowned)}; ownership unresolved={len(paths) - owned - len(unowned)}"
    if unowned:
        detail += ". Review paths: " + "; ".join(unowned[:40])
        if len(unowned) > 40:
            detail += f"; {len(unowned) - 40} additional paths omitted from display (regular files shown before symlinks)"
    detail += (
        ". Scope: system/user unit and timer files, drop-ins, cron spools/directories, "
        "crontab, anacrontab and rc.local; user units limited to local root/UID>=1000 homes. "
        "Package ownership does not establish vendor provenance, file integrity, "
        "authorization or execution. Generated files and enablement symlinks may be legitimate; "
        "symlinked directories and transient in-memory units are not inspected."
    )
    if gaps:
        return Verdict(
            "UNKN", detail + " Visibility gaps: " + "; ".join(sorted(set(gaps)))
        )
    return Verdict("WARN" if unowned else "INFO", detail)
