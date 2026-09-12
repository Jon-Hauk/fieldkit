"""Bounded authorized-key metadata inventory; never emits key blobs/comments."""

import base64
import os
import shlex
import struct
from collections import Counter
from pathlib import Path

from ..common import Unavailable, Verdict
from .identity import local_accounts


def key_metadata(line):
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    algorithm = next(lexer)
    if not algorithm.startswith(("ssh-", "ecdsa-", "sk-")):
        algorithm = next(lexer)  # one options field, possibly containing quotes
    encoded = next(lexer)
    blob = base64.b64decode(encoded, validate=True)
    offset = 0

    def field():
        nonlocal offset
        if offset + 4 > len(blob):
            raise ValueError("truncated key")
        length = struct.unpack_from(">I", blob, offset)[0]
        offset += 4
        if offset + length > len(blob):
            raise ValueError("truncated key")
        value = blob[offset : offset + length]
        offset += length
        return value

    if field().decode("ascii") != algorithm:
        raise ValueError("algorithm mismatch")
    weak = False
    if algorithm == "ssh-rsa":
        exponent, modulus = field(), field()
        if not exponent or not modulus or exponent[0] & 128 or modulus[0] & 128:
            raise ValueError("invalid RSA integer")
        bits = int.from_bytes(modulus, "big").bit_length()
        if int.from_bytes(exponent, "big") < 3 or bits == 0:
            raise ValueError("invalid RSA parameters")
        weak = bits < 2048
        label = "RSA-" + str(bits)
    elif algorithm == "ssh-ed25519":
        if len(field()) != 32:
            raise ValueError("invalid Ed25519 length")
        label = algorithm
    elif algorithm == "ssh-dss":
        for _ in range(4):
            if not field():
                raise ValueError("invalid DSA field")
        label, weak = algorithm, True
    elif algorithm in (
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ):
        if field().decode("ascii") != algorithm[len("ecdsa-sha2-") :] or not field():
            raise ValueError("invalid ECDSA record")
        label = algorithm
    else:
        raise ValueError("unsupported key type")
    if offset != len(blob):
        raise ValueError("trailing key data")
    return label, weak


def authorized_key_inventory(host):
    accounts = local_accounts(host)
    homes = {
        home
        for name, uid, gid, home, shell in accounts
        if (uid == 0 or uid >= 1000) and home.startswith("/") and home != "/"
    }
    gaps = set()
    # Include orphaned immediate home directories without asserting offboarding.
    try:
        for child in (host.root / "home").iterdir():
            if child.is_dir() and not child.is_symlink():
                homes.add("/home/" + child.name)
    except FileNotFoundError:
        pass
    except PermissionError:
        gaps.add("/home: needs root to read")
    paths = set()
    examined = 0
    scan_homes = []
    # Always attempt conventional key locations before bounded deep discovery.
    for home in sorted(homes):
        try:
            if not host.exists(home):
                continue
            if (host.root / home.lstrip("/")).is_symlink():
                gaps.add(home + ": symlinked home not traversed")
                continue
        except PermissionError:
            gaps.add(home + ": needs root to read")
            continue
        scan_homes.append(home)
        for name in ("authorized_keys", "authorized_keys2"):
            paths.add(home.rstrip("/") + "/.ssh/" + name)
    for home in scan_homes:

        def onerror(error):
            gaps.add(
                home  # noqa: B023 - onerror is consumed by os.walk within this iteration
                + (
                    ": needs root to read"
                    if isinstance(error, PermissionError)
                    else ": directory inventory incomplete"
                )
            )

        for directory, dirs, names in os.walk(
            str(host.root / home.lstrip("/")), onerror=onerror, followlinks=False
        ):
            dirs.sort(key=lambda name: (name != ".ssh", name))
            examined += len(dirs) + len(names)
            if examined > 100000:
                gaps.add("home discovery exceeds 100000-entry limit")
                break
            for name in names:
                if name in ("authorized_keys", "authorized_keys2"):
                    paths.add(
                        "/" + str((Path(directory) / name).relative_to(host.root))
                    )
        if examined > 100000:
            break
    details = []
    warnings = False
    uid_names = {uid: name for name, uid, gid, home, shell in accounts}
    for path in sorted(paths):
        real = host.root / path.lstrip("/")
        try:
            if real.is_symlink() or any(parent.is_symlink() for parent in real.parents):
                gaps.add(path + ": symlinked key file not read")
                continue
            metadata = real.stat()
            content = host.read_text(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            gaps.add(path + ": needs root to read")
            continue
        except (OSError, Unavailable, UnicodeError):
            gaps.add(path + ": unreadable key file")
            continue
        counts = Counter()
        weak = 0
        invalid = 0
        for line in content.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                kind, ancient = key_metadata(line)
                counts[kind] += 1
                weak += int(ancient)
            except (ValueError, UnicodeError, StopIteration):
                invalid += 1
        if invalid:
            gaps.add(path + f": {invalid} unsupported/malformed key records")
        writable = bool(metadata.st_mode & 0o022)
        warnings = warnings or weak > 0 or writable or metadata.st_uid not in uid_names
        types = (
            ",".join(f"{kind}={count}" for kind, count in sorted(counts.items()))
            or "none parsed"
        )
        details.append(
            "{}: owner={} (uid {}); keys={}; types={}; weak={}; group/other-writable={}".format(
                path,
                uid_names.get(metadata.st_uid, "unmapped"),
                metadata.st_uid,
                sum(counts.values()),
                types,
                weak,
                "yes" if writable else "no",
            )
        )
    detail = (
        "; ".join(details)
        or "No readable authorized_keys files found in inspected homes"
    )
    detail += (
        ". Scope: local root/UID>=1000 homes and immediate /home directories; "
        "bounded recursive discovery without symlink traversal. RSA<2048 and DSA require review. "
        "Certificate/security-key records, sshd alternate key sources, key options and "
        "actual login acceptance are not evaluated. Key blobs and comments are omitted."
    )
    if gaps:
        return Verdict("UNKN", detail + " Visibility gaps: " + "; ".join(sorted(gaps)))
    return Verdict("WARN" if warnings else "INFO", detail)
