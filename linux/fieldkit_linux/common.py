"""Finding contract and bounded, read-only collection primitives (Python 3.8)."""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

STATUSES = ("PASS", "FAIL", "WARN", "UNKN", "INFO")


class Unavailable(Exception):
    """A source could not be inspected; this is not a failed control."""


@dataclass(frozen=True)
class Verdict:
    Status: str
    Detail: str


@dataclass(frozen=True)
class Finding:
    Section: str
    Name: str
    Status: str
    Detail: str
    Remediation: str = ""


def compact(message):
    return " ".join(str(message).split())


def run_check(section, name, check, remediation=""):
    try:
        result = check()
        if result is None:
            result = Verdict("UNKN", "check returned nothing")
        elif not isinstance(result, Verdict) or result.Status not in STATUSES:
            result = Verdict("UNKN", "check errored: invalid verdict")
    except PermissionError:
        result = Verdict("UNKN", "needs root to read")
    except Unavailable as exc:
        result = Verdict("UNKN", compact(exc))
    except Exception as exc:  # noqa: BLE001 - the contract: any check that throws must become UNKN, never propagate
        result = Verdict("UNKN", "check errored: " + compact(exc))
    return Finding(section, name, result.Status, compact(result.Detail), remediation)


class Host:
    """Only local metadata and explicitly requested diagnostic commands.

    No shell, elevation, installation, network probes, or configuration writes.
    The root argument allows fixtures without touching the real host.
    """

    def __init__(self, root=Path("/")):
        self.root = Path(root)

    def exists(self, path):
        try:
            (self.root / path.lstrip("/")).stat()
            return True
        except FileNotFoundError:
            return False

    def which(self, binary):
        return shutil.which(binary)

    def read_text(self, path):
        with (self.root / path.lstrip("/")).open(encoding="utf-8") as stream:
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise Unavailable(path + ": exceeds 1 MiB collection limit")
        return content

    def command(self, args):
        binary = self.which(args[0])
        if binary is None:
            raise Unavailable("missing binary: " + args[0])
        env = dict(os.environ, LC_ALL="C", SYSTEMD_PAGER="cat", SYSTEMD_COLORS="0")
        try:
            result = subprocess.run(
                [binary] + list(args[1:]),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise Unavailable(args[0] + " timed out after 15 seconds")
        except FileNotFoundError:
            raise Unavailable("missing binary: " + args[0])
        if result.returncode:
            message = compact(result.stderr or result.stdout)[:300]
            if any(
                word in message.lower()
                for word in (
                    "permission denied",
                    "operation not permitted",
                    "access denied",
                    "authentication is required",
                )
            ):
                raise PermissionError(message)
            raise Unavailable(
                "{} unavailable (exit {}): {}".format(
                    args[0], result.returncode, message or "no diagnostic output"
                )
            )
        return result.stdout
