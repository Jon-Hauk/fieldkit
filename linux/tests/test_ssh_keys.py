import base64
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.ssh_keys import (
    authorized_key_inventory,
    key_metadata,
)
from fieldkit_linux.common import Host


def record(kind, fields):
    blob = b"".join(
        struct.pack(">I", len(value)) + value for value in [kind.encode()] + fields
    )
    return kind + " " + base64.b64encode(blob).decode()


class KeyTests(unittest.TestCase):
    def test_ed25519_and_quoted_options(self):
        key = record("ssh-ed25519", [b"x" * 32])
        self.assertEqual(
            key_metadata(key + " comment with unmatched '"), ("ssh-ed25519", False)
        )
        self.assertEqual(
            key_metadata('command="echo hello",no-pty ' + key), ("ssh-ed25519", False)
        )

    def test_rsa_size_not_signature_name(self):
        for bits, weak in ((1024, True), (2048, False), (4096, False)):
            modulus = b"\0" + (1 << (bits - 1)).to_bytes(bits // 8, "big")
            self.assertEqual(
                key_metadata(record("ssh-rsa", [b"\1\0\1", modulus])),
                ("RSA-" + str(bits), weak),
            )

    def test_dsa_warns(self):
        self.assertEqual(key_metadata(record("ssh-dss", [b"x"] * 4)), ("ssh-dss", True))

    def test_bad_blob_rejected(self):
        for line in (
            "ssh-rsa invalid!",
            record("ssh-ed25519", [b"x"]),
            record("ssh-ed25519", [b"x" * 32]).replace("ssh-ed25519 ", "ssh-rsa ", 1),
        ):
            with self.assertRaises(ValueError):
                key_metadata(line)

    def test_nested_key_inventory_no_blob_or_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text(
                "root:x:0:0::/root:/bin/bash\n", encoding="utf-8"
            )
            keyfile = root / "root/nested/authorized_keys"
            keyfile.parent.mkdir(parents=True)
            key = record("ssh-ed25519", [b"x" * 32])
            keyfile.write_text(key + " PRIVATE_COMMENT\n", encoding="utf-8")
            result = authorized_key_inventory(Host(root))
            self.assertIn("keys=1", result.Detail)
            self.assertNotIn("PRIVATE_COMMENT", result.Detail)
            self.assertNotIn(key.split()[1], result.Detail)

    def test_nonexistent_home_and_symlinked_home(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "actual").mkdir()
            (root / "linked").symlink_to(root / "actual", target_is_directory=True)
            (root / "etc/passwd").write_text(
                "root:x:0:0::/missing:/bin/bash\na:x:1000:1000::/linked:/bin/bash\n",
                encoding="utf-8",
            )
            result = authorized_key_inventory(Host(root))
            self.assertNotIn("/missing:", result.Detail)
            self.assertIn("symlinked home not traversed", result.Detail)

    @unittest.skipIf(os.geteuid() == 0, "requires an unprivileged process")
    def test_real_unreadable_key_file_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text(
                "root:x:0:0::/root:/bin/bash\n", encoding="utf-8"
            )
            keyfile = root / "root/.ssh/authorized_keys"
            keyfile.parent.mkdir(parents=True)
            keyfile.write_text("", encoding="utf-8")
            keyfile.chmod(0)
            try:
                result = authorized_key_inventory(Host(root))
                self.assertEqual(result.Status, "UNKN")
                self.assertIn("needs root to read", result.Detail)
            finally:
                keyfile.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
