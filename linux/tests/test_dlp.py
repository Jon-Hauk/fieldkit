import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.dlp import disk_encryption, key_escrow
from fieldkit_linux.common import Host, run_check


def node(kind="part", fstype="ext4", mount="/", children=None):
    result = {
        "name": "/dev/fixture",
        "type": kind,
        "fstype": fstype,
        "mountpoint": mount,
    }
    if children is not None:
        result["children"] = children
    return result


class DiskHost:
    def __init__(self, nodes):
        self.text = json.dumps({"blockdevices": nodes})

    def command(self, args):
        return self.text


class DiskTests(unittest.TestCase):
    def test_unencrypted_root_warns(self):
        self.assertEqual(disk_encryption(DiskHost([node()])).Status, "WARN")

    def test_luks_root_passes(self):
        root = node(fstype="crypto_LUKS", mount=None, children=[node(kind="crypt")])
        self.assertEqual(disk_encryption(DiskHost([root])).Status, "PASS")

    def test_plain_data_prevents_pass(self):
        root = node(fstype="crypto_LUKS", mount=None, children=[node(kind="crypt")])
        self.assertEqual(
            disk_encryption(DiskHost([root, node(mount="/data")])).Status, "WARN"
        )

    def test_plain_crypt_is_not_assumed_luks(self):
        self.assertEqual(disk_encryption(DiskHost([node(kind="crypt")])).Status, "UNKN")

    def test_missing_root_and_fstype_unknown(self):
        self.assertEqual(
            disk_encryption(DiskHost([node(mount="/data")])).Status, "UNKN"
        )
        self.assertEqual(disk_encryption(DiskHost([node(fstype=None)])).Status, "UNKN")

    def test_boot_and_loop_excluded(self):
        root = node(fstype="crypto_LUKS", mount=None, children=[node(kind="crypt")])
        self.assertEqual(
            disk_encryption(
                DiskHost(
                    [
                        root,
                        node(mount="/boot/efi"),
                        node(kind="loop", mount="/snap/example"),
                    ]
                )
            ).Status,
            "PASS",
        )

    def test_malformed_tree_unknown(self):
        for nodes in ([None], [node(children="invalid")]):
            self.assertEqual(disk_encryption(DiskHost(nodes)).Status, "UNKN")

    def test_missing_binary_unknown(self):
        with patch("shutil.which", return_value=None):
            result = run_check("DLP", "encryption", lambda: disk_encryption(Host()))
        self.assertEqual(result.Status, "UNKN")
        self.assertIn("missing binary: lsblk", result.Detail)

    def test_escrow_remains_separate_unknown(self):
        self.assertEqual(key_escrow().Status, "UNKN")
        self.assertIn("No keys", key_escrow().Detail)


if __name__ == "__main__":
    unittest.main()
