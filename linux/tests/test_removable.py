import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fieldkit_linux.checks.removable import (
    removable_storage,
    udev_block_candidate,
)
from fieldkit_linux.common import Host, Unavailable


class RemovableTests(unittest.TestCase):
    def test_storage_deauthorization_candidates(self):
        for text in (
            'DRIVERS=="usb-storage", ATTR{authorized}="0"',
            'ATTRS{bInterfaceClass}=="08", \\\n+ATTR{authorized}:="0"',
        ):
            self.assertTrue(udev_block_candidate(text))

    def test_comments_and_unrelated_rules_not_candidates(self):
        for text in (
            '# DRIVERS=="usb-storage", ATTR{authorized}="0"',
            'DRIVERS=="usb-storage", MODE="0660"',
            'ATTR{authorized}="0"',
        ):
            self.assertFalse(udev_block_candidate(text))

    def test_runtime_defaults_info_with_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host(directory)
            with patch.object(host, "command", side_effect=["block", "apply-policy"]):
                result = removable_storage(host)
            self.assertEqual(result.Status, "INFO")
            self.assertIn("allow exceptions", result.Detail)

    def test_allow_default_warns(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host(directory)
            with patch.object(host, "command", side_effect=["allow", "apply-policy"]):
                self.assertEqual(removable_storage(host).Status, "WARN")

    def test_missing_binary_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host(directory)
            with patch.object(
                host, "command", side_effect=Unavailable("missing binary: usbguard")
            ):
                self.assertEqual(removable_storage(host).Status, "UNKN")

    def test_denied_runtime_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host(directory)
            with patch.object(host, "command", side_effect=PermissionError()):
                self.assertIn("needs root to read", removable_storage(host).Detail)

    def test_udev_override_masks_vendor_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for folder in ("usr/lib/udev/rules.d", "etc/udev/rules.d"):
                (root / folder).mkdir(parents=True)
            (root / "usr/lib/udev/rules.d/90-storage.rules").write_text(
                'DRIVERS=="usb-storage", ATTR{authorized}="0"', encoding="utf-8"
            )
            (root / "etc/udev/rules.d/90-storage.rules").write_text(
                "# overridden", encoding="utf-8"
            )
            host = Host(root)
            with patch.object(host, "command", side_effect=["block", "apply-policy"]):
                self.assertIn("candidates=0", removable_storage(host).Detail)


if __name__ == "__main__":
    unittest.main()
