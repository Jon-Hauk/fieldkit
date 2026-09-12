"""Observe block-device encryption without reading keys or changing mappings."""

import json

from ..common import Verdict


def disk_encryption(host):
    output = host.command(
        ["lsblk", "--json", "--paths", "--output", "NAME,TYPE,FSTYPE,MOUNTPOINT"]
    )
    try:
        document = json.loads(output)
    except (ValueError, TypeError):
        return Verdict("UNKN", "lsblk returned invalid JSON")
    if not isinstance(document, dict) or not isinstance(
        document.get("blockdevices"), list
    ):
        return Verdict("UNKN", "lsblk returned an unrecognized device tree")
    observations = []
    malformed = False

    def visit(nodes, luks=False, crypt=False, excluded=False, depth=0):
        nonlocal malformed
        if depth > 32:
            malformed = True
            return
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get("type"), str):
                malformed = True
                continue
            node_luks = luks or node.get("fstype") == "crypto_LUKS"
            node_crypt = crypt or node["type"] == "crypt"
            node_excluded = excluded or node["type"] in ("loop", "rom")
            mount = node.get("mountpoint")
            if mount is not None and not isinstance(mount, str):
                malformed = True
            elif (
                mount
                and mount.startswith("/")
                and not node_excluded
                and mount not in ("/boot", "/boot/efi")
            ):
                if node_luks and node_crypt:
                    state = "LUKS-backed mapping observed"
                elif node_crypt or not node.get("fstype"):
                    state = "encryption type unresolved"
                else:
                    state = "no LUKS layer observed"
                observations.append((mount, state))
            children = node.get("children", [])
            if not isinstance(children, list):
                malformed = True
            else:
                visit(children, node_luks, node_crypt, node_excluded, depth + 1)

    visit(document["blockdevices"])
    observations = sorted(set(observations))
    detail = "; ".join(mount + ": " + state for mount, state in observations)
    if not detail:
        detail = "No mounted root/data block filesystems were identified"
    detail += (
        ". Scope: lsblk-reported mounted block-device ancestry; boot, loop and optical "
        "devices excluded. Unmounted volumes, alternate mounts, network/overlay filesystems, "
        "file-level/hardware encryption and cipher strength are not evaluated."
    )
    if malformed or not any(mount == "/" for mount, state in observations):
        return Verdict(
            "UNKN", detail + " Root coverage or device-tree completeness is unresolved."
        )
    if any(state == "encryption type unresolved" for mount, state in observations):
        return Verdict("UNKN", detail)
    return Verdict(
        "WARN"
        if any(state == "no LUKS layer observed" for mount, state in observations)
        else "PASS",
        detail,
    )


def key_escrow():
    return Verdict(
        "UNKN",
        "Key escrow cannot be established from host encryption metadata. "
        "Obtain operator evidence of recovery-key custody, authorized access and a "
        "tested recovery procedure. No keys or recovery material are collected.",
    )
