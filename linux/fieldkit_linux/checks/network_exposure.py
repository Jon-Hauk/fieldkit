"""Socket bindings in the current namespace; never a reachability test."""

import ipaddress
import json

from ..common import Unavailable, Verdict


def listening_sockets(host):
    output = host.command(["ss", "-H", "-lntu"])
    interfaces = {}
    gaps = []
    try:
        data = json.loads(host.command(["ip", "-j", "address", "show"]))
        if not isinstance(data, list):
            raise ValueError("interface list expected")  # noqa: TRY004 - Unavailable is the kit's own signal, not a type error
        for interface in data:
            name = interface["ifname"]
            if not isinstance(name, str):
                raise ValueError("invalid interface name")  # noqa: TRY004 - same
            for address in interface["addr_info"]:
                if address.get("family") in ("inet", "inet6"):
                    key = str(ipaddress.ip_address(address["local"]))
                    interfaces.setdefault(key, set()).add(name)
    except PermissionError:
        gaps.append("interface addresses: needs root to read")
    except (Unavailable, ValueError, KeyError, TypeError) as exc:
        gaps.append("interface addresses unavailable: " + str(exc))
    rows = set()
    for line in output.splitlines():
        parts = line.split()
        try:
            if len(parts) != 6 or (parts[0], parts[1]) not in (
                ("tcp", "LISTEN"),
                ("udp", "UNCONN"),
            ):
                raise ValueError()
            endpoint, port = parts[4].rsplit(":", 1)
            if not port.isdigit() or not 0 <= int(port) <= 65535:
                raise ValueError()
            address, _, zone = endpoint.strip("[]").partition("%")
            if address == "*":
                kind = "wildcard (family unspecified)"
            else:
                parsed = ipaddress.ip_address(address)
                address = str(parsed)
                if parsed.is_unspecified:
                    kind = f"IPv{parsed.version} wildcard"
                elif parsed.is_loopback or (
                    getattr(parsed, "ipv4_mapped", None)
                    and parsed.ipv4_mapped.is_loopback
                ):
                    kind = "loopback"
                else:
                    names = interfaces.get(address, set())
                    if zone:
                        names = names.intersection({zone})
                    kind = (
                        "interfaces=" + ",".join(sorted(names))
                        if names
                        else "interface unresolved"
                    )
                    if not names:
                        gaps.append("unresolved binding " + parts[4])
            rows.add(f"{parts[0]} {endpoint}:{port} [{kind}]")
        except ValueError:
            gaps.append("unrecognized socket row")
    detail = f"TCP listening / UDP unconnected bindings={len(rows)}. "
    detail += "; ".join(sorted(rows)[:100]) or "None observed"
    if len(rows) > 100:
        detail += f"; {len(rows) - 100} additional bindings omitted"
    detail += (
        ". Scope: current network namespace, TCP listeners and unconnected UDP sockets; "
        "interface mapping uses local address equality, not SO_BINDTODEVICE. tailscale0 "
        "is an interface name, not proof of overlay-only access. Wildcard IPv6 dual-stack "
        "behavior, firewall/NAT policy, other namespaces, process ownership and remote "
        "reachability are not evaluated. No connection probes are sent."
    )
    if gaps:
        detail += " Visibility gaps: " + "; ".join(sorted(set(gaps)))
    return Verdict("UNKN" if gaps else "INFO", detail)
