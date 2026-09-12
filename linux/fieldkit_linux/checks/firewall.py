"""Observe inbound firewall defaults without changing rules or probing peers."""

import json
import re

from ..common import Unavailable, Verdict


def nft_policy(text):
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return Verdict("UNKN", "nft: invalid JSON ruleset")
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        return Verdict("UNKN", "nft: unrecognized ruleset schema")
    chains = {}
    rules = []
    for entry in document["nftables"]:
        if not isinstance(entry, dict):
            return Verdict("UNKN", "nft: malformed ruleset entry")
        if "chain" in entry:
            chain = entry["chain"]
            if not isinstance(chain, dict):
                return Verdict("UNKN", "nft: malformed chain")
            if chain.get("hook") != "input" or chain.get("family") not in (
                "inet",
                "ip",
                "ip6",
            ):
                continue
            if not all(
                isinstance(chain.get(key), str) for key in ("table", "name", "policy")
            ):
                return Verdict("UNKN", "nft: incomplete input base-chain policy")
            if chain["policy"] not in ("drop", "accept"):
                return Verdict("UNKN", "nft: unrecognized input policy")
            chains[(chain["family"], chain["table"], chain["name"])] = chain["policy"]
        if "rule" in entry:
            if not isinstance(entry["rule"], dict):
                return Verdict("UNKN", "nft: malformed rule")
            rules.append(entry["rule"])
    families = {key[0] for key, policy in chains.items() if policy == "drop"}
    covered = "inet" in families or {"ip", "ip6"}.issubset(families)
    broad_accept = False
    for rule in rules:
        key = (rule.get("family"), rule.get("table"), rule.get("chain"))
        if key not in chains:
            continue
        expressions = rule.get("expr")
        if not isinstance(expressions, list) or not all(
            isinstance(item, dict) for item in expressions
        ):
            return Verdict("UNKN", "nft: malformed input rule expressions")
        if any("accept" in item for item in expressions) and all(
            set(item).issubset({"accept", "counter", "comment"}) for item in expressions
        ):
            broad_accept = True
    # No names, counters, addresses or ports are needed to establish defaults.
    detail = "nft input base chains={}; IPv4+IPv6 drop defaults={}; direct unconditional accept={}".format(
        len(chains),
        "yes" if covered else "not established",
        "yes" if broad_accept else "not detected",
    )
    detail += (
        ". Scope: input default policies and simple unconditional accepts only; "
        "conditional rules, jumps, sets, other namespaces and reachability are not evaluated."
    )
    return Verdict("PASS" if covered and not broad_accept else "WARN", detail)


def ufw_policy(text, ipv6_config):
    if re.search(r"^Status: inactive\s*$", text, re.MULTILINE):
        return Verdict("WARN", "UFW reports inactive")
    if not re.search(r"^Status: active\s*$", text, re.MULTILINE):
        return Verdict("UNKN", "UFW: unrecognized status")
    match = re.search(r"^Default: (deny|reject|allow) \(incoming\)", text, re.MULTILINE)
    if not match:
        return Verdict("UNKN", "UFW: incoming default could not be parsed")
    # Last assignment wins in this shell-style config; do not evaluate shell.
    values = re.findall(
        r"^\s*IPV6\s*=\s*['\"]?(yes|no)['\"]?\s*(?:#.*)?$", ipv6_config, re.MULTILINE
    )
    if not values:
        return Verdict(
            "UNKN", "UFW active; IPv6 configuration could not be established"
        )
    detail = f"UFW reports active; incoming default={match.group(1)}; configured IPv6={values[-1]}"
    detail += (
        ". Scope: UFW-reported default and configured IPv6 support; "
        "allow rules, kernel IPv6 state, other namespaces and reachability are not evaluated."
    )
    return Verdict(
        "PASS"
        if match.group(1) in ("deny", "reject") and values[-1] == "yes"
        else "WARN",
        detail,
    )


def host_firewall(host):
    def collect(check, label):
        try:
            return check()
        except PermissionError:
            return Verdict("UNKN", label + ": needs root to read")
        except FileNotFoundError:
            return Verdict("UNKN", label + ": configuration file unavailable")
        except Unavailable as exc:
            if "need to be root" in str(exc).lower():
                return Verdict("UNKN", label + ": needs root to read")
            return Verdict("UNKN", label + ": " + str(exc))

    nft = collect(
        lambda: nft_policy(host.command(["nft", "-j", "list", "ruleset"])), "nft"
    )
    if nft.Status == "PASS":
        return nft

    def ufw_check():
        output = host.command(["ufw", "status", "verbose"])
        if re.search(r"^Status: inactive\s*$", output, re.MULTILINE):
            return Verdict("WARN", "UFW reports inactive")
        return ufw_policy(output, host.read_text("/etc/default/ufw"))

    ufw = collect(ufw_check, "UFW")
    if ufw.Status == "PASS":
        return Verdict("PASS", ufw.Detail + " nft observation: " + nft.Detail)
    status = "UNKN" if "UNKN" in (nft.Status, ufw.Status) else "WARN"
    return Verdict(status, nft.Detail + "; " + ufw.Detail)
