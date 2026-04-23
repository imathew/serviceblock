"""
Serviceblock blocklist generator.

Maintains services.txt (grouped by category, sorted, with metadata) and
generates blocklist.txt (ABP format) from active (uncommented) entries.

services.txt format:
  active:    discord                 # Discord (12 rules)
  commented: # kik                   # Kik (5 rules)
  header:    # ── messaging ──────── (section divider, not a service)

On every run, services.txt is rebuilt: new AdGuard services are added
(commented out), removed services are warned about, and the file is
kept grouped by category and sorted alphabetically within each group.
"""
import json
import re
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

URL = "https://adguardteam.github.io/HostlistsRegistry/assets/services.json"
ID_RE = re.compile(r"^[a-z0-9_]+$")


def fetch_data():
    return json.loads(urllib.request.urlopen(URL).read())["blocked_services"]


def read_active_ids():
    """Return the set of currently active (uncommented) service IDs."""
    active = set()
    for line in Path("services.txt").read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            candidate = s.split()[0]
            if ID_RE.match(candidate):
                active.add(candidate)
    return active


def sync_services_txt(svc_data):
    """Rebuild services.txt grouped by category, preserving active/commented state."""
    active_ids = read_active_ids() if Path("services.txt").exists() else set()

    # Collect commented IDs too (to detect services removed from AdGuard's list)
    commented_ids = set()
    if Path("services.txt").exists():
        for line in Path("services.txt").read_text().splitlines():
            s = line.strip()
            if s.startswith("#"):
                candidate = s.lstrip("#").strip().split()[0] if s.lstrip("#").strip() else ""
                if ID_RE.match(candidate):
                    commented_ids.add(candidate)

    known_ids = {svc["id"] for svc in svc_data}
    gone = (active_ids | commented_ids) - known_ids
    if gone:
        print(f"WARNING: service IDs no longer in AdGuard list: {sorted(gone)}")

    by_group = defaultdict(list)
    for svc in svc_data:
        by_group[svc["group"]].append(svc)

    def rule_str(n):
        return f"{n} rule" if n == 1 else f"{n} rules"

    lines = [
        "# Services to block for kids and unregistered devices.",
        "# Uncomment a line to enable blocking, comment out to disable.",
        f"# Source: {URL}",
        "",
    ]

    for group in sorted(by_group.keys()):
        services = sorted(by_group[group], key=lambda s: s["id"])
        lines.append(f"# ── {group} " + "─" * max(1, 56 - len(group)))
        for svc in services:
            suffix = f"  # {svc['name']} ({rule_str(len(svc['rules']))})"
            if svc["id"] in active_ids:
                lines.append(f"{svc['id']:<24}{suffix}")
            else:
                lines.append(f"# {svc['id']:<22}{suffix}")
        lines.append("")

    Path("services.txt").write_text("\n".join(lines))
    n_commented = len(known_ids) - len(active_ids)
    print(f"services.txt: {len(active_ids)} active, {n_commented} commented out")


def generate_blocklist(svc_data):
    """Generate blocklist.txt from active entries in services.txt."""
    active_ids = read_active_ids()

    rules = sorted({
        rule
        for svc in svc_data
        if svc["id"] in active_ids
        for rule in svc["rules"]
    })

    svc_by_id = {svc["id"]: svc for svc in svc_data}
    found = [svc_by_id[i] for i in sorted(active_ids) if i in svc_by_id]
    missing = active_ids - svc_by_id.keys()
    if missing:
        print(f"WARNING: unknown service IDs: {sorted(missing)}")

    blocking_names = ", ".join(svc["name"] for svc in found)
    not_blocking_names = ", ".join(
        svc["name"] for svc in sorted(svc_data, key=lambda s: s["name"].lower())
        if svc["id"] not in active_ids
    )
    rule_count = len(rules)

    output = [
        "[Adblock Plus]",
        "! Title: ServiceBlock",
        f"! Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"! Source: {URL}",
        "!",
        f"! Blocking: {blocking_names} ({rule_count} rules)",
        "!",
        f"! Not blocking: {not_blocking_names}",
        "!",
        *rules,
        "",
    ]

    Path("blocklist.txt").write_text("\n".join(output))
    print(f"Generated {rule_count} rules for {len(found)} services")


if __name__ == "__main__":
    svc_data = fetch_data()
    sync_services_txt(svc_data)
    generate_blocklist(svc_data)
