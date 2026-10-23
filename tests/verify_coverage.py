"""
Verify MAC coverage for all test servers by querying Netbox.

Typical workflow
----------------
1. Run test_api.py against the qa-de-1 servers to update Netbox.
2. Run this script with --save-snapshot to capture the known-good baseline.
3. After any code change, re-run test_api.py and then this script with --check
   to detect regressions (interfaces that previously had MACs but no longer do).

Usage
-----
  # View current MAC coverage (no comparison):
  python tests/verify_coverage.py --config config/config_qa-de-1.yaml \\
      --servers servers_qa-de-1.txt

  # Save current state as known-good baseline:
  python tests/verify_coverage.py --config config/config_qa-de-1.yaml \\
      --servers servers_qa-de-1.txt --save-snapshot

  # Detect regressions against the saved snapshot (exits 1 if any found):
  python tests/verify_coverage.py --config config/config_qa-de-1.yaml \\
      --servers servers_qa-de-1.txt --check

Options
-------
  --config         Config YAML (same file used for test_api.py / main.py)
  --target         Single node hostname
  --servers        File with one hostname per line
  --save-snapshot  Save current Netbox interface state as baseline
  --check          Compare against snapshot; exit 1 on regressions
  --snapshot       Path to snapshot file
                   (default: tests/snapshots/coverage.json)
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_WORKSPACE = Path(__file__).parent.parent
_DEFAULT_SNAPSHOT = _WORKSPACE / "tests" / "snapshots" / "coverage.json"

sys.path.insert(0, str(_WORKSPACE))
from netbox import NetboxConnection, NetboxConnectionException  # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.load(f.read(), Loader=yaml.FullLoader)


def load_servers(path: str) -> list[str]:
    servers = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                servers.append(line)
    return servers


def device_name_from_hostname(hostname: str) -> str | None:
    """Extract device name from a full hostname.

    'node001-bb604.cc.qa-de-1.cloud.sap'  →  'node001-bb604'
    'node001-bb604-node01'                 →  'node001-bb604-node01'
    """
    m = re.match(r"^([a-z]+\d{1,3}-[a-z]{2,3}\d{3}(?:-[a-z]+\d+)?)", hostname)
    return m.group(1) if m else None


def _nb_get(nb: NetboxConnection, url: str, params: dict) -> dict:
    """Wrapper around send_request that passes a high page limit."""
    params.setdefault("limit", 1000)
    return nb.send_request(url, "GET", params=params)


def get_device(nb: NetboxConnection, device_name: str) -> dict | None:
    try:
        resp = _nb_get(nb, nb.netbox_devices_url, {"name": device_name})
        results = resp.get("results", [])
        return results[0] if results else None
    except NetboxConnectionException as exc:
        print(f"  ERROR querying device '{device_name}': {exc}", file=sys.stderr)
        return None


def get_interfaces(nb: NetboxConnection, device_id: int) -> list[dict]:
    try:
        url = f"{nb.netbox_url}/api/dcim/interfaces/"
        resp = _nb_get(nb, url, {"device_id": device_id})
        return resp.get("results", [])
    except NetboxConnectionException as exc:
        print(f"  ERROR querying interfaces for device {device_id}: {exc}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Per-server collection
# ---------------------------------------------------------------------------

def collect_coverage(nb: NetboxConnection, hostname: str) -> dict | None:
    """Return interface MAC state for one server, keyed by interface name."""
    device_name = device_name_from_hostname(hostname)
    if not device_name:
        print(f"  SKIP {hostname}: cannot parse device name", file=sys.stderr)
        return None

    device = get_device(nb, device_name)
    if not device:
        print(f"  SKIP {hostname}: '{device_name}' not found in Netbox")
        return None

    manufacturer = ""
    dt = device.get("device_type") or {}
    mfr = dt.get("manufacturer") or {}
    manufacturer = mfr.get("name", "")

    interfaces = get_interfaces(nb, device["id"])
    iface_macs: dict[str, str | None] = {
        iface["name"]: iface.get("mac_address")
        for iface in interfaces
        if iface.get("name")
    }

    return {"device_name": device_name, "manufacturer": manufacturer, "interfaces": iface_macs}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _mark(condition: bool) -> str:
    return "✓" if condition else "✗"


def print_server_report(
    hostname: str,
    cov: dict,
    snap_entry: dict | None,
) -> tuple[int, int, int]:
    """Print per-server coverage lines.

    Returns (with_mac_count, no_mac_count, regression_count).
    """
    iface_macs: dict[str, str | None] = cov["interfaces"]
    snap_ifaces: dict[str, str | None] = (snap_entry or {}).get("interfaces", {})

    total = len(iface_macs)
    with_mac = sum(1 for v in iface_macs.values() if v)
    regressions = 0

    mfr_tag = f"  [{cov['manufacturer']}]" if cov["manufacturer"] else ""
    print(f"\n{hostname}{mfr_tag}")
    print(f"  {with_mac}/{total} interfaces have MACs")

    if snap_entry:
        for name in sorted(iface_macs):
            mac = iface_macs[name]
            snap_mac = snap_ifaces.get(name)
            if snap_mac and not mac:
                print(f"  ⚠  REGRESSION  {name:<24} had {snap_mac} → now empty")
                regressions += 1
            elif not snap_mac and mac:
                print(f"  ↑  IMPROVED    {name:<24} now {mac}")
            elif name not in snap_ifaces:
                print(f"  +  NEW         {name:<24} ({'MAC' if mac else 'no MAC'})")
            # else: unchanged — only show on mismatch
        for name in sorted(snap_ifaces):
            if name not in iface_macs:
                was = snap_ifaces[name] or "no MAC"
                print(f"  -  REMOVED     {name:<24} (was {was})")
    else:
        # No snapshot — show missing MACs so the user can spot obvious gaps
        missing_names = sorted(n for n, v in iface_macs.items() if not v)
        if missing_names:
            print(f"  Interfaces without MAC ({len(missing_names)}):")
            for name in missing_names:
                print(f"    {_mark(False)}  {name}")

    return with_mac, total - with_mac, regressions


# ---------------------------------------------------------------------------
# Snapshot I/O
# ---------------------------------------------------------------------------

def save_snapshot(
    servers_coverage: dict[str, dict],
    snapshot_path: Path,
) -> None:
    data: dict = {
        "_meta": {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "server_count": len(servers_coverage),
        }
    }
    for hostname, cov in servers_coverage.items():
        data[hostname] = {
            "manufacturer": cov["manufacturer"],
            "interfaces": cov["interfaces"],
        }
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    print(f"\nSnapshot saved → {snapshot_path}  ({len(servers_coverage)} servers)")


def load_snapshot(snapshot_path: Path) -> dict:
    if not snapshot_path.exists():
        return {}
    return json.loads(snapshot_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify MAC coverage for test servers via Netbox."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", metavar="HOST", help="Single node hostname")
    group.add_argument("--servers", metavar="FILE", help="File with one hostname per line")
    parser.add_argument(
        "--config", metavar="FILE", required=True,
        help="Config YAML (same file used for test_api.py / main.py)",
    )
    parser.add_argument(
        "--save-snapshot", action="store_true",
        help="Save current Netbox state as known-good baseline",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Compare against snapshot; exit 1 on regressions",
    )
    parser.add_argument(
        "--snapshot", metavar="FILE", default=str(_DEFAULT_SNAPSHOT),
        help=f"Snapshot file path (default: tests/snapshots/coverage.json)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    snapshot_path = Path(args.snapshot)

    config = load_config(args.config)
    nb = NetboxConnection(config)

    targets = [args.target] if args.target else load_servers(args.servers)
    if not targets:
        print("ERROR: no targets found.", file=sys.stderr)
        sys.exit(1)

    snapshot: dict = {}
    if args.check:
        snapshot = load_snapshot(snapshot_path)
        if not snapshot:
            print(
                f"ERROR: --check requires a saved snapshot but none found at {snapshot_path}.\n"
                "Run with --save-snapshot first after a known-good test run.",
                file=sys.stderr,
            )
            sys.exit(1)

    print(f"Querying Netbox coverage for {len(targets)} server(s) ...")

    servers_coverage: dict[str, dict] = {}
    for raw_host in targets:
        hostname = raw_host.strip()
        if not hostname:
            continue
        cov = collect_coverage(nb, hostname)
        if cov is not None:
            servers_coverage[hostname] = cov

    # Print report
    total_ok = total_missing = total_regressions = 0
    for hostname, cov in servers_coverage.items():
        snap_entry = snapshot.get(hostname) if args.check else None
        ok, missing, regressions = print_server_report(hostname, cov, snap_entry)
        total_ok += ok
        total_missing += missing
        total_regressions += regressions

    # Summary
    total_ifaces = total_ok + total_missing
    print()
    print("=" * 68)
    print(
        f"Coverage : {total_ok}/{total_ifaces} interfaces have MACs"
        f"  ({len(servers_coverage)} servers)"
    )
    if args.check:
        if total_regressions:
            print(f"REGRESSIONS DETECTED: {total_regressions} interface(s) lost their MAC!")
        else:
            print("No regressions detected vs snapshot.")
    print("=" * 68)

    if args.save_snapshot:
        save_snapshot(servers_coverage, snapshot_path)

    if args.check and total_regressions > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
