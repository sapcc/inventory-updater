# Integration Testing

This directory contains two scripts for testing the inventory-updater against real servers in a test environment and verifying that MAC addresses are correctly collected and written to Netbox.

## Overview

```
test_api.py          Drives the inventory pipeline against live BMC endpoints
verify_coverage.py   Checks Netbox afterwards to confirm all MACs were collected
```

Running both scripts together forms a complete test cycle:

1. `test_api.py` triggers inventory collection (Redfish → Netbox)
2. `verify_coverage.py` reads back what landed in Netbox and checks completeness

---

## Prerequisites

- Python virtual environment activated (`.venv`)
- A config file for the target environment, e.g. `config/config_qa-de-1.yaml`
- A servers file listing the node hostnames to test, e.g. `servers_qa-de-1.txt`
- Credentials available via environment variables or the config file:
  - `REDFISH_USERNAME` / `REDFISH_PASSWORD`
  - `NETBOX_URL` / `NETBOX_TOKEN`

---

## test_api.py

Runs inventory collection for one or more servers by calling the inventory-updater API. Can start the API server automatically or connect to one that is already running.

### Usage

```bash
# Start the API server automatically and run against a list of servers
python tests/test_api.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt

# Run against a single server
python tests/test_api.py --config config/config_qa-de-1.yaml \
    --target node001-bb604.cc.qa-de-1.cloud.sap

# Connect to an already-running API server (started manually with main.py --api)
python tests/test_api.py --servers servers_qa-de-1.txt
```

### Options

| Option | Default | Description |
|---|---|---|
| `--config FILE` | — | Config YAML. When given, starts the API server automatically. |
| `--target HOST` | — | Single node hostname (mutually exclusive with `--servers`). |
| `--servers FILE` | — | File with one hostname per line. |
| `--url URL` | `http://localhost:9200` | Base URL of the inventory-updater API. |
| `--timeout SECS` | `300` | Per-request timeout. |
| `--output DIR` | `tests` | Directory where per-server JSON responses are written. |
| `--workers N` | `5` | Number of parallel requests. |

### Output

Each run creates a timestamped subdirectory under `--output` (e.g. `tests/20240115_143022/`) containing:

- `<hostname>.json` — the API response for each server (`{"status": "ok", ...}`)
- `app.log` — full debug log from the inventory-updater (only when `--config` is used)

The script exits with code 0 if all servers returned HTTP 200, and 1 if any failed.

---

## verify_coverage.py

Queries Netbox to check which interfaces on each test server have MAC addresses populated. Supports saving a known-good baseline snapshot and comparing future runs against it to detect regressions.

### Usage

```bash
# View current MAC coverage across all test servers (no baseline needed)
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt

# Save the current Netbox state as a known-good baseline
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt --save-snapshot

# Detect regressions by comparing against the saved snapshot
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt --check

# Single server
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --target node001-bb604.cc.qa-de-1.cloud.sap
```

### Options

| Option | Default | Description |
|---|---|---|
| `--config FILE` | — | Config YAML (required). Same file used for `test_api.py`. |
| `--target HOST` | — | Single node hostname (mutually exclusive with `--servers`). |
| `--servers FILE` | — | File with one hostname per line. |
| `--save-snapshot` | — | Save current Netbox state as baseline for future comparisons. |
| `--check` | — | Compare against saved snapshot; exits 1 if any regression is found. |
| `--snapshot FILE` | `tests/snapshots/coverage.json` | Path to the snapshot file. |

### Output without a snapshot

Shows a per-server summary and lists any interfaces that are currently missing a MAC address:

```
node001-bb604  [Lenovo]
  5/5 interfaces have MACs

node007-bb098  [Lenovo]
  3/5 interfaces have MACs
  Interfaces without MAC (2):
    ✗  L1
    ✗  L2

================================================================
Coverage : 8/10 interfaces have MACs  (2 servers)
```

### Output with `--check`

Compares each interface against the snapshot and highlights what changed:

```
node001-bb604  [Lenovo]
  5/5 interfaces have MACs
  ⚠  REGRESSION  L1   had AA:BB:CC:DD:EE:FF → now empty
  ⚠  REGRESSION  L2   had 11:22:33:44:55:66 → now empty

================================================================
Coverage : 3/5 interfaces have MACs  (1 server)
REGRESSIONS DETECTED: 2 interface(s) lost their MAC!
```

Change categories:

| Symbol | Meaning |
|---|---|
| `⚠  REGRESSION` | Interface had a MAC in the snapshot but has none now — **likely a code bug** |
| `↑  IMPROVED` | Interface had no MAC in the snapshot but now has one |
| `+  NEW` | Interface is present now but was not in the snapshot |
| `-  REMOVED` | Interface was in the snapshot but no longer exists in Netbox |

The script exits with code 1 if any regressions are found, making it suitable for use in CI pipelines.

---

## Recommended workflow

### First-time setup (after fixing a vendor gap)

```bash
# 1. Run inventory collection to update Netbox
python tests/test_api.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt

# 2. Confirm the coverage looks correct
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt

# 3. Save the verified state as the baseline
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt --save-snapshot
```

### After any code change

```bash
# 1. Re-run inventory collection
python tests/test_api.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt

# 2. Check for regressions — exits 1 if any MAC was lost
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt --check
```

### Accepting a new baseline (after an intentional improvement)

```bash
# Run both flags together: compare, then update the snapshot with the new state
python tests/verify_coverage.py --config config/config_qa-de-1.yaml \
    --servers servers_qa-de-1.txt --check --save-snapshot
```

---

## Notes

- Snapshot files are stored under `tests/snapshots/` and are git-ignored because they contain MAC addresses and are environment-specific.
- The snapshot records the full interface→MAC mapping. A missing MAC in the snapshot means that interface was already empty at baseline time — not a regression.
- `test_api.py` only returns `{"status": "ok"}` per server; it does not report which MACs were collected. `verify_coverage.py` fills that gap by reading directly from Netbox.
