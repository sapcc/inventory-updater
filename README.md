# inventory-updater

A Redfish-based server hardware inventory collector that reads hardware details from
servers via the Redfish API and writes them into the device inventory in Netbox.

## Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Loop** (default) | — | Periodically fetches the server list from Netbox and updates every device |
| **API** | `--api` | Starts an HTTP server; inventory is triggered per request |

## Usage

```shell
python main.py [OPTIONS]

Options:
  -c, --config FILE   Config YAML file (default: config.yaml)
  -l, --logging FILE  Log file path (default: ./logfile.txt)
  -s, --servers FILE  Plain-text file with one hostname per line (overrides Netbox query)
  -a, --api           Start in API mode
  -d, --debug         Enable debug logging
```

## API Endpoints (API mode)

### `GET /`
Welcome page with usage instructions.

### `GET /inventory?target=<host>`
Collect inventory for a single server and update Netbox.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | Yes | Hostname (`node001-abc123.cc.eu10.cloud.sap`) or IP address. For IP addresses a reverse DNS lookup is performed. |

**Responses**

| Status | Meaning |
|--------|---------|
| `200 OK` | Inventory collected and Netbox updated |
| `400 Bad Request` | Missing or invalid `target` parameter |
| `500 Internal Server Error` | Collection or update failed |

## Configuration File

All options can be set in a YAML file (default `config.yaml`).
Many can also be overridden with environment variables (see table below).

```yaml
# ── Redfish credentials ───────────────────────────────────────────────────────
redfish_username: hwconsole         # env: REDFISH_USERNAME
redfish_password: secret            # env: REDFISH_PASSWORD

# ── Region ────────────────────────────────────────────────────────────────────
region: eu-de-1                     # Netbox region slug; env: REGION

# ── Connection ────────────────────────────────────────────────────────────────
connection_timeout: 10              # Redfish HTTP timeout in seconds (default: 30)
workers: 10                         # Parallel worker threads in loop mode (default: 10); env: WORKERS

# ── Loop mode ─────────────────────────────────────────────────────────────────
scrape_interval: 3600               # Seconds between full update rounds (0 = run once); env: SCRAPE_INTERVAL
servers: ./servers.txt              # Optional: static server list file (one hostname per line)

# ── API mode ──────────────────────────────────────────────────────────────────
listen_port: 9200                   # HTTP listen port (default: 9200); env: LISTEN_PORT

# ── Netbox ────────────────────────────────────────────────────────────────────
netbox:
  url: https://netbox.global.cloud.sap   # env: NETBOX_URL
  token: <token>                          # env: NETBOX_TOKEN

  query:                            # Filters passed to the Netbox devices API
    role_id: 8                      # Device role ID
    tenant_id: 1                    # Tenant ID
    status__n: decommissioning      # Exclude devices with this status
    tag__n: no-redfish              # Exclude devices with this tag

# ── Manufacturer name aliases ─────────────────────────────────────────────────
# Maps raw Redfish manufacturer strings to the canonical name used in Netbox.
# Keys are matched case-insensitively.
manufacturer_aliases:
  fsas: Fujitsu
  mlnx: Mellanox
  mellanox: Mellanox
  skhynix: SK Hynix

# ── BMC interface name fallback ───────────────────────────────────────────────
# When updating the BMC MAC address, the tool first looks for a Netbox interface
# marked "Management Only" (mgmt_only=true). If none is found it falls back to
# matching by name against this list (case-insensitive, separators ignored).
# Override in Helm values to add site-specific interface names.
bmc_interface_names:
  - remoteboard   # internal collector key
  - iLO           # HPE
  - iDRAC         # Dell
  - XCC           # Lenovo
  - iRMC          # Fujitsu
  - BMC
  - MGMT
```

## Environment Variables

| Variable | Config key | Description |
|----------|------------|-------------|
| `REDFISH_USERNAME` | `redfish_username` | Redfish login user |
| `REDFISH_PASSWORD` | `redfish_password` | Redfish login password |
| `REGION` | `region` | Netbox region slug |
| `NETBOX_URL` | `netbox.url` | Netbox base URL |
| `NETBOX_TOKEN` | `netbox.token` | Netbox API token |
| `NETBOX_QUERY` | `netbox.query` | Netbox device query params (overrides entire block) |
| `CONNECTION_TIMEOUT` | `connection_timeout` | Redfish HTTP timeout in seconds |
| `SCRAPE_INTERVAL` | `scrape_interval` | Seconds between loop runs |
| `WORKERS` | `workers` | Parallel worker thread count |
| `LISTEN_PORT` | `listen_port` | API mode HTTP listen port |

## Helm / Deployment-Only Keys

These keys are consumed by the Helm chart and are not read by the Python application itself.

| Key | Description |
|-----|-------------|
| `enabled` | Enable/disable the deployment |
| `replicas` | Number of pod replicas |
| `api.enabled` | Deploy the API mode instead of loop mode |
| `mtu` | MTU value to configure on interfaces |
| `force` | Overwrite existing serial numbers in Netbox |
| `iponly` | Only update IP addresses, skip full inventory |
| `write` | Enable writes to Netbox (set to `false` for dry-run) |
