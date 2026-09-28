"""
Run the inventory-updater against a single server target and save the log output.

The inventory-updater must already be running in API mode before calling this script.
Start it with:
    python main.py -c config/config_qa-de-1.yaml --api -d -l test-reports/<run>.log

Usage:
    python run_inventory_test.py --target <node-hostname>

Options:
    --target   Node hostname (NOT the BMC hostname; BMC is derived automatically)
               Example: node013-bb098.cc.qa-de-1.cloud.sap
    --url      Inventory-updater base URL (default: http://localhost:9200)
    --timeout  Seconds to wait for the request (default: 300)
"""
import argparse
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 300  # seconds — inventory collection is slow (Redfish + Netbox writes)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test the inventory-updater against a single server target."
    )
    parser.add_argument("--target", required=True,
                        help="Node hostname (e.g. node013-bb098.cc.qa-de-1.cloud.sap)")
    parser.add_argument("--url", default="http://localhost:9200", metavar="URL",
                        help="Inventory-updater base URL (default: %(default)s)")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, metavar="SECS",
                        help="Request timeout in seconds (default: %(default)s)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    # Wait for the updater to become reachable
    print(f"Waiting for inventory-updater at {base_url} ...", end="", flush=True)
    deadline = time.monotonic() + 30
    while True:
        try:
            requests.get(f"{base_url}/", timeout=2)
            print(" ready.")
            break
        except requests.exceptions.ConnectionError:
            if time.monotonic() > deadline:
                print()
                print("ERROR: Inventory-updater did not become reachable within 30 s.")
                sys.exit(1)
            print(".", end="", flush=True)
            time.sleep(1)

    print(f"Updater  : {base_url}")
    print(f"Target   : {args.target}")
    print(f"Timeout  : {args.timeout}s")
    print()

    url = f"{base_url}/inventory?target={args.target}"
    print(f"GET {url}")
    print("-" * 72)

    start = time.monotonic()
    try:
        resp = requests.get(url, timeout=args.timeout, verify=False)
        elapsed = time.monotonic() - start
        print(f"Status   : {resp.status_code}  ({elapsed:.1f}s)")
        print(f"Response : {resp.text}")
        success = resp.status_code == 200
    except requests.exceptions.Timeout:
        elapsed = time.monotonic() - start
        print(f"TIMEOUT after {elapsed:.1f}s")
        success = False
    except Exception as e:
        elapsed = time.monotonic() - start
        print(f"ERROR after {elapsed:.1f}s: {e}")
        success = False

    print("-" * 72)
    print(f"Result   : {'PASS' if success else 'FAIL'}")
    print()
    print(f"Check the log file for details (passed to main.py with -l).")

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
