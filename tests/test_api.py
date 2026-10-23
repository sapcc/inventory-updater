"""
Run the inventory-updater against one or more server targets via the API.

Pass --config to start the API server automatically (log goes to the run folder):
    python tests/test_api.py --config config/config_qa-de-1.yaml --servers servers_qa-de-1.txt

Or start the API manually first and omit --config:
    python main.py -c config/config_qa-de-1.yaml --api -d
    python tests/test_api.py --servers servers_qa-de-1.txt

Options:
    --config    Config file — if given, the API server is started automatically
    --target    Single node hostname (NOT the BMC hostname)
    --servers   File with one hostname per line
    --url       Inventory-updater base URL (default: http://localhost:9200)
    --timeout   Seconds to wait per request (default: 300)
    --output    Directory for JSON responses (default: tests)
    --workers   Parallel requests (default: 5)
"""
import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 300
DEFAULT_OUTPUT = "tests"
DEFAULT_WORKERS = 5


_WORKSPACE = Path(__file__).parent.parent


def start_api_server(config: str, log_path: Path) -> subprocess.Popen:
    """Start main.py in API mode with debug logging directed to log_path."""
    cmd = [sys.executable, "main.py", "-c", config, "--api", "-d", "-l", str(log_path)]
    return subprocess.Popen(cmd, cwd=_WORKSPACE)


def wait_for_server(base_url: str, timeout: int = 30) -> bool:
    """Wait until the inventory-updater API is reachable or the timeout expires."""
    print(f"Waiting for inventory-updater at {base_url} ...", end="", flush=True)
    deadline = time.monotonic() + timeout
    while True:
        try:
            requests.get(f"{base_url}/", timeout=2)
            print(" ready.")
            return True
        except requests.exceptions.ConnectionError:
            if time.monotonic() > deadline:
                print()
                return False
            print(".", end="", flush=True)
            time.sleep(1)


def query_target(base_url: str, target: str, timeout: int, output_dir: Path) -> dict:
    """Query the inventory endpoint for one target and write the JSON response to output_dir."""
    url = f"{base_url}/inventory?target={target}"
    start = time.monotonic()
    result = {"target": target, "status": None, "elapsed": None, "success": False, "error": None}
    try:
        resp = requests.get(url, timeout=timeout, verify=False)
        result["elapsed"] = round(time.monotonic() - start, 1)
        result["status"] = resp.status_code
        result["success"] = resp.status_code == 200

        out_file = output_dir / f"{target}.json"
        try:
            parsed = resp.json()
            out_file.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        except ValueError:
            out_file.write_text(resp.text, encoding="utf-8")

    except requests.exceptions.Timeout:
        result["elapsed"] = round(time.monotonic() - start, 1)
        result["error"] = f"Timeout after {result['elapsed']}s"
    except (requests.exceptions.RequestException, OSError) as exc:
        result["elapsed"] = round(time.monotonic() - start, 1)
        result["error"] = str(exc)

    return result


def load_servers(path: str) -> list[str]:
    """Read hostnames from a file, one per line, ignoring blank lines and comments."""
    servers = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                servers.append(line)
    return servers


def print_summary(results: list[dict]) -> int:
    """Print a pass/fail summary table and return the number of failures."""
    passed = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]

    print()
    print("=" * 72)
    print(f"Results: {len(passed)} passed, {len(failed)} failed / {len(results)} total")
    print("=" * 72)

    if failed:
        print("\nFailed:")
        for r in failed:
            detail = f"HTTP {r['status']}" if r["status"] else r["error"]
            print(f"  FAIL  {r['elapsed']:>6.1f}s  {r['target']}  ({detail})")

    if passed:
        print("\nPassed:")
        for r in passed:
            print(f"  PASS  {r['elapsed']:>6.1f}s  {r['target']}")

    print()
    return len(failed)


def parse_args() -> argparse.Namespace:
    """Build and return the parsed CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Test the inventory-updater API against one or more servers."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", metavar="HOST",
                       help="Single node hostname")
    group.add_argument("--servers", metavar="FILE",
                       help="File with one hostname per line")
    parser.add_argument("--config", metavar="FILE",
                        help="Config file — starts the API server automatically")
    parser.add_argument("--url", default="http://localhost:9200", metavar="URL",
                        help="Inventory-updater base URL (default: %(default)s)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SECS",
                        help="Per-request timeout in seconds (default: %(default)s)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, metavar="DIR",
                        help="Directory for JSON responses (default: %(default)s)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, metavar="N",
                        help="Parallel requests (default: %(default)s)")
    return parser.parse_args()


def main() -> None:
    """Run queries against all targets and exit non-zero on failures."""
    args = parse_args()

    base_url = args.url.rstrip("/")
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = [args.target] if args.target else load_servers(args.servers)
    if not targets:
        print("ERROR: no targets found.")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    api_proc = None
    if args.config:
        log_path = run_dir / "app.log"
        print(f"Starting API server (log: {log_path}) ...")
        api_proc = start_api_server(args.config, log_path)

    try:
        if not wait_for_server(base_url):
            print(f"ERROR: inventory-updater did not become reachable within 30s at {base_url}")
            sys.exit(1)

        print(f"Targets  : {len(targets)}")
        print(f"Workers  : {args.workers}")
        print(f"Timeout  : {args.timeout}s per request")
        print(f"Output   : {run_dir}")
        print()

        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(query_target, base_url, t, args.timeout, run_dir): t
                for t in targets
            }
            for future in as_completed(futures):
                result = future.result()
                status = "PASS" if result["success"] else "FAIL"
                detail = f"HTTP {result['status']}" if result["status"] else result["error"]
                print(f"  {status}  {result['elapsed']:>6.1f}s  {result['target']}  ({detail})")
                results.append(result)

        failures = print_summary(results)

    finally:
        if api_proc is not None:
            api_proc.terminate()
            api_proc.wait()

    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
