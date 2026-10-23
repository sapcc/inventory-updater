"""
Module for handling the requests and responses.
"""

import json
import logging
import os
import re
import socket
import sys
import time
import traceback

import falcon
import requests

from netbox import NetboxConnectionException, NetboxInventoryUpdater
from redfish_collector import CollectorException, RedfishIventoryCollector

logger = logging.getLogger(__name__)

# pylint: disable=no-member


class WelcomePage:  # pylint: disable=too-few-public-methods
    """
    Create the Welcome page for the API.
    """

    def on_get(self, _req, resp):
        """
        Define the GET method for the API.
        """
        resp.status = falcon.HTTP_200
        resp.content_type = "text/html"
        resp.text = """<!DOCTYPE html>
<html>
<head>
  <title>Inventory Updater</title>
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.95em; }
    pre  { background: #f4f4f4; padding: 12px; border-radius: 4px; overflow-x: auto; }
    table { border-collapse: collapse; width: 100%; }
    th, td { text-align: left; padding: 8px 12px; border: 1px solid #ddd; }
    th { background: #f0f0f0; }
  </style>
</head>
<body>
  <h1>Inventory Updater</h1>
  <p>Redfish-based inventory collection and Netbox update tool.</p>

  <h2>Endpoints</h2>

  <h3>GET /inventory</h3>
  <p>Collects the hardware inventory of a server via Redfish and updates Netbox.</p>

  <h4>Query Parameters</h4>
  <table>
    <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
    <tr>
      <td><code>target</code></td>
      <td>Yes</td>
      <td>
        Hostname or IP address of the server to query.<br>
        Hostname format: <code>nodeXXX-podXXX.&lt;suffix&gt;</code>
        (e.g. <code>node001-abc123.cc.region1.cloud.sap</code>)<br>
        IP address: a reverse DNS lookup is performed to resolve the hostname.
      </td>
    </tr>
  </table>

  <h4>Examples</h4>
  <pre>GET /inventory?target=node001-abc123.cc.eu10.cloud.sap
GET /inventory?target=10.0.0.1</pre>

  <h4>Responses</h4>
  <table>
    <tr><th>Status</th><th>Meaning</th></tr>
    <tr><td><code>200 OK</code></td><td>Inventory collected and Netbox updated successfully.</td></tr>
    <tr><td><code>400 Bad Request</code></td><td>Missing or invalid <code>target</code> parameter.</td></tr>
    <tr><td><code>500 Internal Server Error</code></td><td>Inventory collection or Netbox update failed.</td></tr>
  </table>
</body>
</html>"""


class HandlerException(Exception):
    """
    Exception class for the handler.
    """


class InventoryCollector:
    """
    Inventory Collector class.
    """

    def __init__(self, config, netbox_connection):
        self.config = config
        self.netbox_connection = netbox_connection
        self.usr = os.getenv("REDFISH_USERNAME", self.config.get("redfish_username"))
        self.pwd = os.getenv("REDFISH_PASSWORD", self.config.get("redfish_password"))

        if not self.usr:
            logger.error("No REDFISH_USERNAME found in environment or config file")
            sys.exit(1)

        if not self.pwd:
            logger.error("No REDFISH_PASSWORD found in environment or config file")
            sys.exit(1)

    def on_get(self, req, resp):  # pylint: disable=too-many-locals
        """
        Define the GET method for the API.
        """
        target = req.get_param("target")
        if not target:
            logger.error("No target parameter provided!")
            raise falcon.HTTPMissingParam("target")

        logger.info("Received Target: %s", target)
        ip_re = re.compile(
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
            r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        )

        bmc_ip = None
        if ip_re.match(target):
            logger.info("Target %s: Target is an IP Address.", target)
            try:
                host = socket.gethostbyaddr(target)[0]
                if host:
                    server_pattern = re.compile(
                        r"^([a-z]+\d{2,3})r-([a-z]{2,3}\d{3})(\..+)$"
                    )
                    matches = re.match(server_pattern, host)
                    if matches:
                        node, pod, suffix = matches.groups()
                        bmc_ip = target
                        target = node + "-" + pod + suffix
                        logger.info(
                            "Target %s: DNS lookup successful, using IP %s for BMC.",
                            target,
                            bmc_ip,
                        )
                    else:
                        logger.warning(
                            "Target %s: Reverse DNS hostname %s does not match naming convention.",
                            target,
                            host,
                        )
            except socket.herror as err:
                msg = f"Target {target}: Reverse DNS lookup failed: {err}"
                logger.error(msg)
                raise falcon.HTTPInvalidParam(msg, "target")

        start_time = time.time()
        try:
            result = self.process_single_server(target, bmc_ip=bmc_ip)
        except HandlerException as exc:
            logger.error("A Handler Exception occured: %s", traceback.format_exc())
            raise falcon.HTTPBadRequest(description=str(exc)) from exc
        except NetboxConnectionException as exc:
            logger.error("Netbox connection failed: %s", exc)
            raise falcon.HTTPServiceUnavailable(description=str(exc)) from exc

        duration = round(time.time() - start_time, 2)
        if result == 0:
            resp.status = falcon.HTTP_200
            resp.content_type = "application/json"
            resp.text = json.dumps(
                {"status": "ok", "target": target, "duration_s": duration}
            )
        else:
            resp.status = falcon.HTTP_500
            resp.content_type = "application/json"
            resp.text = json.dumps(
                {
                    "status": "error",
                    "target": target,
                    "message": "Failed to collect inventory. Check logs for details.",
                }
            )

    def process_single_server(self, server, bmc_ip=None):
        """
        Process a single server: collect inventory and update all data in Netbox.
        This method is used by both API mode and daemon/loop mode.
        """
        result = self.check_server_inventory(server, bmc_ip=bmc_ip)
        return result

    def check_server_inventory(self, server, bmc_ip=None):
        """
        Check the inventory of the server.
        """

        server_collector = None
        server_pattern = re.compile(
            r"^([a-z]+\d{1,3})-([a-z]{2,3}\d{3})(-[a-z]+\d+)?(\..+)$"
        )

        matches = re.match(server_pattern, server)

        if not matches:
            logger.warning(
                "  Server %s: Not matching the naming convention, skipping.", server
            )
            return 1

        node, pod, node_index, suffix = matches.groups()
        node_index = node_index or ""

        bmc = node + "r-" + pod + node_index + suffix

        updater = NetboxInventoryUpdater(
            device_name=node + "-" + pod + node_index, netbox_connection=self.netbox_connection
        )

        manufacturer, model = updater.get_device_model()
        logger.info("  Server %s: Model: %s %s", server, manufacturer, model)

        if not manufacturer:
            return 1

        inventory = {}
        logger.info("  Target %s: Collecting inventory using RedFish ...", server)

        try:
            server_collector = RedfishIventoryCollector(
                timeout=int(
                    os.getenv(
                        "CONNECTION_TIMEOUT", self.config.get("connection_timeout", 30)
                    )
                ),
                target=bmc,
                label=server,
                usr=self.usr,
                pwd=self.pwd,
                vendor_aliases=self.netbox_connection.manufacturer_aliases,
                lom_manufacturers=self.netbox_connection.lom_manufacturers,
                lom_max_speed_mbps=self.netbox_connection.lom_max_speed_mbps,
                bmc_ip=bmc_ip,
            )
            server_collector.get_session()

            if not server_collector.last_http_code:
                return 1

            inventory = server_collector.collect()

        except CollectorException as err:
            logger.error("  Target %s: Error collecting inventory: %s", server, err)

        except (
            requests.exceptions.RequestException,
            ConnectionError,
            TimeoutError,
        ) as err:
            logger.error(
                "  Target %s: Network error during inventory collection: %s",
                server,
                type(err).__name__,
            )
            raise HandlerException(
                f"Network error for {server}: {type(err).__name__}"
            ) from err

        except (KeyError, ValueError, TypeError) as err:
            logger.error(
                "  Target %s: Data parsing error during inventory collection: %s",
                server,
                err,
            )
            raise HandlerException(f"Data parsing error for {server}: {err}") from err

        except Exception as err:
            logger.error(
                "  Target %s: Unexpected error during inventory collection: %s",
                server,
                type(err).__name__,
            )
            raise HandlerException(traceback.format_exc()) from err

        finally:
            try:
                if server_collector:
                    server_collector.close_session()
            except (requests.exceptions.RequestException, ConnectionError) as err:
                logger.warning(
                    "  Target %s: Error closing session: %s", server, type(err).__name__
                )

        if inventory:
            # Updating Netbox inventory
            updater.update_device_inventory_and_mac_serial(inventory)

            del inventory
            del updater
            del server_collector

            return 0

        return 1
