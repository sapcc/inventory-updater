"""
Module for handling the requests and responses.
"""
import logging
import socket
import re
import os
import sys
import time
import traceback
import falcon
import requests

from redfish_collector import RedfishIventoryCollector, CollectorException
from netbox import NetboxInventoryUpdater

# pylint: disable=no-member

class WelcomePage:
    """
    Create the Welcome page for the API.
    """

    def on_get(self, _req, resp):
        """
        Define the GET method for the API.
        """
        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
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
        self.usr = os.getenv("REDFISH_USERNAME", self.config.get('redfish_username'))
        self.pwd = os.getenv("REDFISH_PASSWORD", self.config.get('redfish_password'))

        if not self.usr:
            logging.error("No REDFISH_USERNAME found in environment or config file")
            sys.exit(1)

        if not self.pwd:
            logging.error("No REDFISH_PASSWORD found in environment or config file")
            sys.exit(1)


    def on_get(self, req, resp):
        """
        Define the GET method for the API.
        """
        target = req.get_param("target")
        if not target:
            logging.error("No target parameter provided!")
            raise falcon.HTTPMissingParam("target")

        logging.info("Received Target: %s", target)
        ip_re = re.compile(
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
            r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        )

        if ip_re.match(target):
            logging.info("Target %s: Target is an IP Address.", target)
            try:
                host = socket.gethostbyaddr(target)[0]
                if host:
                    server_pattern = re.compile(r"^([a-z]+\d{2,3})r-([a-z]{2,3}\d{3})(\..+)$")
                    matches = re.match(server_pattern, host)
                    node, pod, suffix = matches.groups()
                    target = node + "-" + pod + suffix
                    logging.info("Target %s: DNS lookup successful.", target)
            except socket.herror as err:
                msg = f"Target {target}: Reverse DNS lookup failed: {err}"
                logging.error(msg)
                raise falcon.HTTPInvalidParam(msg, "target")

        start_time = time.time()
        try:
            result = self.process_single_server(target)
        except HandlerException as exc:
            logging.error("A Handler Exception occured: %s", traceback.format_exc())
            raise falcon.HTTPBadRequest("Bad Request", traceback.format_exc()) from exc

        if result == 0:
            duration = round(time.time() - start_time, 2)
            resp.status = falcon.HTTP_200
            resp.content_type = 'text/html'
            resp.text = (
                f"<p>Successfully pulled the inventory of target {target}."
                f" Duration: {duration}s.</p>"
            )
        else:
            resp.status = falcon.HTTP_500
            resp.content_type = 'text/html'
            resp.text = f"<p>Failed to pull the inventory of target {target}.</p>"

    def process_single_server(self, server):
        """
        Process a single server: collect inventory and update all data in Netbox.
        This method is used by both API mode and daemon/loop mode.
        """
        result = self.check_server_inventory(server)
        return result

    def check_server_inventory(self, server):
        """
        Check the inventory of the server.
        """
        logging.info("==> Server %s", server)

        server_collector = None
        server_pattern = re.compile(r"^([a-z]+\d{2,3})-([a-z]{2,3}\d{3})(\..+)$")

        matches = re.match(server_pattern, server)

        if not matches:
            raise HandlerException(f"  Server {server}: Not matching the naming convention!")

        node, pod, suffix = matches.groups()

        bmc = node + "r-" + pod + suffix

        updater = NetboxInventoryUpdater(
            device_name = node + "-" + pod,
            netbox_connection = self.netbox_connection
        )

        manufacturer, model = updater.get_device_model()
        logging.info("  Server %s: Model: %s %s", server, manufacturer, model)

        if not manufacturer:
            return 1

        logging.info("==> Server %s: Collecting inventory", server)

        inventory = {}
        logging.info("  Target %s: Collecting using RedFish ...", bmc)

        try:
            server_collector = RedfishIventoryCollector(
                timeout        = int(os.getenv('CONNECTION_TIMEOUT',
                                               self.config.get('connection_timeout', 30))),
                target         = bmc,
                usr            = self.usr,
                pwd            = self.pwd,
                vendor_aliases = self.netbox_connection.manufacturer_aliases
            )
            server_collector.get_session()

            if not server_collector.last_http_code:
                return 1

            inventory = server_collector.collect()

        except CollectorException as err:
            logging.error("  Target %s: Error collecting inventory: %s", bmc, err)

        except (requests.exceptions.RequestException, ConnectionError, TimeoutError) as err:
            logging.error("  Target %s: Network error during inventory collection: %s", bmc, type(err).__name__)
            raise HandlerException(f"Network error for {bmc}: {type(err).__name__}") from err

        except (KeyError, ValueError, TypeError) as err:
            logging.error("  Target %s: Data parsing error during inventory collection: %s", bmc, err)
            raise HandlerException(f"Data parsing error for {bmc}: {err}") from err

        except Exception as err:
            logging.error("  Target %s: Unexpected error during inventory collection: %s", bmc, type(err).__name__)
            raise HandlerException(traceback.format_exc()) from err

        finally:
            try:
                if server_collector:
                    server_collector.close_session()
            except (requests.exceptions.RequestException, ConnectionError) as err:
                logging.warning("  Target %s: Error closing session: %s", bmc, type(err).__name__)

        if inventory:
            logging.info("==> Server %s: Updating Netbox inventory", server)
            
            updater.update_device_inventory_and_mac_serial(inventory)

            logging.info("==> Server %s: Done.", server)

            del inventory
            del updater
            del server_collector

            return 0

        return 1
            