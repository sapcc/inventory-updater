"""
Module for handling the requests and responses.
"""
import logging
import socket
import re
import os
import time
import traceback
import falcon

from redfish_collector import RedfishIventoryCollector, CollectorException
from netbox import NetboxInventoryUpdater

# pylint: disable=no-member

class WelcomePage:
    """
    Create the Welcome page for the API.
    """

    def on_get(self, resp):
        """
        Define the GET method for the API.
        """
        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = """
        <h1>Inventory Updater</h1>
        <h2>Redfish based Inventory to Netbox update tool.</h2>
        <ul>
            <li>Use <a href="/inventory">/inventory</a> to retrieve the inventory and update it in Netbox.</li>
        </ul>
        """

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
            logging.error("No user found in environment and config file!")
            exit(1)

        if not self.pwd:
            logging.error("No password found in environment and config file!")
            exit(1)


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
            result = self.check_server_inventory(target)
        except HandlerException as exc:
            logging.error("A Handler Exception occured: %s", traceback.format_exc())
            raise falcon.HTTPBadRequest("Bad Request", traceback.format_exc()) from exc

        if result == 0:
            duration = round(time.time() - start_time, 2)
            resp.status = falcon.HTTP_200
            resp.content_type = 'text/html'
            resp.body = (
                f"<p>Successfully pulled the inventory of target {target}."
                f" Duration: {duration}s.</p>"
            )
        else:
            resp.status = falcon.HTTP_500
            resp.content_type = 'text/html'
            resp.body = f"<p>Failed to pull the inventory of target {target}.</p>"

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
                timeout     = int(os.getenv('CONNECTION_TIMEOUT',
                                            self.config['connection_timeout'])),
                target      = bmc,
                usr         = self.usr,
                pwd         = self.pwd
            )
            server_collector.get_session()

            if not server_collector.last_http_code:
                return 1

            inventory = server_collector.collect()

        except CollectorException as err:
            logging.error("  Target %s: Error collecting inventory: %s", bmc, err)

        except Exception as err:
            raise HandlerException(traceback.format_exc()) from err

        finally:
            try:
                if server_collector:
                    server_collector.close_session()
            except Exception as err:
                raise HandlerException(err) from err

        if inventory:
            logging.info("==> Server %s: Updating Netbox inventory", server)
            updater.update_device_inventory(inventory)

            del inventory
            del updater
            del server_collector

            return 0

        return 1
            