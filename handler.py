from redfish_collector import RedfishIventoryCollector, CollectorException
from netbox import NetboxInventoryUpdater

import traceback
import falcon
import logging
import socket
import re
import os

class welcomePage:
    def on_get(self, req, resp):
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
    pass


class InventoryCollector(object):

    def __init__(self, config, netbox_connection):
        self.config = config
        self.netbox_connection = netbox_connection
        self.usr = os.getenv("REDFISH_USERNAME", self.config['redfish_username'])
        self.pwd = os.getenv("REDFISH_PASSWORD", self.config['redfish_password'])

        if not self.usr:
            logging.error("No user found in environment and config file!")
            exit(1)

        if not self.pwd:
            logging.error("No password found in environment and config file!")
            exit(1)


    def on_get(self, req, resp):
        self.server = req.get_param("target")
        if not self.server:
            logging.error("No target parameter provided!")
            raise falcon.HTTPMissingParam("target")

        logging.info(f"Received Target: {self.server}")

        try:
            result = self.check_server_inventory(self.server)
        except HandlerException:
            raise falcon.HTTPBadRequest("Bad Request", traceback.format_exc())

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/html'
        resp.body = f"<p>Sucessfully scraped target {self.server}</p>"

    def check_server_inventory(self, server):
        
        logging.info(f"==> Server {server}")

        server_pattern = re.compile(r"^([a-z]+\d{2,3})-([a-z]{2,3}\d{3})(\..+)$")
        matches = re.match(server_pattern, server)
        
        if not matches:
            raise HandlerException(f"  Server {server}: Not matching the naming convention!")

        node, pod, suffix = matches.groups()

        self.device_name = node + "-" + pod
        self.target = node + "r-" + pod + suffix

        try:
            self.ip_address = socket.gethostbyname(self.target)
        except socket.gaierror as err:
            raise HandlerException(f"  Server {server}: DNS lookup failed for Remote Board {self.target}: {err}")

        updater = NetboxInventoryUpdater(
            device_name = self.device_name, 
            netbox_connection = self.netbox_connection
        )

        manufacturer, model = updater.get_device_model()
        logging.info(f"  Server {server}: Model: {manufacturer} {model}")

        if not manufacturer:
            return 1

        logging.info(f"==> Server {server}: Collecting inventory")

        inventory = {}
        logging.info(f"  Target {self.target}: Collecting using RedFish ...")

        server_collector = RedfishIventoryCollector(
            timeout     = int(os.getenv('CONNECTION_TIMEOUT', self.config['connection_timeout'])),
            target      = self.target,
            ip_address  = self.ip_address,
            usr         = self.usr,
            pwd         = self.pwd
        )

        server_collector.get_session()

        try:
            inventory = server_collector.collect()

        except CollectorException as err:
            raise HandlerException(err)

        except Exception as err:
            raise HandlerException(traceback.format_exc())

        finally:
            server_collector.close_session()

        if inventory:
            logging.info(f"==> Server {server}: Updating Netbox inventory")
            updater.update_device_inventory(inventory)
            
            del inventory
            del updater
            del server_collector

            return 0
            