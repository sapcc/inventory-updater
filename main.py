"""
Inventory Updater is a tool that retrieves the inventory of a server
using Redfish and updates it in Netbox. The tool can be run in two modes:
as a daemon that periodically checks the inventory of the servers and updates it in Netbox,
or as an API that listens for requests to check the inventory of a server.
"""

import argparse
import logging
import os
import warnings
import time
import gc       # Garbage collection module
import sys
from mac_serial_ng import InventoryContext
from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler
from socketserver import ThreadingMixIn
import yaml
import falcon
from netbox import NetboxInventoryUpdater  

from handler import WelcomePage, InventoryCollector, HandlerException
from netbox import NetboxConnection, NetboxConnectionException


def get_args():
    """
    Get the command line options
    """

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c", "--config",
        help="Specify config yaml file",
        metavar="FILE",
        required=False,
        default="config.yaml"
    )

    parser.add_argument(
        "-l", "--logging",
        help="Log all messages to a file",
        metavar="FILE",
        required=False,
        default="./logfile.txt"
    )

    parser.add_argument(
        "-s",
        "--servers",
        help="Use a file with a list of servers instead of pulling it from Netbox.",
        metavar="FILE",
        required=False
    )

    parser.add_argument(
        "-a",
        "--api",
        help="Start in API mode and listen for requests to check the inventory of a server.",
        action="store_true",
        required=False
    )

    parser.add_argument(
        "-d",
        "--debug",
        help="Debugging mode",
        action="store_true",
        required=False
    )

    parser.add_argument("-q", "--query", type=str, required=True, help="Pod or node name.")

    arguments = parser.parse_args()

    return arguments

class _SilentHandler(WSGIRequestHandler):
    """WSGI handler that does not log requests."""

    def log_message(self, format, *args): # pylint: disable=redefined-builtin
        """Log nothing."""


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Thread per request HTTP server."""

    daemon_threads = True

def falcon_app(config, connection):
    """
    Start the Falcon API
    """
    port = int(os.getenv("LISTEN_PORT", config.get("listen_port", 9200)))
    addr = "0.0.0.0"
    logging.info("Starting Redfish Prometheus Server on Port %s", port)

    api = falcon.API()
    api.add_route("/inventory", InventoryCollector(config, connection))
    api.add_route("/", WelcomePage())

    with make_server(addr, port, api, ThreadingWSGIServer, handler_class=_SilentHandler) as httpd:
        httpd.daemon = True # pylint: disable=attribute-defined-outside-init
        try:
            httpd.serve_forever()
        except (KeyboardInterrupt, SystemExit):
            logging.info("Stopping Redfish Prometheus Server")


def enable_logging(filename, debug):
    """
    enable logging
    """

    logger = logging.getLogger()

    formatter = logging.Formatter(
        '%(asctime)-15s %(process)d %(filename)20s:%(lineno)-4d %(levelname)-7s %(message)s'
    )

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    if filename:
        try:
            fh = logging.FileHandler(filename, mode='w')
        except FileNotFoundError as err:
            logging.error("Could not open logfile %s: %s", filename, err)
            sys.exit(1)

        fh.setFormatter(formatter)
        logger.addHandler(fh)

def get_config(filename):
    """
    Read the config
    """

    try:
        with open(filename, 'r', encoding="utf8") as config_file:
            file_config =  yaml.load(config_file.read(), Loader=yaml.FullLoader)
    except FileNotFoundError as err:
        logging.error("Config File not found: %s", err)
        sys.exit(1)
    return file_config

def get_serverlist(config, connection):
    """
    Get the serverlist from the file or from Netbox
    """
    serverlist = []

    if config.get('servers'):
        logging.info("==> Retrieving server list from file %s", config['servers'])
        try:
            with open(config['servers'], 'rt', encoding="utf8") as f:
                serverlist = f.readlines()
        except FileNotFoundError as err:
            logging.error("Serverlist File not found: %s", err)
            sys.exit(1)
    else:
        logging.info("==> Retrieving server list from %s", connection.netbox_url)
        servers = connection.get_devices()
        for server in servers:
            serverlist.append(f"{server['name']}.cc.{server['site']['slug'][:7]}.cloud.sap")

    logging.info("  %s device(s) found.", len(serverlist))
    return serverlist

def run_inventory_loop(config, connection):
    """
    Loop to check the inventory of the servers
    """
    scrape_interval = os.getenv('SCRAPE_INTERVAL', config['scrape_interval'])
    serverlist = []

    while True:
        try:

            try:
                serverlist = get_serverlist(config, connection)
            except NetboxConnectionException as err:
                logging.error(err)

            for server in serverlist:
                try:
                    server = server.replace('\r','').replace('\n','')
                    collector= InventoryCollector(config, connection)
                    collector.check_server_inventory(server)

                except (HandlerException, NetboxConnectionException) as err:
                    logging.error(err)

                del collector

            gc.collect() # trigger garbage collection

        except KeyboardInterrupt:
            logging.info("Keyboard Interrupt. Stopping Inventory Updater...")
            sys.exit()

        logging.info("==> Sleeping for %s seconds.", scrape_interval)
        time.sleep(scrape_interval)



if __name__ == '__main__':

    call_args = get_args()
   
    warnings.filterwarnings("ignore")

    enable_logging(call_args.logging, call_args.debug)

    configuration = get_config(call_args.config)
    netbox_url = configuration.get("netbox", {}).get("url", "")
    NETBOX_ENVIRONMENT = "staging" if "staging" in netbox_url else "global"

    if call_args.servers:
        configuration['servers'] = call_args.servers

    netbox_connection = NetboxConnection(configuration)

    #Currently if it is not a pod node, we set special_netbox_case to true
    special_netbox_case = "ap" in str(call_args.query).lower()
    if not special_netbox_case:
        try:
            device_info = NetboxInventoryUpdater(call_args.query, netbox_connection).get_device()
            if not device_info:
                raise NetboxConnectionException(f"Device {call_args.query} not found in Netbox")
            tags = [tag["name"].lower() for tag in device_info.get("tags", [])]
            special_netbox_case = any("pod" in tag for tag in tags)
        except NetboxConnectionException as e:
            print(f"Warning: Could not determine if device is APOD: {e}")

    inventory_obj = InventoryContext(NETBOX_ENVIRONMENT, configuration, special_netbox_case)

    if call_args.api:
        falcon_app(configuration, netbox_connection)
    else:
        inventory_obj.runSerialNumberScript(call_args.query)
        run_inventory_loop(configuration, netbox_connection)

