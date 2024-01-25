from handler import welcomePage, InventoryCollector, HandlerException
from netbox import NetboxConnection

import argparse
import yaml
import logging
import os
import warnings
import time
import gc

from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler
from socketserver import ThreadingMixIn
import falcon

def get_args():
    # command line options
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", help="Specify config yaml file", metavar="FILE", required=False, default="config.yaml")
    parser.add_argument(
        "-l", "--logging", help="Log all messages to a file", metavar="FILE", required=False, default="./logfile.txt")
    parser.add_argument(
        "-s", "--servers", help="Use a file with a list of servers instead of pulling it from Netbox.", metavar="FILE", required=False)
    parser.add_argument(
        "-a", "--api", help="Start in API mode and listen for requests to check the inventory of a server.", action="store_true", required=False)
    parser.add_argument(
        "-d", "--debug", help="Debugging mode", action="store_true", required=False)
    args = parser.parse_args()

    return args

class _SilentHandler(WSGIRequestHandler):
    """WSGI handler that does not log requests."""

    def log_message(self, format, *args):
        """Log nothing."""
        pass


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Thread per request HTTP server."""
    pass

def falcon_app():
    port = int(os.getenv("LISTEN_PORT", config.get("listen_port", 9200)))
    addr = "0.0.0.0"
    logging.info("Starting Redfish Prometheus Server on Port %s", port)

    api = falcon.API()
    api.add_route("/inventory", InventoryCollector(config, netbox_connection))
    api.add_route("/", welcomePage())

    with make_server(addr, port, api, ThreadingWSGIServer, handler_class=_SilentHandler) as httpd:
        httpd.daemon = True
        try:
            httpd.serve_forever()
        except (KeyboardInterrupt, SystemExit):
            logging.info("Stopping Redfish Prometheus Server")


def enable_logging(filename, debug):
    # enable logging
    logger = logging.getLogger()
    
    formatter = logging.Formatter('%(asctime)-15s %(process)d %(filename)20s:%(lineno)-3d %(levelname)-7s %(message)s')

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
        except FileNotFoundError as e:
            logging.error(f"Could not open logfile {filename}: {e}")
            exit(1)

        fh.setFormatter(formatter)
        logger.addHandler(fh)

def get_config(filename):
    # get the config
    try:
        with open(filename, 'r') as config_file:
            config =  yaml.load(config_file.read(), Loader=yaml.FullLoader)
    except FileNotFoundError as e:
        logging.error(f"Config File not found: {e}")
        exit(1)
    return config

def get_serverlist(config):
    serverlist = []

    if config.get('servers'):
        logging.info(f"==> Retrieving server list from file {config['servers']}")
        try:
            with open(config['servers'], 'r') as f:
                serverlist = f.readlines()
        except FileNotFoundError as e:
            logging.error(f"Serverlist File not found: {e}")
            exit(1)
    else:
        logging.info(f"==> Retrieving server list from {netbox_connection.netbox_url}")
        servers = netbox_connection.get_devices()
        for server in servers:
            serverlist.append(f"{server['name']}.cc.{server['site']['slug'][:7]}.cloud.sap")

    logging.info(f"  {len(serverlist)} device(s) found.")
    return serverlist

def run_inventory_loop(config):

    scrape_interval = os.getenv('SCRAPE_INTERVAL', config['scrape_interval'])

    while True:
        try:
            serverlist = get_serverlist(config) # Get the list of servers to check

            for server in serverlist:
                
                server = server.replace('\r','').replace('\n','')
                collector= InventoryCollector(config, netbox_connection)
                collector.check_server_inventory(server)

            del serverlist
            del collector
            gc.collect()

            logging.info(f"==> Sleeping for {scrape_interval} seconds.")
            time.sleep(scrape_interval)

        except HandlerException as err:
            logging.error(err)

        except KeyboardInterrupt:
            logging.info("Keyboard Interrupt. Stopping Inventory Updater...")
            exit()


if __name__ == '__main__':

    args = get_args()

    warnings.filterwarnings("ignore")

    enable_logging(args.logging, args.debug)

    config = get_config(args.config)
    if args.servers:
        config['servers'] = args.servers

    netbox_connection = NetboxConnection(config)

    if args.api:
        falcon_app()
    else:
        run_inventory_loop(config)
    