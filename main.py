from redfish_collector import RedfishIventoryCollector, CollectorException
from netbox import NetboxConnection, NetboxInventoryUpdater
from lenovo_collector import LxcaIventoryCollector

import argparse
import yaml
import logging
import sys
import socket
import os
import warnings
import json
import traceback
import re
import time

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
        "-d", "--debug", help="Debugging mode", action="store_true", required=False)
    args = parser.parse_args()

    return args

def ConnectLXCA (config):
    usr = os.getenv("LENOVO_USERNAME", config['lenovo_username'])
    pwd = os.getenv("LENOVO_PASSWORD", config['lenovo_password'])
    region = os.getenv("REGION", config['region'])
    console = os.getenv("LENOVO_CONSOLE", config['lenovo_console']).replace("<region>", region)

    try:
        ip_address = socket.gethostbyname(console)
    except socket.gaierror as err:
        logging.warn(f"DNS lookup failed for LXCA {console}: {err}")
        return

    if not usr:
        logging.error("No user found in environment and config file!")
        exit(1)

    if not pwd:
        logging.error("No password found in environment and config file!")
        exit(1)

    return LxcaIventoryCollector(
            config,
            console = ip_address,
            usr = usr,
            pwd = pwd
        )


class InventoryCollector(object):

    def __init__(self, config, target, server):
        self.config = config
        self.target = target
        self.server = server

        try:
            ip_address = socket.gethostbyname(self.target)
        except socket.gaierror as err:
            logging.error(f"  Server {server}: DNS lookup failed for Remote Board {self.target}: {err}")
            raise ValueError(f"  Server {server}: DNS lookup failed for Remote Board {self.target}: {err}")

        self.ip_address = ip_address

    def redfish(self):
        inventory = {}
        logging.info(f"  Target {self.target}: Collecting using RedFish ...")

        usr = os.getenv("REDFISH_USERNAME", self.config['redfish_username'])
        pwd = os.getenv("REDFISH_PASSWORD", self.config['redfish_password'])

        if not usr:
            logging.error("No user found in environment and config file!")
            exit(1)

        if not pwd:
            logging.error("No password found in environment and config file!")
            exit(1)

        server_collector = RedfishIventoryCollector(
            timeout     = int(os.getenv('CONNECTION_TIMEOUT', self.config['connection_timeout'])),
            target      = self.target,
            ip_address  = self.ip_address,
            usr         = usr,
            pwd         = pwd
        )

        server_collector.get_session()

        try:
            inventory = server_collector.collect()

        except CollectorException as err:
            logging.error(err)

        except Exception as err:
            logging.exception(traceback.format_exc())
            exit()

        finally:
            server_collector.close_session()
        
        return inventory

    def cisco(self):
        inventory = self.redfish()
        return inventory

    def dell(self):
        inventory = self.redfish()
        return inventory

    def hpe(self):
        inventory = self.redfish()
        return inventory

    def lenovo(self):
        if LXCA:
            inventory = LXCA.collect(self.target)
        else:
            inventory = self.redfish()
        return inventory

    # Defining a function to decide which collection method to call using the manufacturer
    def collect(self, manufacturer):
        return getattr(self, manufacturer.lower())()


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
        with open(config['servers'], 'r') as f:
            serverlist = f.readlines()
    else:
        logging.info(f"==> Retrieving server list from {netbox_connection.netbox_url}")
        servers = netbox_connection.get_devices()
        for server in servers:
            serverlist.append(f"{server['name']}.cc.{server['site']['slug'][:7]}.cloud.sap")

    logging.info(f"  {len(serverlist)} device(s) found.")
    return serverlist

def run_inventory_loop(config):

    scrape_interval = os.getenv('SCRAPE_INTERVAL', config['scrape_interval'])

    try:
        while True:
            serverlist = get_serverlist(config)
            for server in serverlist:
                
                server = server.replace('\r','').replace('\n','')
                logging.info(f"==> Server {server}:")

                matches = re.match(server_pattern, server)
                if not matches:
                    logging.error(f"  Server {server}: Not matching the naming convention!")
                    continue

                node, pod, suffix = matches.groups()

                device_name = node + "-" + pod
                remote_board = node + "r-" + pod + suffix

                updater = NetboxInventoryUpdater(config, device_name, netbox_connection)

                manufacturer, model = updater.get_device_model()
                logging.info(f"  Server {server}: Manufacturer: {manufacturer}, Model: {model}")

                if not manufacturer:
                    continue

                logging.info(f"==> Server {server}: Collecting inventory")
                try:
                    collector = InventoryCollector(config, remote_board, server)
                # catch DNS errors
                except ValueError:
                    continue

                inventory = collector.collect(manufacturer)

                output = json.dumps(inventory, indent=4, sort_keys=True)
                if args.debug and output and output != "{}":
                    filename = f"{server}.txt"
                    logging.info(f"Writing inventory to file {filename}")
                    output_file = open(filename, 'w')
                    print(output, file = output_file)
                    output_file.close()

                if inventory:
                    logging.info(f"==> Server {server}: Updating Netbox inventory")
                    result = updater.update_device_inventory(inventory)

            logging.info(f"==> Sleeping for {scrape_interval} seconds.")
            time.sleep(scrape_interval)

    except KeyboardInterrupt:
        logging.info("Stopping Inventory Updater")
        exit()

if __name__ == '__main__':

    args = get_args()

    warnings.filterwarnings("ignore")

    enable_logging(args.logging, args.debug)

    config = get_config(args.config)
    if args.servers:
        config['servers'] = args.servers

    server_pattern = re.compile(r"^([a-z]+\d{2,3})-([a-z]{2,3}\d{3})(\..+)$")

    LXCA = ConnectLXCA(config)

    netbox_connection = NetboxConnection(config)

    run_inventory_loop(config)
    