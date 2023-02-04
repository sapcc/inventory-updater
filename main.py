from redfish_collector import RedfishIventoryCollector, CollectorException
from netbox import NetboxInventoryUpdater
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
import pprint

def ConnectLXCA (config):
    usr = os.getenv("LENOVO_USERNAME", config['lenovo_username'])
    pwd = os.getenv("LENOVO_PASSWORD", config['lenovo_password'])
    region = os.getenv("REGION", config['region'])
    console = os.getenv("LENOVO_CONSOLE", config['lenovo_console']).replace("<region>", region)

    try:
        ip_address = socket.gethostbyname(console)
    except socket.gaierror as err:
        logging.error(f"DNS lookup failed for LXCA {console}: {err}")
        exit(1)

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

    def __init__(self, config, target):
        self.config = config
        self.target = target

        try:
            ip_address = socket.gethostbyname(remote_board)
        except socket.gaierror as err:
            logging.error(f"Server {server}: DNS lookup failed for Remote Board {remote_board}: {err}")
            raise ValueError(f"Server {server}: DNS lookup failed for Remote Board {remote_board}: {err}")

        self.host = ip_address

    def redfish(self):
        inventory = {}
        logging.info(f"Target {self.target}: Collecting using RedFish ...")

        usr = os.getenv("REDFISH_USERNAME", self.config['redfish_username'])
        pwd = os.getenv("REDFISH_PASSWORD", self.config['redfish_password'])

        if not usr:
            logging.error("No user found in environment and config file!")
            exit(1)

        if not pwd:
            logging.error("No password found in environment and config file!")
            exit(1)

        server_collector = RedfishIventoryCollector(
            config,
            target = self.target,
            host = self.host,
            usr = usr,
            pwd = pwd
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
        # inventory = self.redfish()
        # return inventory

        inventory = LXCA.collect(self.target)
        return inventory

    # Defining a function to decide which collection method to call using the manufacturer
    def collect(self, manufacturer):
        return getattr(self, manufacturer.lower())()


def enable_logging():
    # enable logging
    logger = logging.getLogger()
    
    formatter = logging.Formatter('%(asctime)-15s %(process)d %(filename)20s:%(lineno)-3d %(levelname)-7s %(message)s')

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    if args.logging:
        fh = logging.FileHandler(args.logging, mode='w')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

if __name__ == '__main__':
    # command line options
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", help="Specify config yaml file", metavar="FILE", required=False, default="config.yml")
    parser.add_argument(
        "-s", "--serverlist", help="Specify a text file with a list of servers to examine", metavar="FILE", required=False, default="serverlist.txt")
    parser.add_argument(
        "-l", "--logging", help="Log all messages to a file", metavar="FILE", required=False)
    parser.add_argument(
        "-d", "--debug", help="Debugging mode", action="store_true", required=False)
    args = parser.parse_args()

    warnings.filterwarnings("ignore")

    enable_logging()

    # get the config
    try:
        with open(args.config, 'r') as config_file:
            config =  yaml.load(config_file.read(), Loader=yaml.FullLoader)
    except FileNotFoundError as e:
        print("Config File not found: {0}".format(e))
        exit(1)

    # get the server list
    try:
        with open(args.serverlist, 'r') as serverlist_file:
            serverlist =  serverlist_file.readlines()
    except FileNotFoundError as e:
        print("Server File not found: {0}".format(e))
        exit(1)

    server_pattern = re.compile(r"^([a-z]+\d{3})-([a-z]{2,3}\d{3})(\..+)$")

    LXCA = ConnectLXCA(config)
    
    for server in serverlist:
        
        server = server.replace('\r','').replace('\n','')
        filename = f"{server}.txt"

        matches = re.match(server_pattern, server)
        if not matches:
            logging.error(f"Server {server}: Not matching the naming convention!")
            continue

        node, pod, suffix = matches.groups()

        device_name = node + "-" + pod
        remote_board = node + "r-" + pod + suffix

        updater = NetboxInventoryUpdater(config, device_name)

        manufacturer, model = updater.get_device_model()
        logging.info(f"Server {server}: Manufacturer: {manufacturer}, Model: {model}")

        if not manufacturer:
            continue

        if config['collect']:

            try:
                collector = InventoryCollector(config, remote_board)
            # catch DNS errors
            except ValueError:
                continue

            inventory = collector.collect(manufacturer)

            output = json.dumps(inventory, indent=4, sort_keys=True)

            if output and output != "{}":
                output_file = open(filename, 'w')
                print(output, file = output_file)
                output_file.close()

        if os.path.exists(filename):
            input_file = open(filename, 'r')
            inventory = json.load(input_file)
            input_file.close()

            result = updater.update_device_inventory(inventory)
