from collector import RedfishIventoryCollector
from netbox import NetboxInventoryUpdater

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

def enable_logging():
    # enable logging
    logger = logging.getLogger()
    if args.debug:
        logger.setLevel('DEBUG')
    else:
        logger.setLevel('INFO')
    format = '%(asctime)-15s %(process)d %(filename)s:%(lineno)3d %(levelname)-7s %(message)s'
    if args.logging:
        logging.basicConfig(filename=args.logging, format=format)
    else:
        logging.basicConfig(stream=sys.stdout, format=format)

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
        with open(args.serverlist, 'r') as server_file:
            serverlist =  server_file.readlines()
    except FileNotFoundError as e:
        print("Server File not found: {0}".format(e))
        exit(1)

    usr = os.getenv("REDFISH_USERNAME", config['username'])
    pwd = os.getenv("REDFISH_PASSWORD", config['password'])

    if not usr:
        logging.error("No user found in environment and config file!")
        exit(1)

    if not pwd:
        logging.error("No password found in environment and config file!")
        exit(1)

    server_pattern = re.compile(r"^([a-z]+\d{3})-([a-z]{2,3}\d{3})(\..+)$")
    
    for server in serverlist:
        
        server = server.replace('\r','').replace('\n','')
        matches = re.match(server_pattern, server)
        if not matches:
            logging.error(f"Server {server}: Not matching the naming convention!")
            continue

        node, pod, suffix = matches.groups()

        remote_board = node + "r-" + pod + suffix
        try:
            ip_address = socket.gethostbyname(remote_board)
        except socket.gaierror as err:
            logging.warning(f"Server {server}: DNS lookup failed for Remote Board {remote_board}: {err}")
            continue
      
        if config['collect']:
            server_collector = RedfishIventoryCollector(
                config,
                target = remote_board,
                host = ip_address,
                usr = usr,
                pwd = pwd
            )

            server_collector.get_session()

            try:
                inventory = server_collector.collect()

            except Exception as err:
                logging.exception(traceback.format_exc())
                exit()

            finally:
                server_collector.close_session()
        
            output = json.dumps(inventory, indent=4, sort_keys=True)

            if output and output != "{}":
                filename = f"{server}.txt"
                output_file = open(filename, 'w')
                print(output, file = output_file)
                output_file.close()

        filename = f"{server}.txt"
        input_file = open(filename, 'r')
        inventory = json.load(input_file)
        input_file.close()

        device_name = node + "-" + pod
        netbox_inventory_updater = NetboxInventoryUpdater(config, device_name)

        result = netbox_inventory_updater.update_device_inventory(inventory)
