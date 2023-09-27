import requests
import json
import os
import socket
from requests.auth import HTTPBasicAuth
import re
import argparse
import warnings
import sys

warnings.filterwarnings("ignore")

def get_args():
    parser = argparse.ArgumentParser(description='Python script using Redfish API to reset(reboot) iDRAC')
    parser.add_argument('-ip', "--ip_address", help='IP address', required=False)
    parser.add_argument('-u', "--username", help='username', required=False)
    parser.add_argument('-p', "--password", help='password', required=False)

    if len(sys.argv)==1:
        parser.print_help()
        exit(1)

    args = parser.parse_args()
    return args
    
def get_manufacturer(netbox_device):
    print(f"[INFO] Get Manufacturer from Netbox for device {netbox_device} ...")

    netbox_url = "https://netbox.global.cloud.sap"
    netbox_token = os.getenv("NETBOX_API_KEY")
    netbox_params = {'q': netbox_device, 'exclude': 'config_context'}
    netbox_devices_url = f"{netbox_url}/api/dcim/devices/"
    netbox_manufacturers_url = f"{netbox_url}/api/dcim/manufacturers/"

    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.get(
            netbox_devices_url,
            headers=headers,
            params=netbox_params
        )

    except Exception as e:
        print(f"An error occurred: {str(e)}")

    results = response.json().get('results')
    if results:
        manufacturer = results[0]['device_type']['manufacturer']['name']
        return manufacturer
    else:
        print("[ERROR] No manufacturer received from Netbox!")
        exit(1)

def restart_remote_board(target, username, password):

    # Set the authentication headers for Redfish
    auth = HTTPBasicAuth(username, password)
    headers = {'Content-Type': 'application/json'}

    print(f"[INFO] Manufacturer: {manufacturer}")

    if manufacturer == "HPE":
        # Set the Redfish URL for resetting the iLO
        redfish_url = f"https://{target}/redfish/v1/Managers/HpEthernetNetworkInterface/Reset"
        reset_payload = {}

    elif manufacturer == "Dell":

        # Redfish URL to restart the iDRAC
        redfish_url = f'https://{target}/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset'
        # JSON payload for the reset action
        reset_payload = {
            "ResetType": "GracefulRestart"
        }

    try:
        response = requests.post(
            redfish_url,
            json = reset_payload,
            auth = auth, #(username, password),
            headers=headers,
            verify=False  # Disabling SSL certificate verification for simplicity (not recommended in production)
        )

    except Exception as e:
        print(f"[ERROR] An error occurred contacting Remote Board: {str(e)}")
        exit(1)

    # Check if the request was successful
    if response.status_code == 202 or response.status_code == 204:
        print("[INFO] Remote Board restart initiated successfully")
    else:
        print(f"[ERROR] Failed to reset Remote Board: {response.status_code}")
        print(response.text)


##############################################################################
if __name__ == '__main__':

    args = get_args()

    # Set the iLO IP address, username and password
    target = args.ip_address
    username = args.username
    password = args.password

    print(f"[INFO] Restarting Remote Board with IP {target}")

    ip_re = re.compile(
        r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    )

    node_name_re = r"^(node\d{3})r-(\w{2}\d{3})\.cc.(\w{2}-\w{2}-\d)\.cloud\.sap$"

    if ip_re.match(target):
        try:
            host = socket.gethostbyaddr(target)[0]
        except socket.herror as err:
            print(f"[ERROR] Reverse DNS lookup failed for {target}")
        if host:
            matches = re.match(node_name_re, host).groups()
            netbox_device = matches[0] + "-" + matches[1]
            target = host

        print(f"[INFO] Resolved to hostname {host}")
    else:
        print(f"[ERROR] No valid IP provided: {target}!")
        exit(1)

    manufacturer = get_manufacturer(netbox_device)  
    restart_remote_board(target, username, password)
