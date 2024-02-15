"""
restart.py - Restart a remote board using Redfish API
"""

import socket
import re
import argparse
import warnings
import sys
import requests
from requests.auth import HTTPBasicAuth

warnings.filterwarnings("ignore")

def get_args():
    """
    Get the command line options
    """

    parser = argparse.ArgumentParser(
        description='Python script using Redfish API to reset(reboot) iDRAC'
    )

    parser.add_argument(
        '-t',
        "--target",
        help='IP address or hostname of the remote board.',
        required=True
    )

    parser.add_argument(
        '-u',
        "--username",
        help='username for accessing the remote board',
        required=True
    )

    parser.add_argument(
        '-p',
        "--password",
        help='password for accessing the remote board',
        required=True
    )

    parser.add_argument(
        '-f',
        "--force",
        help = "force restart",
        action='store_true',
        required=False
    )

    parser.add_argument(
        '-to',
        "--timeout",
        help = "timeout for redfish request",
        default=10,
        required=False,
        type=int
    )

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    arguments = parser.parse_args()
    return arguments

def get_manufacturer(device):
    """
    Get the manufacturer of the device from Netbox
    """

    print(f"[INFO] Get Manufacturer from Netbox for device {device} ...")

    netbox_url = "https://netbox.global.cloud.sap"
    netbox_params = {'q': device, 'exclude': 'config_context'}
    netbox_devices_url = f"{netbox_url}/api/dcim/devices/"

    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.get(
            netbox_devices_url,
            headers=headers,
            params=netbox_params,
            timeout=10
        )

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {str(e)}")

    results = response.json().get('results')
    if results:
        netbox_manufacturer = results[0]['device_type']['manufacturer']['name']
        print(f"[INFO] Manufacturer: {netbox_manufacturer}")
        return netbox_manufacturer

    print("[ERROR] No manufacturer received from Netbox!")
    sys.exit(1)

def restart_remote_board(host, username, password, force, manufacturer, timeout):
    """
    Restart the remote board using Redfish API
    """

    # Set the authentication headers for Redfish
    auth = HTTPBasicAuth(username, password)
    headers = {'Content-Type': 'application/json'}

    # Dell iDRAC does not support ForceRestart Value
    if force and manufacturer != "Dell":
        reset_payload = {
            "ResetType": "ForceRestart"
        }
    else:
        reset_payload = {
            "ResetType": "GracefulRestart"
        }

    expected_status_codes = [200, 202, 204]

    if manufacturer == "HPE" or manufacturer == "Lenovo":
        # Set the Redfish URL for resetting the iLO
        redfish_url = f"https://{host}/redfish/v1/Managers/1/Actions/Manager.Reset"

    elif manufacturer == "Dell":

        # Redfish URL to restart the iDRAC
        redfish_url = f'https://{host}/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset'
        # JSON payload for the reset action

    elif manufacturer == "Cisco":
        redfish_url = f"https://{host}/redfish/v1/Managers/CIMC/Actions/Manager.Reset"

    else:
        print(f"[ERROR] Unknown manufacturer: {manufacturer}!")
        sys.exit(1)

    print("[INFO] Sending restart request ...")
    try:
        response = requests.post(
            redfish_url,
            json = reset_payload,
            auth = auth,
            headers=headers,
            timeout=timeout,
            verify=False
        )
        response.raise_for_status()

    except requests.exceptions.Timeout:
        print(
            "[WARN] The restart request timed out, but the reset might still have been successful."
        )
        sys.exit()

    except requests.exceptions.HTTPError as err:
        print(f"[ERROR] An HTTP error occurred: {err}")
        sys.exit(1)

    except requests.exceptions.RequestException as err:
        print(f"[ERROR] An error occurred: {err}")
        sys.exit(1)

    # Check if the request was successful
    if response and response.status_code in expected_status_codes:
        print(f"[INFO] Remote Board restart initiated successfully: {response.status_code}")
    else:
        print(f"[ERROR] Failed to reset Remote Board: {response.status_code}")
        print(response.text)


##############################################################################
if __name__ == '__main__':

    args = get_args()

    # Set the iLO IP address, username and password
    target = args.target

    print(f"[INFO] Restarting Remote Board with IP {target}")

    ip_re = re.compile(
        r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
        r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    )

    NODE_NAME_RE = r"^(node\d{2,3})r-(\w{2}\d{3})\.cc.(\w{2}-\w{2}-\d)\.cloud\.sap$"

    if re.match(ip_re, target):
        try:
            target_host_name = socket.gethostbyaddr(target)[0]
        except socket.herror:
            print(f"[ERROR] Reverse DNS lookup failed for {target}")
            sys.exit(1)

    elif re.match(NODE_NAME_RE, target):
        target_host_name = target

    else:
        print(f"[ERROR] Unknown target format {target}")
        sys.exit(1)

    if target_host_name:
        if re.match(NODE_NAME_RE, target_host_name):
            matches = re.match(NODE_NAME_RE, target_host_name).groups()
            netbox_device = matches[0] + "-" + matches[1]
            target = target_host_name
        else:
            print(f"[ERROR] Unknown hostname format {target_host_name}")
            sys.exit(1)

        print(f"[INFO] Resolved to hostname {target_host_name}")
    else:
        print(f"[ERROR] No valid IP provided: {target}!")
        sys.exit(1)

    target_manufacturer = get_manufacturer(netbox_device)

    restart_remote_board(
        target,
        args.username,
        args.password,
        args.force,
        target_manufacturer,
        args.timeout
    )
