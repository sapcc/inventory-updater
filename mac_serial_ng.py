import logging
import sys
import os
import re
import requests
import urllib3
from natsort import natsorted
from typing import Optional, Tuple, Dict, Any

urllib3.disable_warnings()

class InventoryContext:
    def __init__(self, NETBOX_ENVIRONMENT, configuration, special_netbox_case):
        self.configuration = configuration

        self.url_netbox_device_q = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/dcim/devices/?q="
        self.url_netbox_ip_device = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/ipam/ip-addresses/?device="
        self.url_netbox_device = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/dcim/devices/"
        self.url_netbox_device_interface = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/dcim/interfaces/"

        self.args_user_name = self._get_config("redfish_username")
        self.args_password = self._get_config("redfish_password")

        if not self.args_user_name:
            logging.error("No REDFISH_USERNAME found in environment or config file")
            sys.exit(1)
        if not self.args_password:
            logging.error("No REDFISH_PASSWORD found in environment or config file")
            sys.exit(1)

        self.args_write_flag = self._get_config_bool("write", False)
        self.args_force_flag = self._get_config_bool("force", False)
        self.args_iponly_flag = self._get_config_bool("iponly", False)
        self.args_mtu = int(os.getenv("MTU", str(configuration.get("mtu", 9000))))
        self.special_netbox_case = special_netbox_case

        if self.args_force_flag:
            self.args_write_flag = True

        self.api_netbox_key = os.getenv(
            "NETBOX_TOKEN",
            configuration.get('netbox', {}).get('token')
        )
        if not self.api_netbox_key:
            logging.error("No NETBOX_TOKEN found in environment or config file")
            sys.exit(1)

        self.server_rib_matrix = ["XCC", "iDRAC", "iLO", "remoteboard"]
        self.netbox_network_interface_mapping = ["NIC1-port1", "NIC1-port2", "NIC2-port1", "NIC2-port2", "NIC3-port1", "NIC3-port2", "NIC4-port1", "NIC4-port2"]
        self.netbox_network_interface_description_mapping = {
            "NIC1-port1": 0,
            "NIC1-port2": 1,
            "NIC2-port1": 2,
            "NIC2-port2": 3,
            "NIC3-port1": 4,
            "NIC3-port2": 5,
            "NIC4-port1": 6,
            "NIC4-port2": 7
        }
        self.netbox_network_interface_description_mapping_short = {
            "NIC1-port1": 0,
            "NIC1-port2": 1,
        }
        self.remoteboard_uri_key_mapping = {"Dell": {"uri": "/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces/NIC.1", "mac_key_name": "PermanentMACAddress"},
                                    "Lenovo": {"uri": "/redfish/v1/Managers/1/EthernetInterfaces/ToHost", "mac_key_name": "MACAddress"},
                                    "HPE": {"uri": "/redfish/v1/Managers/1/EthernetInterfaces/1", "mac_key_name": "MACAddress"},
                                    "Supermicro": {"uri": "/redfish/v1/Managers/1/EthernetInterfaces/1", "mac_key_name": "MACAddress"}
                                    }

        self.redfish_get_info_mapping = {"Dell": "System.Embedded.1", "Lenovo": "1", "HPE": "1", "Supermicro": "1"}

        self.done_counter = 0
        self.error_counter = 0
        self.result_counter = 0
        self.netbox_server_dict = {}
        self.netbox_nic_interfaces_dict = {}
        self.nic_interfaces_summary_list = []
        self.my_new_template_nic_list = []
        self.my_new_template_nic_list_sorted = []
        self.mac_list = []
        self.vendor_list = ["Dell", "Lenovo", "HPE", "Supermicro"]
        self.server_manufacturer = ""
        self.custom_field = ""
        self.isNICNot4Port = False
        self.hpe_ilo_version_matrix = {"iLO 5": self.hpe_redfish_get_network_interfaces, "iLO 6": self.hpe_redfish_get_network_interfaces_ilo6}
        self.manufacturer_interface = {"Dell": self.dell_redfish_get_network_interfaces, "Lenovo": self.lenovo_redfish_get_network_interfaces, "Supermicro": self.supermicro_redfish_get_network_interfaces}

    def _get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get configuration value from environment variable or config file"""
        return os.getenv(key.upper(), self.configuration.get(key.lower(), default))

    def _get_config_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean configuration value from environment variable or config file"""
        value = os.getenv(key.upper(), str(self.configuration.get(key.lower(), default)))
        return value.lower() == "true"

    def _redfish_url(self, path: str, system_id: str = "1") -> str:
        """
        Build Redfish URL paths with common base patterns.

        Args:
            path: The endpoint type ('systems', 'chassis', 'managers')
            system_id: The system/chassis/manager ID (default: "1")

        Returns:
            Full Redfish path
        """
        base_paths = {
            'systems': f"/redfish/v1/Systems/{system_id}",
            'chassis': f"/redfish/v1/Chassis/{system_id}",
            'managers': f"/redfish/v1/Managers/{system_id}",
        }
        return base_paths.get(path.lower(), f"/redfish/v1/{path}")

    def _redfish_get(self, bmc_address: str, path: str, session_token: str) -> Dict[str, Any]:
        """Single method for all Redfish GET calls"""
        url = f"https://{bmc_address}{path}"
        response = requests.get(url, headers={"X-Auth-Token": session_token}, verify=False)
        response.raise_for_status()
        return response.json()

    def _netbox_patch(self, url: str, payload: Dict[str, Any]) -> None:
        """Single method for all Netbox PATCH operations"""
        headers = {
            "Authorization": f"Token {self.api_netbox_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        logging.info("  Writing to Netbox %s", url)
        try:
            result = requests.patch(url, json=payload, headers=headers)
            result.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logging.error("  HTTP error writing to %s (status %s): %s",
                         url, e.response.status_code if e.response else 'unknown', type(e).__name__)
        except requests.exceptions.RequestException as e:
            logging.error("  Network error writing to %s: %s", url, type(e).__name__)

    def session_get_redfish_link(self, bmc_address: str, username: str, password: str) -> str:
        """
        Redfish /v1 path should be accessible without authentication.
        Return session service link.
        """
        url = f"https://{bmc_address}/redfish/v1/"
        resp = requests.get(url, verify=False)
        if resp.status_code == 200:
            return "/redfish/v1/SessionService/Sessions"
        # fallback with authentication if needed
        resp = requests.get(url, auth=(username, password), verify=False)
        resp.raise_for_status()
        return "/redfish/v1/SessionService/Sessions"

    def session_create_x_auth_token(self, server_rib: str, username: str, password: str, session_uri: str) -> Tuple[str, Optional[str]]:
        url = f"https://{server_rib}{session_uri}"
        payload = {"UserName": username, "Password": password}
        headers = {'content-type': 'application/json'}
        response = requests.post(url, json=payload, headers=headers, verify=False)
        if response.headers.get("x-auth-token") is None:
            logging.error("Not able to create token")
            sys.exit(1)
        data = response.json()
        my_session_id = data["Id"]
        my_session_token = response.headers.get("x-auth-token")
        return my_session_id, my_session_token


    def session_delete_x_auth_session(self, server_rib: str, session_x_auth_token: str, session_uri: str, session_id: str):
        url = f"https://{server_rib}{session_uri}/{session_id}"
        requests.delete(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)


    def dell_redfish_get_network_interfaces(self, bmc_address, server_name_short, session_x_auth_token):
        nic_list = list()
        myjsondata = self._redfish_get(bmc_address, "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/", session_x_auth_token)
        myjson_members_data = myjsondata["Members"]

        for entry in myjson_members_data:
            nic = entry["@odata.id"]
            nicdata = self._redfish_get(bmc_address, nic, session_x_auth_token)
            if nicdata.get("MACAddress"):
                nic_list.append(nicdata.get("Description"))
                nic_list.append(self.nic_port_mapping(nicdata.get("Description")))
                nic_list.append(nicdata["MACAddress"])

        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def server_redfish_get_system_info(self, server_name_bmc, server_name_short, session_x_auth_token, hw_vendor):
        system_id = self.redfish_get_info_mapping.get(hw_vendor)
        myjsondata = self._redfish_get(server_name_bmc, f"{self._redfish_url('systems', system_id)}", session_x_auth_token)
        memory_gib = myjsondata["MemorySummary"]["TotalSystemMemoryGiB"]
        memory_gb = round(memory_gib * 1.073741824)    # 1 GiB = 1.073741824 GB
        vendor = myjsondata["Manufacturer"]
        model = myjsondata["Model"]
        serial = myjsondata["SKU"]
        health = myjsondata["Status"]["Health"]
        self.netbox_server_dict[server_name_short].update({"manufacturer": vendor, "model": model, "memory_gb": memory_gb, "serial_redfish": serial, "system_health": health})


    def lenovo_redfish_get_network_interfaces(self, bmc_address, server_name_short, session_x_auth_token):
        nic_list = []
        myjson_members_data = self._redfish_get(bmc_address, f"{self._redfish_url('chassis')}/NetworkAdapters/", session_x_auth_token)["Members"]

        for nic_entry in myjson_members_data:
            nicdata = self._redfish_get(bmc_address, nic_entry['@odata.id'], session_x_auth_token)

            manufacturer = nicdata.get("Manufacturer", "")
            name = nicdata.get("Name", "")

            if "Mellanox" in manufacturer:
                prefix = "Mellanox"
                use_token = True
            elif "Broadcom" in manufacturer and "RJ45" not in name:
                prefix = "Broadcom"
                use_token = False
            elif "Intel" in manufacturer or "RJ45" in name:
                prefix = "Intel"
                use_token = False
            else:
                continue  # Skip NICs that don't match these rules

            for controller in nicdata.get("Controllers", []):
                for func in controller["Links"].get("NetworkDeviceFunctions", []):
                    if use_token:
                        nic2data = self._redfish_get(bmc_address, func['@odata.id'], session_x_auth_token)
                    else:
                        nic2_url = f"https://{bmc_address}{func['@odata.id']}"
                        nic2_request = requests.get(nic2_url, auth=(self.args_user_name, self.args_password), verify=False)
                        nic2data = nic2_request.json()

                    custom_field = f"{prefix}_{nicdata['Id']}_{nic2data['Id']}"
                    mac = nic2data.get("Ethernet", {}).get("MACAddress")
                    if mac:
                        nic_list.append(custom_field)
                        nic_list.append(self.nic_port_mapping(custom_field))
                        nic_list.append(mac)

        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def hpe_redfish_get_network_interfaces(self,bmc_address, server_name_short, session_x_auth_token):
        nic_list = list()
        myjsondata = self._redfish_get(bmc_address, f"{self._redfish_url('systems')}/BaseNetworkAdapters/", session_x_auth_token)
        adapters_data = myjsondata["Members"]
        for adapter_entry in adapters_data:
            adapter_data = self._redfish_get(bmc_address, adapter_entry['@odata.id'], session_x_auth_token)

            adapter_name = adapter_data.get("Name", "")
            structured_name = adapter_data.get("StructuredName", "")
            physical_ports = adapter_data.get("PhysicalPorts", [])

            if ("Connect" in adapter_name or "Eth 100G" in adapter_name or "FlexLOM" in structured_name):
                custom_field = structured_name + "_"
                for port in physical_ports:
                    mac = port.get("MacAddress")
                    if mac:
                        self.mac_list.append(mac)

                self.mac_list.sort()

                for mac_item in self.mac_list:
                    suffix = str(self.mac_list.index(mac_item) + 1)
                    nic_list.append(custom_field + suffix)
                    nic_list.append(self.nic_port_mapping(custom_field + suffix))
                    nic_list.append(mac_item)

                self.mac_list.clear()

        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def hpe_redfish_get_network_interfaces_ilo6(self, bmc_address, server_name_short, session_x_auth_token):
        nic_list = list()
        myjsondata = self._redfish_get(bmc_address, f"{self._redfish_url('systems')}/PCIDevices/", session_x_auth_token)
        myjson_members_data = myjsondata["Members"]
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nicdata = self._redfish_get(bmc_address, nic, session_x_auth_token)
            if "NIC" in nicdata["DeviceType"] or "LOM" in nicdata["DeviceType"]:
                if "Connect" in nicdata["Name"] or "Mellanox" in nicdata["Name"] or "Broadcom" in nicdata["Name"]:
                    nic_device_resource_id = nicdata["DeviceResourceId"]
                    nic_device_endpoint_url = "/Ports/"
                    custom_field = nicdata["StructuredName"] + "_"
                else:
                    if "DeviceResourceId" not in nicdata:
                        nic_device_resource_id = "DA000000"
                    else:
                        nic_device_resource_id = nicdata["DeviceResourceId"]
                    nic_device_endpoint_url = "/Ports/"
                    custom_field = "NIC.FlexLOM.1.1" + "_"

                myjsondata2 = self._redfish_get(bmc_address, f"{self._redfish_url('chassis')}/NetworkAdapters/{nic_device_resource_id}{nic_device_endpoint_url}", session_x_auth_token)
                myjson_members_data2 = myjsondata2["Members"]
                for nic_entry in myjson_members_data2:
                    nic2 = nic_entry["@odata.id"]
                    nic2data = self._redfish_get(bmc_address, nic2, session_x_auth_token)
                    if "Network" in nic_device_endpoint_url:
                        for entry in nic2data["AssociatedNetworkAddresses"]:
                            self.mac_list.append(entry)
                    else:
                        for entry in nic2data["Ethernet"]["AssociatedMACAddresses"]:
                            self.mac_list.append(entry)

                self.mac_list.sort()
                for mac_item in self.mac_list:
                    suffix = str((self.mac_list.index(mac_item) + 1))
                    nic_list.append(custom_field + suffix)
                    nic_list.append(self.nic_port_mapping(custom_field + suffix))
                    nic_list.append(mac_item)


                custom_field = ""
                self.mac_list.clear()
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def hpe_get_ilo_version(self, bmc_address, session_x_auth_token):
        myjsondata = self._redfish_get(bmc_address, f"{self._redfish_url('managers')}/", session_x_auth_token)
        return myjsondata["Model"]


    def supermicro_redfish_get_network_interfaces(self, bmc_address, server_name_short, session_x_auth_token):
        nic_list = list()
        myjsondata = self._redfish_get(bmc_address, f"{self._redfish_url('chassis')}/NetworkAdapters/", session_x_auth_token)
        myjson_members_data = myjsondata["Members"]
        for adapter in myjson_members_data:
            nicdata = self._redfish_get(bmc_address, adapter['@odata.id'], session_x_auth_token)
            if "Supermicro" in nicdata["Manufacturer"]:
                controllers = nicdata["Controllers"]
                for controller in controllers:
                    functions = controller["Links"]["NetworkDeviceFunctions"]
                    for function in functions:
                        nic2data = self._redfish_get(bmc_address, function['@odata.id'], session_x_auth_token)
                        custom_field = f"AOC_{controllers[0]['Location']['PartLocation']['LocationOrdinalValue']}_{nic2data['Id']}"
                        if nic2data["Ethernet"]["MACAddress"] != "":
                            nic_list.append(custom_field)
                            nic_list.append(self.nic_port_mapping(custom_field))
                            nic_list.append(nic2data["Ethernet"]["MACAddress"])
                            custom_field = ""
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})
        myjsondata = self._redfish_get(bmc_address, f"{self._redfish_url('systems')}/EthernetInterfaces", session_x_auth_token)
        myjson_members_data = myjsondata["Members"]
        for interface in myjson_members_data:
            nicdata = self._redfish_get(bmc_address, interface['@odata.id'], session_x_auth_token)
            if "OnBoard" in nicdata["Name"]:
                custom_field = f"OnBoard_{nicdata['Id']}"
                if nicdata["MACAddress"] != "":
                    nic_list.append(custom_field)
                    nic_list.append(self.nic_port_mapping(custom_field))
                    nic_list.append(nicdata["MACAddress"])
                    custom_field = ""
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def netbox_get_info(self, server_name):
        url = f"{self.url_netbox_device_q}{server_name}"
        with requests.Session() as session:
            myjson = session.get(url).json()
            myworkingdata = myjson["results"]
            for entry in myworkingdata:
                if entry["device_type"]["manufacturer"]["name"] in self.vendor_list:
                    self.netbox_server_dict[entry["name"]] = {"device_id": entry["id"], "servername": entry["name"], "serial": entry["serial"]}
                    self.server_manufacturer = entry["device_type"]["manufacturer"]["name"]

            for device_name_entry in self.netbox_server_dict:
                url = f"{self.url_netbox_ip_device}{device_name_entry}"
                myjson = session.get(url).json()
                myworkingdata = myjson["results"]
                for ip_entry in myworkingdata:
                    assigned_obj = ip_entry["assigned_object"]
                    name = assigned_obj["name"]
                    if name in self.server_rib_matrix:
                        device_name = assigned_obj["device"]["name"]
                        self.netbox_server_dict[device_name].update({
                            "remoteboard": ip_entry["description"],
                            "remoteboard_ip": self.get_ip(ip_entry["address"])
                        })

        if not self.server_manufacturer:
            return None

        return self.server_manufacturer


    def get_ip(self, input):
        return input[:-3]


    def get_remoteboard_mac(self, server_manufactorer, bmc_address):
        url = f"https://{bmc_address}{self.remoteboard_uri_key_mapping.get(server_manufactorer).get('uri')}"
        with requests.Session() as session:
            my_json = session.get(url, auth=(self.args_user_name, self.args_password), verify=False).json()
        return my_json[(self.remoteboard_uri_key_mapping.get(server_manufactorer).get("mac_key_name"))]


    def nic_port_mapping(self, port_description: str) -> str:
        """
        Dynamically parse NIC port descriptions into standardized format.
        """
        # Pattern 1: "Integrated/Embedded NIC 1 Port X Partition 1" → "LX"
        match = re.match(r"(?:Integrated|Embedded) NIC 1 Port (\d+) Partition 1", port_description)
        if match:
            return f"L{match.group(1)}"

        # Pattern 2: "NIC in Slot X Port Y Partition 1" → "PCIX-PY"
        match = re.match(r"NIC in Slot (\d+) Port (\d+) Partition 1", port_description)
        if match:
            return f"PCI{match.group(1)}-P{match.group(2)}"

        # Pattern 3: "Intel_slot-X_Y.1" → "LY"
        match = re.match(r"Intel_slot-\d+_(\d+)\.1", port_description)
        if match:
            return f"L{match.group(1)}"

        # Pattern 4: "Mellanox_slot-X_Y.1" or "Broadcom_slot-X_Y.1" → "PCIX-PY"
        match = re.match(r"(?:Mellanox|Broadcom)_slot-(\d+)_(\d+)\.1", port_description)
        if match:
            return f"PCI{match.group(1)}-P{match.group(2)}"

        # Pattern 5: "NIC.FlexLOM.1.1_X" → "LX"
        match = re.match(r"NIC\.FlexLOM\.1\.1_(\d+)", port_description)
        if match:
            return f"L{match.group(1)}"

        # Pattern 6: "NIC.Slot.X.1_Y" → "PCIX-PY"
        match = re.match(r"NIC\.Slot\.(\d+)\.1_(\d+)", port_description)
        if match:
            return f"PCI{match.group(1)}-P{match.group(2)}"

        # Pattern 7: "AOC_X_Y" → "PCIX-PY"
        match = re.match(r"AOC_(\d+)_(\d+)", port_description)
        if match:
            return f"PCI{match.group(1)}-P{match.group(2)}"

        # Pattern 8: "OnBoard_X" → "LX"
        match = re.match(r"OnBoard_(\d+)", port_description)
        if match:
            return f"L{match.group(1)}"

        # Fallback: return error message
        return f"Error, mapping failed for: {port_description}"


    def netbox_nic_description_mapping(self, my_input):
        return self.netbox_network_interface_description_mapping.get(my_input, "Error, Netbox NIC description mapping")


    def netbox_nic_description_mapping_short(self, my_input):
        return self.netbox_network_interface_description_mapping_short.get(my_input, "Error, Netbox NIC description mapping")


    def netbox_write_serial_number(self, device_id, serial_number):
        url = f"{self.url_netbox_device}{device_id}/"
        payload = {"serial": serial_number}
        self._netbox_patch(url, payload)


    def netbox_get_interface_mac(self, device_id):
        url = f"{self.url_netbox_device_interface}?device_id={device_id}"
        with requests.Session() as session:
            data = session.get(url).json()
            interfaces = data["results"]
            netbox_nic_interfaces_dict_helper = {}

            for interface in interfaces:
                node_name = interface["device"]["name"]
                if interface["connected_endpoints"] is not None:
                    interface_id = (interface["id"])
                    result = {"device": device_id, "name": interface["name"], "mac_address": interface["mac_address"], "mtu": interface["mtu"], "description": interface["name"]}
                    netbox_nic_interfaces_dict_helper[interface_id] = result
                    self.netbox_nic_interfaces_dict.update({node_name: netbox_nic_interfaces_dict_helper})


    def netbox_write_interface_mac_and_mtu(self, device_interface_id, payload, mac, mtu_size=None):
        url = f"{self.url_netbox_device_interface}{device_interface_id}/"
        payload.update({"mac_address": mac, "mtu": mtu_size})
        self._netbox_patch(url, payload)


    def generic_get_infos(self, vendor: str):
        for server in self.netbox_server_dict:
            try:
                logging.info("  %s: Getting Infos from Netbox", server)

                board_address = (
                    self.netbox_server_dict[server]["remoteboard_ip"]
                    if self.args_iponly_flag
                    else self.netbox_server_dict[server]["remoteboard"]
                )

                # Auth + Redfish session setup
                session_uri = self.session_get_redfish_link(board_address, self.args_user_name, self.args_password)
                session_id, session_x_auth_token = self.session_create_x_auth_token(board_address, self.args_user_name, self.args_password, session_uri)

                # Get system info
                self.server_redfish_get_system_info(board_address, server, session_x_auth_token, vendor)

                logging.info("  %s: Collecting Redfish Infos", server)

                # Vendor-specific network interface logic
                if vendor == "HPE":
                    ilo_version = self.hpe_get_ilo_version(board_address, session_x_auth_token)
                    network_fn = self.hpe_ilo_version_matrix.get(ilo_version)
                else:
                    network_fn = self.manufacturer_interface.get(vendor)

                if network_fn:
                    network_fn(board_address, server, session_x_auth_token)

                # Cleanup session
                self.session_delete_x_auth_session(board_address, session_x_auth_token, session_uri, session_id)

            except (requests.exceptions.RequestException, ConnectionError) as e:
                logging.error("  Network error processing server %s: %s", server, type(e).__name__)
            except (KeyError, ValueError, TypeError) as e:
                logging.error("  Data error processing server %s: %s", server, e)
            except Exception as e:
                logging.error("  Unexpected error processing server %s: %s - %s",
                             server, type(e).__name__, str(e))


    def runSerialNumberScript(self, server):
        logging.info("==> Server %s: Getting Serial# and MAC-Addresses", server)
        
        # cut off the FQDN from the server variable
        short_server_name = server.split('.')[0]

        self.netbox_get_info(short_server_name)
        self.generic_get_infos(self.server_manufacturer)

        for item in self.netbox_server_dict:
            isNICNot4Port = False
            try:
                self.my_new_template_nic_list.clear()
                device_id = None
                serial_number = None
                mac_address = None
                device_id = self.netbox_server_dict[item]["device_id"]
                serial_number = self.netbox_server_dict[item]["serial_redfish"]

                if  not self.args_write_flag:
                    logging.info("  Dry-Run mode - No changes will be made to Netbox")
                    continue

                if self.netbox_server_dict[item]["serial"] != serial_number:
                    logging.warning("  %s: Netbox serial number NOT MATCHING", self.netbox_server_dict[item]["servername"])
                    if self.netbox_server_dict[item]["serial"] == "":
                        self.netbox_write_serial_number(device_id, serial_number)
                        logging.info("  %s: Netbox serial number empty. Writing serial number to Netbox.", self.netbox_server_dict[item]["servername"])
                    if self.args_force_flag:
                        self.netbox_write_serial_number(device_id, serial_number)
                        logging.info("  %s: Mismatch serial number in Netbox. Changing in Netbox.", self.netbox_server_dict[item]["servername"])
                else:
                    logging.info("  %s: Netbox serial number matching", self.netbox_server_dict[item]["servername"])

                mylist = self.netbox_server_dict[item]["nics"]
                self.netbox_get_interface_mac(self.netbox_server_dict[item]["device_id"])
                for inner_loop in self.netbox_nic_interfaces_dict[item]:
                    if "NIC" in self.netbox_nic_interfaces_dict[item][inner_loop]["name"]:
                        for myitem in mylist:
                            if "PCI" in myitem:
                                self.my_new_template_nic_list.append(myitem)
                        my_new_template_nic_list_sorted = natsorted(self.my_new_template_nic_list)
                        my_new_template_nic_list_counter = 0

                        if len(my_new_template_nic_list_sorted) < 4:            # > 4 means a list with all 4 ports, in the new case we only have 2 entries in the list
                            my_new_template_nic_list_counter_increase = 1       # add 2 otherwise the list will map wrong port, valid for 2 entries
                            isNICNot4Port = True
                        else:
                            my_new_template_nic_list_counter_increase = 1       # add 1 if all four ports exists, valid for 2 port nic's

                        for nic_item in my_new_template_nic_list_sorted:
                            my_new_template_nic_index = (mylist.index(nic_item))
                            mylist[my_new_template_nic_index] = self.netbox_network_interface_mapping[my_new_template_nic_list_counter]
                            my_new_template_nic_list_counter += my_new_template_nic_list_counter_increase
                        break

                mylist.append("remoteboard")
                mylist.append(self.get_remoteboard_mac(self.server_manufacturer, self.netbox_server_dict[item]["remoteboard"]))

                for inner_dict_key in self.netbox_nic_interfaces_dict[item]:

                    if self.netbox_nic_interfaces_dict[item][inner_dict_key]["name"] not in mylist:
                        break

                    mylist_index = (mylist.index(self.netbox_nic_interfaces_dict[item][inner_dict_key]["name"]))
                    mac_address = str.upper(mylist[mylist_index + 1])

                    if "NIC" in self.netbox_nic_interfaces_dict[item][inner_dict_key]["description"]:

                        if len(my_new_template_nic_list_sorted) < 4: # same convention 2 / 4 Ports, needs to be mapped different. WTF
                            self.netbox_nic_interfaces_dict[item][inner_dict_key]["description"] = my_new_template_nic_list_sorted[
                                self.netbox_nic_description_mapping_short(self.netbox_nic_interfaces_dict[item][inner_dict_key]["description"])]
                            isNICNot4Port = True
                        else:
                            self.netbox_nic_interfaces_dict[item][inner_dict_key]["description"] = my_new_template_nic_list_sorted[
                                self.netbox_nic_description_mapping(self.netbox_nic_interfaces_dict[item][inner_dict_key]["description"])]

                    if not self.args_write_flag:
                        logging.info("  Dry-Run mode - No changes will be made to Netbox")
                        continue

                    payload_data = self.netbox_nic_interfaces_dict[item][inner_dict_key]
                    interface_id = inner_dict_key
                    if payload_data["mac_address"] != mac_address:
                        logging.warning("  Netbox MAC-Address mismatch for server=%s interface=%s", self.netbox_server_dict[item]['servername'], payload_data['name'])
                        if payload_data["mac_address"] is None:
                            if payload_data["name"] == "L1":
                                self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                logging.info("  No MAC-Address in Netbox. Writing MAC to Netbox %s", item)
                            elif payload_data["name"] == "L2" and self.special_netbox_case:
                                self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                logging.info("  No MAC-Address in Netbox. Writing MAC to Netbox %s", item)
                            elif payload_data["name"] == "remoteboard":
                                self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                            else:
                                self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 9000)
                                logging.info("  No MAC-Address in Netbox. Writing MAC to Netbox %s", item)
                                if isNICNot4Port:
                                    logging.info("  No 4 Port NIC!!!!")
                                    isNICNot4Port = False

                    if not self.args_force_flag:
                        continue

                    if payload_data["name"] == "L1":
                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                    elif payload_data["name"] == "L2" and self.special_netbox_case:
                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                    elif payload_data["name"] == "remoteboard":
                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                    else:
                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 9000)

            except (requests.exceptions.RequestException, ConnectionError) as e:
                logging.error("  Network error processing server %s NIC interfaces: %s", item, type(e).__name__)
            except (KeyError, ValueError, TypeError, IndexError) as e:
                logging.error("  Data error processing server %s NIC interfaces: %s", item, e)
            except Exception as e:
                logging.error("  Unexpected error processing server %s: %s - %s",
                             item, type(e).__name__, str(e))
            finally:
                self.netbox_nic_interfaces_dict.clear()
        return