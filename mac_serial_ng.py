import logging
import sys
import os
import requests
import urllib3
from natsort import natsorted
from typing import Optional, Tuple

urllib3.disable_warnings()

class InventoryContext:
    def __init__(self, NETBOX_ENVIRONMENT, configuration, special_netbox_case):

        self.url_netbox_device_q = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/dcim/devices/?q="
        self.url_netbox_ip_device = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/ipam/ip-addresses/?device="
        self.url_netbox_device = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/dcim/devices/"
        self.url_netbox_device_interface = f"https://netbox.{NETBOX_ENVIRONMENT}.cloud.sap/api/dcim/interfaces/"

        self.args_user_name = os.getenv("REDFISH_USERNAME", configuration.get('redfish_username'))
        self.args_password = os.getenv("REDFISH_PASSWORD", configuration.get('redfish_password'))

        self.args_write_flag = os.getenv("WRITE", str(configuration.get("write", False))).lower() == "true"
        self.args_force_flag = os.getenv("FORCE", str(configuration.get("force", False))).lower() == "true"
        self.args_iponly_flag = os.getenv("IPONLY", str(configuration.get("iponly", False))).lower() == "true"
        self.args_mtu = int(os.getenv("MTU", configuration.get("mtu", 9000)))
        self.special_netbox_case = special_netbox_case

        if self.args_force_flag:
            self.args_write_flag = True

        try:
            self.api_netbox_key = os.environ["NETBOX_API_TOKEN"]
        except KeyError:
            print("No NETBOX_API_TOKEN environment variable set, please set one and try again")
            quit(1)

        self.nic_port_mapping_matrix = {
            "Integrated NIC 1 Port 1 Partition 1": "L1",
            "Integrated NIC 1 Port 2 Partition 1": "L2",
            "Integrated NIC 1 Port 3 Partition 1": "L3",
            "Integrated NIC 1 Port 4 Partition 1": "L4",
            "Embedded NIC 1 Port 1 Partition 1": "L1",
            "Embedded NIC 1 Port 2 Partition 1": "L2",
            "Embedded NIC 1 Port 3 Partition 1": "L3",
            "Embedded NIC 1 Port 4 Partition 1": "L4",
            "NIC in Slot 1 Port 1 Partition 1": "PCI1-P1",
            "NIC in Slot 1 Port 2 Partition 1": "PCI1-P2",
            "NIC in Slot 2 Port 1 Partition 1": "PCI2-P1",
            "NIC in Slot 2 Port 2 Partition 1": "PCI2-P2",
            "NIC in Slot 3 Port 1 Partition 1": "PCI3-P1",
            "NIC in Slot 3 Port 2 Partition 1": "PCI3-P2",
            "NIC in Slot 4 Port 1 Partition 1": "PCI4-P1",
            "NIC in Slot 4 Port 2 Partition 1": "PCI4-P2",
            "NIC in Slot 5 Port 1 Partition 1": "PCI5-P1",
            "NIC in Slot 5 Port 2 Partition 1": "PCI5-P2",
            "NIC in Slot 6 Port 1 Partition 1": "PCI6-P1",
            "NIC in Slot 6 Port 2 Partition 1": "PCI6-P2",
            "NIC in Slot 7 Port 1 Partition 1": "PCI7-P1",
            "NIC in Slot 7 Port 2 Partition 1": "PCI7-P2",
            "NIC in Slot 8 Port 1 Partition 1": "PCI8-P1",
            "NIC in Slot 8 Port 2 Partition 1": "PCI8-P2",
            "NIC in Slot 9 Port 1 Partition 1": "PCI9-P1",
            "NIC in Slot 9 Port 2 Partition 1": "PCI9-P2",
            "NIC in Slot 32 Port 1 Partition 1": "PCI32-P1",
            "NIC in Slot 32 Port 2 Partition 1": "PCI32-P2",
            "NIC in Slot 34 Port 1 Partition 1": "PCI34-P1",
            "NIC in Slot 34 Port 2 Partition 1": "PCI34-P2",
            "Intel_slot-1_1.1": "L1",
            "Intel_slot-1_2.1": "L2",
            "Intel_slot-1_3.1": "L3",
            "Intel_slot-1_4.1": "L4",
            "Intel_slot-2_1.1": "L1",
            "Intel_slot-2_2.1": "L2",
            "Intel_slot-2_3.1": "L3",
            "Intel_slot-2_4.1": "L4",
            "Intel_slot-3_1.1": "L1",
            "Intel_slot-3_2.1": "L2",
            "Intel_slot-3_3.1": "L3",
            "Intel_slot-3_4.1": "L4",
            "Intel_slot-4_1.1": "L1",
            "Intel_slot-4_2.1": "L2",
            "Intel_slot-4_3.1": "L3",
            "Intel_slot-4_4.1": "L4",
            "Intel_slot-5_1.1": "L1",
            "Intel_slot-5_2.1": "L2",
            "Intel_slot-5_3.1": "L3",
            "Intel_slot-5_4.1": "L4",
            "Intel_slot-6_1.1": "L1",
            "Intel_slot-6_2.1": "L2",
            "Intel_slot-6_3.1": "L3",
            "Intel_slot-6_4.1": "L4",
            "Intel_slot-7_1.1": "L1",
            "Intel_slot-7_2.1": "L2",
            "Intel_slot-7_3.1": "L3",
            "Intel_slot-7_4.1": "L4",
            "Intel_slot-8_1.1": "L1",
            "Intel_slot-8_2.1": "L2",
            "Intel_slot-8_3.1": "L3",
            "Intel_slot-8_4.1": "L4",
            "Intel_slot-9_1.1": "L1",
            "Intel_slot-9_2.1": "L2",
            "Intel_slot-9_3.1": "L3",
            "Intel_slot-9_4.1": "L4",
            "Intel_slot-10_1.1": "L1",
            "Intel_slot-10_2.1": "L2",
            "Intel_slot-10_3.1": "L3",
            "Intel_slot-10_4.1": "L4",
            "Intel_slot-13_1.1": "L1",
            "Intel_slot-13.2.1": "L2",
            "Intel_slot-13_3.1": "L3",
            "Intel_slot-13_4.1": "L4",
            "Mellanox_slot-1_1.1": "PCI1-P1",
            "Mellanox_slot-1_2.1": "PCI1-P2",
            "Mellanox_slot-2_1.1": "PCI2-P1",
            "Mellanox_slot-2_2.1": "PCI2-P2",
            "Mellanox_slot-3_1.1": "PCI3-P1",
            "Mellanox_slot-3_2.1": "PCI3-P2",
            "Mellanox_slot-4_1.1": "PCI4-P1",
            "Mellanox_slot-4_2.1": "PCI4-P2",
            "Mellanox_slot-5_1.1": "PCI5-P1",
            "Mellanox_slot-5_2.1": "PCI5-P2",
            "Mellanox_slot-6_1.1": "PCI6-P1",
            "Mellanox_slot-6_2.1": "PCI6-P2",
            "Mellanox_slot-7_1.1": "PCI7-P1",
            "Mellanox_slot-7_2.1": "PCI7-P2",
            "Mellanox_slot-13_1.1": "PCI13-P1",
            "Mellanox_slot-13_2.1": "PCI13-P2",
            "Broadcom_slot-1_1.1": "PCI1-P1",
            "Broadcom_slot-1_2.1": "PCI1-P2",
            "Broadcom_slot-2_1.1": "PCI2-P1",
            "Broadcom_slot-2_2.1": "PCI2-P2",
            "Broadcom_slot-3_1.1": "PCI3-P1",
            "Broadcom_slot-3_2.1": "PCI3-P2",
            "Broadcom_slot-4_1.1": "PCI4-P1",
            "Broadcom_slot-4_2.1": "PCI4-P2",
            "Broadcom_slot-5_1.1": "PCI5-P1",
            "Broadcom_slot-5_2.1": "PCI5-P2",
            "Broadcom_slot-6_1.1": "PCI6-P1",
            "Broadcom_slot-6_2.1": "PCI6-P2",
            "Broadcom_slot-7_1.1": "PCI7-P1",
            "Broadcom_slot-7_2.1": "PCI7-P2",
            "Broadcom_slot-8_1.1": "PCI8-P1",
            "Broadcom_slot-8_2.1": "PCI8-P2",
            "Broadcom_slot-13_1.1": "PCI13-P1",
            "Broadcom_slot-13_2.1": "PCI13-P2",
            "Broadcom_slot-15_1.1": "PCI15-P1",
            "Broadcom_slot-15_2.1": "PCI15-P2",
            "Broadcom_slot-18_1.1": "PCI18-P1",
            "Broadcom_slot-18_2.1": "PCI18-P2",
            "NIC.FlexLOM.1.1_1": "L1",
            "NIC.FlexLOM.1.1_2": "L2",
            "NIC.FlexLOM.1.1_3": "L3",
            "NIC.FlexLOM.1.1_4": "L4",
            "NIC.Slot.1.1_1": "PCI1-P1",
            "NIC.Slot.1.1_2": "PCI1-P2",
            "NIC.Slot.2.1_1": "PCI2-P1",
            "NIC.Slot.2.1_2": "PCI2-P2",
            "NIC.Slot.3.1_1": "PCI3-P1",
            "NIC.Slot.3.1_2": "PCI3-P2",
            "NIC.Slot.4.1_1": "PCI4-P1",
            "NIC.Slot.4.1_2": "PCI4-P2",
            "NIC.Slot.5.1_1": "PCI5-P1",
            "NIC.Slot.5.1_2": "PCI5-P2",
            "NIC.Slot.6.1_1": "PCI6-P1",
            "NIC.Slot.6.1_2": "PCI6-P2",
            "AOC_1_1": "PCI1-P1",
            "AOC_1_2": "PCI1-P2",
            "AOC_2_1": "PCI2-P1",
            "AOC_2_2": "PCI2-P2",
            "AOC_3_1": "PCI3-P1",
            "AOC_3_2": "PCI3-P2",
            "AOC_4_1": "PCI4-P1",
            "AOC_4_2": "PCI4-P2",
            "AOC_5_1": "PCI5-P1",
            "AOC_5_2": "PCI5-P2",
            "OnBoard_1": "L1",
            "OnBoard_2": "L2",
            "OnBoard_3": "L3",
            "OnBoard_4": "L4"
        }
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
        url = f"https://{bmc_address}/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()

        for entry in myjson_members_data:
            nic = entry["@odata.id"]
            nic_url = f"https://{bmc_address}{nic}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            if nicdata.get("MACAddress"):
                nic_list.append(nicdata.get("Description"))
                nic_list.append(self.nic_port_mapping(nicdata.get("Description")))
                nic_list.append(nicdata["MACAddress"])

            nic_request.close()
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def server_redfish_get_system_info(self, server_name_bmc, server_name_short, session_x_auth_token, hw_vendor):
        url = f"https://{server_name_bmc}/redfish/v1/Systems/{self.redfish_get_info_mapping.get(hw_vendor)}"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myrequest.close()
        memory_gib = myjsondata["MemorySummary"]["TotalSystemMemoryGiB"]   
        memory_gb = round(memory_gib * 1.073741824)    # 1 GiB = 1.073741824 GB
        vendor = myjsondata["Manufacturer"]
        model = myjsondata["Model"]
        serial = myjsondata["SKU"]
        health = myjsondata["Status"]["Health"]
        self.netbox_server_dict[server_name_short].update({"manufacturer": vendor, "model": model, "memory_gb": memory_gb, "serial_redfish": serial, "system_health": health})


    def lenovo_redfish_get_network_interfaces(self, bmc_address, server_name_short, session_x_auth_token):
        nic_list = []
        url = f"https://{bmc_address}/redfish/v1/Chassis/1/NetworkAdapters/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjson_members_data = myrequest.json()["Members"]
        myrequest.close()

        for nic_entry in myjson_members_data:
            nic_url = f"https://{bmc_address}{nic_entry['@odata.id']}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            nic_request.close()

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
                    nic2_url = f"https://{bmc_address}{func['@odata.id']}"
                    if use_token:
                        nic2_request = requests.get(nic2_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
                    else:
                        nic2_request = requests.get(nic2_url, auth=(self.args_user_name, self.args_password), verify=False)
                    
                    nic2data = nic2_request.json()
                    nic2_request.close()

                    custom_field = f"{prefix}_{nicdata['Id']}_{nic2data['Id']}"
                    mac = nic2data.get("Ethernet", {}).get("MACAddress")
                    if mac:
                        nic_list.append(custom_field)
                        nic_list.append(self.nic_port_mapping(custom_field))
                        nic_list.append(mac)

        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def hpe_redfish_get_network_interfaces(self,bmc_address, server_name_short, session_x_auth_token):
        nic_list = list()
        url = f"https://{bmc_address}/redfish/v1/Systems/1/BaseNetworkAdapters/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        adapters_data = myjsondata["Members"]
        myrequest.close()
        for adapter_entry in adapters_data:
            adapter_url = f"https://{bmc_address}{adapter_entry['@odata.id']}"
            adapter_response = requests.get(adapter_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            adapter_data = adapter_response.json()
            adapter_response.close()

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
        url = f"https://{bmc_address}/redfish/v1/Systems/1/PCIDevices/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nic_url = f"https://{bmc_address}{nic}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            nic_request.close()
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

                url2 = f"https://{bmc_address}/redfish/v1/Chassis/1/NetworkAdapters/{nic_device_resource_id}{nic_device_endpoint_url}"
                myrequest2 = requests.get(url2, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
                myjsondata2 = myrequest2.json()
                myjson_members_data2 = myjsondata2["Members"]
                myrequest2.close()
                for nic_entry in myjson_members_data2:
                    nic2 = nic_entry["@odata.id"]
                    nic2_url = f"https://{bmc_address}{nic2}"
                    nic2_request = requests.get(nic2_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
                    nic2data = nic2_request.json()
                    nic2_request.close()
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
        url = f"https://{bmc_address}/redfish/v1/Managers/1/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myrequest.close()
        return myjsondata["Model"]


    def supermicro_redfish_get_network_interfaces(self, bmc_address, server_name_short, session_x_auth_token):
        nic_list = list()
        url = f"https://{bmc_address}/redfish/v1/Chassis/1/NetworkAdapters/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for adapter in myjson_members_data:
            nic_url = f"https://{bmc_address}{adapter['@odata.id']}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            if "Supermicro" in nicdata["Manufacturer"]:
                controllers = nicdata["Controllers"]
                for controller in controllers:
                    functions = controller["Links"]["NetworkDeviceFunctions"]
                    for function in functions:
                        nic2_url = f"https://{bmc_address}{function['@odata.id']}"
                        nic2_request = requests.get(nic2_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
                        nic2data = nic2_request.json()
                        custom_field = f"AOC_{controllers[0]['Location']['PartLocation']['LocationOrdinalValue']}_{nic2data['Id']}"
                        if nic2data["Ethernet"]["MACAddress"] != "":
                            nic_list.append(custom_field)
                            nic_list.append(self.nic_port_mapping(custom_field))
                            nic_list.append(nic2data["Ethernet"]["MACAddress"])
                            custom_field = ""
                        nic2_request.close()
            nic_request.close()
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})
        url = f"https://{bmc_address}/redfish/v1/Systems/1/EthernetInterfaces"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for interface in myjson_members_data:
            nic_url = f"https://{bmc_address}{interface['@odata.id']}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            if "OnBoard" in nicdata["Name"]:
                custom_field = f"OnBoard_{nicdata['Id']}"
                if nicdata["MACAddress"] != "":
                    nic_list.append(custom_field)
                    nic_list.append(self.nic_port_mapping(custom_field))
                    nic_list.append(nicdata["MACAddress"])
                    custom_field = ""
            nic_request.close()
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def netbox_get_info(self, pod):
        global server_manufacturer
        url = f"{self.url_netbox_device_q}{pod}"
        myrequest = requests.get(url)
        myjson = myrequest.json()
        myrequest.close()
        myworkingdata = myjson["results"]
        for entry in myworkingdata:
            if entry["device_type"]["manufacturer"]["name"] in self.vendor_list:
                self.netbox_server_dict[entry["name"]] = {"device_id": entry["id"], "servername": entry["name"], "serial": entry["serial"]}
                server_manufacturer = entry["device_type"]["manufacturer"]["name"]

        for device_name_entry in self.netbox_server_dict:
            url = f"{self.url_netbox_ip_device}{device_name_entry}"
            myrequest = requests.get(url)
            myjson = myrequest.json()
            myrequest.close()
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

        if server_manufacturer == "":
            return None

        return server_manufacturer


    def get_ip(self, input):
        return input[:-3]


    def get_remoteboard_mac(self, server_manufactorer, bmc_address):
        url = f"https://{bmc_address}{self.remoteboard_uri_key_mapping.get(server_manufactorer).get('uri')}"
        my_request = requests.get(url, auth=(self.args_user_name, self.args_password), verify=False)
        my_json = my_request.json()
        my_request.close()
        return my_json[(self.remoteboard_uri_key_mapping.get(server_manufactorer).get("mac_key_name"))]


    def nic_port_mapping(self, port_description):
        return self.nic_port_mapping_matrix.get(port_description, "Error, mapping failed")


    def netbox_nic_description_mapping(self, my_input):
        return self.netbox_network_interface_description_mapping.get(my_input, "Error, Netbox NIC description mapping")


    def netbox_nic_description_mapping_short(self, my_input):
        return self.netbox_network_interface_description_mapping_short.get(my_input, "Error, Netbox NIC description mapping")


    def netbox_write_serial_number(self, device_id, serial_number):
        head = {"Authorization": "Token {}".format(self.api_netbox_key), "Content-Type": "application/json", "Accept": "application/json"}
        url = f"{self.url_netbox_device}{device_id}/"
        payload = {"serial": serial_number}
        try:
            result = requests.patch(url, json=payload, headers=head)
            result.close()
        except Exception as e:
            print(f"Error writing {url}{payload}: {e}")
        return


    def netbox_get_interface_mac(self, device_id):
        url = f"{self.url_netbox_device_interface}?device_id={device_id}"
        myrequest = requests.get(url)
        data = myrequest.json()
        myrequest.close()
        interfaces = data["results"]
        netbox_nic_interfaces_dict_helper = {}

        for interface in interfaces:
            node_name = interface["device"]["name"]
            if interface["connected_endpoints"] is not None:
                interface_id = (interface["id"])
                result = {"device": device_id, "name": interface["name"], "mac_address": interface["mac_address"], "mtu": interface["mtu"], "description": interface["name"]}
                netbox_nic_interfaces_dict_helper[interface_id] = result
                self.netbox_nic_interfaces_dict.update({node_name: netbox_nic_interfaces_dict_helper})
        return


    def netbox_write_interface_mac_and_mtu(self, device_interface_id, payload, mac, mtu_size=None):
        head = {"Authorization": "Token {}".format(self.api_netbox_key), "Content-Type": "application/json", "Accept": "application/json"}
        url = f"{self.url_netbox_device_interface}{device_interface_id}/"
        payload.update({"mac_address": mac, "mtu": mtu_size})
        try:
            result = requests.patch(url, json=payload, headers=head)
            result.close()
        except Exception as e:
            print(f"Error writing MAC {url} - {payload}: {e}")
        return


    def generic_get_infos(self, vendor: str):
        for server in self.netbox_server_dict:
            try:
                print(f"\rGetting Infos from Netbox for \t{server}", end="")

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

                print(f"\rCollecting Redfish Infos from \t{server}", end="")

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

            except Exception as e:
                print("\tError", e)


    def runSerialNumberScript(self, query):
        print("Getting infos from Netbox / All vPod nodes")
        print("")
        server_manufacturer = self.netbox_get_info(query)
        self.generic_get_infos(server_manufacturer)

        print("")
        print("")
        for item in self.netbox_server_dict:
            isNICNot4Port = False
            try:
                self.my_new_template_nic_list.clear()
                device_id = None
                serial_number = None
                mac_address = None
                device_id = self.netbox_server_dict[item]["device_id"]
                serial_number = self.netbox_server_dict[item]["serial_redfish"]
                # noinspection SyntaxError
                if self.args_write_flag:
                    if self.netbox_server_dict[item]["serial"] != serial_number:
                        print(f"Netbox serial number NOT MATCHING.\t{self.netbox_server_dict[item]['servername']}\t{self.netbox_server_dict[item]['serial']} != {serial_number}")
                        if self.netbox_server_dict[item]["serial"] == "":
                            self.netbox_write_serial_number(device_id, serial_number)
                            print(f"Netbox serial number empty. Writing serial number to Netbox. {item}")
                        if self.args_force_flag:
                            self.netbox_write_serial_number(device_id, serial_number)
                            print(f"Mismatch serial number in Netbox. Changing in Netbox. {item}")
                    else:
                        print(device_id, self.netbox_server_dict[item]["serial"], serial_number)
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
                    mylist.append(self.get_remoteboard_mac(server_manufacturer, self.netbox_server_dict[item]["remoteboard"]))

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

                        if self.args_write_flag:
                            payload_data = self.netbox_nic_interfaces_dict[item][inner_dict_key]
                            interface_id = inner_dict_key
                            if payload_data["mac_address"] != mac_address:
                                print(f"Netbox MAC-Address NOT MATCHING.\t{self.netbox_server_dict[item]['servername']}\t{payload_data['name']}\t{payload_data['mac_address']} != {mac_address}")
                                if payload_data["mac_address"] is None:
                                    if payload_data["name"] == "L1":
                                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                        print("No MAC-Address in Netbox. Writing MAC to Netbox {}".format(item))
                                    elif payload_data["name"] == "L2":
                                        if self.special_netbox_case:
                                            self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                            print("No MAC-Address in Netbox. Writing MAC to Netbox {}".format(item))
                                        else:
                                            pass
                                    elif payload_data["name"] == "remoteboard":
                                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                    else:
                                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 9000)
                                        print(f"No MAC-Address in Netbox. Writing MAC to Netbox {item}")
                                        if isNICNot4Port:
                                            print("")
                                            print("No 4 Port NIC!!!!")
                                            print("")
                                            isNICNot4Port = False
                            if self.args_force_flag:
                                if payload_data["name"] == "L1":
                                    self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                elif payload_data["name"] == "L2":
                                    if self.special_netbox_case:
                                        self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                    else:
                                        pass
                                elif payload_data["name"] == "remoteboard":
                                    self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                else:
                                    self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 9000)
    #                            print("Mismatch MAC in Netbox. Changing in Netbox {}".format(item))
                        else:
                            pass
            except Exception:
                pass
            self.netbox_nic_interfaces_dict.clear()
        print("Done")
