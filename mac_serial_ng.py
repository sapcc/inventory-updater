import logging
import sys
import os
import requests
import urllib3
from natsort import natsorted

urllib3.disable_warnings()

class InventoryContext:
    def __init__(self, url_netbox_device_q, url_netbox_ip_device, url_netbox_device, url_netbox_device_interface, username, password, write, force, iponly, mtu, is_apod):

        self.url_netbox_device_q = url_netbox_device_q
        self.url_netbox_ip_device = url_netbox_ip_device
        self.url_netbox_device = url_netbox_device
        self.url_netbox_device_interface = url_netbox_device_interface

        self.args_user_name = username
        self.args_password = password
        self.args_write_flag = write
        self.args_force_flag = force
        self.args_iponly_flag = iponly
        self.args_mtu = mtu
        self.is_apod = is_apod
        try:
            self.api_netbox_key = os.environ["NETBOX_API_TOKEN"]
        except KeyError:
            print("No NETBOX_API_TOKEN environment variable set, please set one and try again")
            quit(1)

        self.regex_string = r"[0-9]{4,}[a-zA-Z]|[0-9]{4,}"

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
        self.redfish_get_info_mapping = {"Dell": "/redfish/v1/Systems/System.Embedded.1/", "Lenovo": "/redfish/v1/Systems/1/", "HPE": "/redfish/v1/Systems/1/",
                                    "Supermicro": "/redfish/v1/Systems/1/"}
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


    def session_get_redfish_link(self, server_rib: str, username: str, password: str) -> str:
        url = f"https://{server_rib}/redfish/v1/"
        my_response = requests.get(url, auth=(username, password), verify=False)
        data = my_response.json()
        return data["Links"]["Sessions"]["@odata.id"]

    from typing import Optional, Tuple


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


    def dell_redfish_get_network_interfaces(self, server_name_rib, server_name_short, session_x_auth_token):
        nic_list = list()
        url = f"https://{server_name_rib}/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nic_url = f"https://{server_name_rib}{nic}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            if nicdata["MACAddress"] != "":
                nic_list.append(nicdata["Description"])
                nic_list.append(self.nic_port_mapping(nicdata["Description"]))
                if nicdata["MACAddress"] != "":
                    nic_list.append(nicdata["MACAddress"])
                
            nic_request.close()
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def server_redfish_get_system_info(self, server_name_idrac, server_name_short, session_x_auth_token, hw_vendor):
        url = f"https://{server_name_idrac}{self.redfish_get_info_mapping.get(hw_vendor)}"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myrequest.close()
        # print(f"\tSimple Memory check ...{myjsondata["MemorySummary"]["Status"]["Health"]}")
        memory = myjsondata["MemorySummary"]["TotalSystemMemoryGiB"]
        if isinstance(memory, float):
            memory = round(memory * 1.073741824)
        vendor = myjsondata["Manufacturer"]
        model = myjsondata["Model"]
        serial = myjsondata["SKU"]
        health = myjsondata["Status"]["Health"]
        self.netbox_server_dict[server_name_short].update({"manufacturer": vendor, "model": model, "memory": memory, "serial_redfish": serial, "system_health": health})


    def lenovo_redfish_get_network_interfaces(self, server_name_rib, server_name_short, session_x_auth_token):
        nic_list = list()
        url = f"https://{server_name_rib}/redfish/v1/Chassis/1/NetworkAdapters/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nic_url = f"https://{server_name_rib}{nic}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            if "Mellanox" in nicdata["Manufacturer"]:
                mydata = nicdata["Controllers"]
                for item2 in range(0, len(mydata)):
                    ftdata = mydata[item2]["Links"]["NetworkDeviceFunctions"]
                    for item3 in range(0, len(ftdata)):
                        ftdata2 = ftdata[item3]["@odata.id"]
                        nic2_url = f"https://{server_name_rib}{ftdata2}"
                        nic2_request = requests.get(nic2_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
                        nic2data = nic2_request.json()
                        custom_field = "Mellanox_" + nicdata["Id"] + "_" + nic2data["Id"]
                        if nic2data["Ethernet"]["MACAddress"] != "":
                            nic_list.append(custom_field)
                            nic_list.append(self.nic_port_mapping(custom_field))
                            nic_list.append(nic2data["Ethernet"]["MACAddress"])
                            custom_field = ""
                        nic2_request.close()
            if "Broadcom" in nicdata["Manufacturer"] and "RJ45" not in nicdata["Name"]:
                mydata = nicdata["Controllers"]
                for item2 in range(0, len(mydata)):
                    ftdata = mydata[item2]["Links"]["NetworkDeviceFunctions"]
                    for item3 in range(0, len(ftdata)):
                        ftdata2 = ftdata[item3]["@odata.id"]
                        nic2_url = f"https://{server_name_rib}{ftdata2}"
                        nic2_request = requests.get(nic2_url, auth=(self.args_user_name, self.args_password), verify=False)
                        nic2data = nic2_request.json()
                        custom_field = "Broadcom_" + nicdata["Id"] + "_" + nic2data["Id"]
                        if nic2data["Ethernet"]["MACAddress"] != "":
                            nic_list.append(custom_field)
                            nic_list.append(self.nic_port_mapping(custom_field))
                            nic_list.append(nic2data["Ethernet"]["MACAddress"])
                            custom_field = ""
                        nic2_request.close()
            if "Intel" in nicdata["Manufacturer"] or "RJ45" in nicdata["Name"]:
                mydata = nicdata["Controllers"]
                for item2 in range(0, len(mydata)):
                    ftdata = mydata[item2]["Links"]["NetworkDeviceFunctions"]
                    for item3 in range(0, len(ftdata)):
                        ftdata2 = ftdata[item3]["@odata.id"]
                        nic2_url = f"https://{server_name_rib}{ftdata2}"
                        nic2_request = requests.get(nic2_url, auth=(self.args_user_name, self.args_password), verify=False)
                        nic2data = nic2_request.json()
                        custom_field = "Intel_" + nicdata["Id"] + "_" + nic2data["Id"]
                        if nic2data["Ethernet"]["MACAddress"] != "":
                            nic_list.append(custom_field)
                            nic_list.append(self.nic_port_mapping(custom_field))
                            nic_list.append(nic2data["Ethernet"]["MACAddress"])
                            custom_field = ""
                        nic2_request.close()
            nic_request.close()
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def hpe_redfish_get_network_interfaces(self,server_name_rib, server_name_short, session_x_auth_token):
        nic_list = list()
        url = f"https://{server_name_rib}/redfish/v1/Systems/1/BaseNetworkAdapters/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nic_url = f"https://{server_name_rib}{nic}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            nic_request.close()
            if "Connect" in nicdata["Name"] or "Eth 100G" in nicdata["Name"]:
                mydata = nicdata["PhysicalPorts"]
                for item2 in range(0, len(mydata)):
                    custom_field = nicdata["StructuredName"] + "_"
                    self.mac_list.append(mydata[item2]["MacAddress"])

                self.mac_list.sort()
                for mac_item in self.mac_list:
                    suffix = str((self.mac_list.index(mac_item) + 1))
                    nic_list.append(custom_field + suffix)
                    nic_list.append(self.nic_port_mapping(custom_field + suffix))
                    nic_list.append(mac_item)

                custom_field = ""
                self.mac_list.clear()

            if "FlexLOM" in nicdata["StructuredName"]:
                mydata = nicdata["PhysicalPorts"]
                for item2 in range(0, len(mydata)):
                    custom_field = nicdata["StructuredName"] + "_"
                    self.mac_list.append(mydata[item2]["MacAddress"])

                self.mac_list.sort()
                for mac_item in self.mac_list:
                    suffix = str((self.mac_list.index(mac_item) + 1))
                    nic_list.append(custom_field + suffix)
                    nic_list.append(self.nic_port_mapping(custom_field + suffix))
                    nic_list.append(mac_item)

                custom_field = ""
                self.mac_list.clear()

        self.netbox_server_dict[server_name_short].update({"nics": nic_list})


    def hpe_redfish_get_network_interfaces_ilo6(self, server_name_rib, server_name_short, session_x_auth_token):
        nic_list = list()
        url = f"https://{server_name_rib}/redfish/v1/Systems/1/PCIDevices/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nic_url = f"https://{server_name_rib}{nic}"
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

                url2 = f"https://{server_name_rib}/redfish/v1/Chassis/1/NetworkAdapters/{nic_device_resource_id}{nic_device_endpoint_url}"
                myrequest2 = requests.get(url2, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
                myjsondata2 = myrequest2.json()
                myjson_members_data2 = myjsondata2["Members"]
                myrequest2.close()
                for item2 in range(0, len(myjson_members_data2)):
                    nic2 = myjsondata2["Members"][item2]["@odata.id"]
                    nic2_url = f"https://{server_name_rib}{nic2}"
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


    def hpe_get_ilo_version(self, server_name_rib, session_x_auth_token):
        url = f"https://{server_name_rib}/redfish/v1/Managers/1/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myrequest.close()
        return myjsondata["Model"]


    def supermicro_redfish_get_network_interfaces(self, server_name_rib, server_name_short, session_x_auth_token):
        nic_list = list()
        url = f"https://{server_name_rib}/redfish/v1/Chassis/1/NetworkAdapters/"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        myjson_members_data = myjsondata["Members"]
        myrequest.close()
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nic_url = f"https://{server_name_rib}{nic}"
            nic_request = requests.get(nic_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
            nicdata = nic_request.json()
            if "Supermicro" in nicdata["Manufacturer"]:
                mydata = nicdata["Controllers"]
                for item2 in range(0, len(mydata)):
                    ftdata = mydata[item2]["Links"]["NetworkDeviceFunctions"]
                    for item3 in range(0, len(ftdata)):
                        ftdata2 = ftdata[item3]["@odata.id"]
                        nic2_url = f"https://{server_name_rib}{ftdata2}"
                        nic2_request = requests.get(nic2_url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
                        nic2data = nic2_request.json()
                        custom_field = f"AOC_{mydata[0]['Location']['PartLocation']['LocationOrdinalValue']}_{nic2data['Id']}"
                        if nic2data["Ethernet"]["MACAddress"] != "":
                            nic_list.append(custom_field)
                            nic_list.append(self.nic_port_mapping(custom_field))
                            nic_list.append(nic2data["Ethernet"]["MACAddress"])
                            custom_field = ""
                        nic2_request.close()
            nic_request.close()
        self.netbox_server_dict[server_name_short].update({"nics": nic_list})
        url = f"https://{server_name_rib}/redfish/v1/Systems/1/EthernetInterfaces"
        myrequest = requests.get(url, headers={"X-Auth-Token": session_x_auth_token}, verify=False)
        myjsondata = myrequest.json()
        for item in range(0, len(myjson_members_data)):
            nic = myjsondata["Members"][item]["@odata.id"]
            nic_url = f"https://{server_name_rib}{nic}"
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
        for item in myworkingdata:
            if item["device_type"]["manufacturer"]["name"] in self.vendor_list:
                self.netbox_server_dict[item["name"]] = {"device_id": item["id"], "servername": item["name"], "serial": item["serial"]}
                server_manufacturer = item["device_type"]["manufacturer"]["name"]

        for item in self.netbox_server_dict:
            url = f"{self.url_netbox_ip_device}{item}"
            myrequest = requests.get(url)
            myjson = myrequest.json()
            myrequest.close()
            myworkingdata = myjson["results"]
            for internal_counter in range(0, len(myworkingdata)):
                if myworkingdata[internal_counter]["assigned_object"]["name"] in self.server_rib_matrix:
                    self.netbox_server_dict[myworkingdata[internal_counter]["assigned_object"]["device"]["name"]].update({"remoteboard": myworkingdata[internal_counter]["description"],
                                                                                                                    "remoteboard_ip": self.get_ip(myworkingdata[internal_counter]["address"])})

        if server_manufacturer == "":
            return None

        return server_manufacturer


    def get_ip(self, input):
        return input[:-3]


    def get_remoteboard_mac(self, server_manufactorer, server_name_rib):
        url = f"https://{server_name_rib}{self.remoteboard_uri_key_mapping.get(server_manufactorer).get('uri')}"
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
        myjson = myrequest.json()
        myrequest.close()
        myworkingdata = myjson["results"]
        netbox_nic_interfaces_dict_helper = {}

        for items in myworkingdata:
            node_name = items["device"]["name"]
            if items["connected_endpoints"] is not None:
                interface_id = (items["id"])
                result = {"device": device_id, "name": items["name"], "mac_address": items["mac_address"], "mtu": items["mtu"], "description": items["name"]}
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
                            pass
                        if self.args_force_flag:
                            self.netbox_write_serial_number(device_id, serial_number)
                            print(f"Mismatch serial number in Netbox. Changing in Netbox. {item}")
                    else:
                        print(device_id, self.netbox_server_dict[item]["serial"], serial_number)
                    mylist = self.netbox_server_dict[item]["nics"]
                    self.netbox_get_interface_mac(self.netbox_server_dict[item]["device_id"])
                    print(self.netbox_nic_interfaces_dict)
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

                            for myitem2 in my_new_template_nic_list_sorted:
                                my_new_template_nic_index = (mylist.index(myitem2))
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
                                        if self.is_apod:
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
                                    pass
                            if self.args_force_flag:
                                if payload_data["name"] == "L1":
                                    self.netbox_write_interface_mac_and_mtu(interface_id, payload_data, mac_address, 1500)
                                elif payload_data["name"] == "L2":
                                    if self.is_apod:
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
