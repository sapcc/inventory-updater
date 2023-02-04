# https://sysmgt.lenovofiles.com/help/index.jsp?topic=%2Fcom.lenovo.lxca_restapis.doc%2Frest_apis.html&cp=1_16_3
# There is an API call to just get a sinlge node's inventory. But you need the UUID of the node first.
# To get the UUID you need to get the whole node list including the inventory because there is no possible filter 
import requests
import logging
import os
import time
import sys
import re
import json

class LxcaIventoryCollector(object):
    def __init__(self, config, console, usr, pwd):

        self.console = console

        self._username = usr
        self._password = pwd

        self._timeout = int(os.getenv('TIMEOUT', config['timeout']))
        self._response_time = 0
        self._last_http_code = 0

        self._start_time = time.time()
        
        self._session = ""

        self.nodelist = self.connect('nodes')

        self.close()
   
    def connect(self, command, noauth = False):
        logging.captureWarnings(True)
        
        req = ""
        req_text = ""
        server_response = ""
        self._last_http_code = 0
        request_duration = 0
        request_start = time.time()

        url = f"https://{self.console}/{command}"

        # check if we already established a session with the server
        if not self._session:
            logging.debug(f"Target {self.console}: Establishing session.")
            self._session = requests.Session()
        else:
            logging.debug(f"Target {self.console}: Using existing session.")

        self._session.verify = False
        self._session.headers.update({'charset': 'utf-8'})
        self._session.headers.update({'content-type': 'application/json'})

        self._session.auth = (self._username, self._password)
        logging.debug(f"Target {self.console}: Using basic auth with user {self._username}")
        logging.debug(f"Target {self.console}: Using URL {url}")

        try:
            req = self._session.get(url, timeout = self._timeout)
            req.raise_for_status()

        except requests.exceptions.HTTPError as err:
            self._last_http_code = err.response.status_code
            if err.response.status_code == 401:
                logging.warning(f"Target {self.console}: Authorization Error: {err}")
            else:
                logging.warning(f"Target {self.console}: HTTP Error: {err}")

        except requests.exceptions.ConnectTimeout:
            logging.warning(f"Target {self.console}: Timeout while connecting!")

        except requests.exceptions.ReadTimeout:
            logging.warning(f"Target {self.console}: Timeout while reading data!")

        except requests.exceptions.ConnectionError as err:
            logging.warning(f"Target {self.console}: Unable to connect: {err}")

        except:
            logging.warning(f"Target {self.console}: Unexpected error: {sys.exc_info()[0]}")
            logging.warning(f"Target {self.console}: URL: {url}")

        if req != "":
            self._last_http_code = req.status_code
            try: 
                req_text = req.json()

            except:
                logging.debug(f"Target {self.console}: No json data received.")

            # req will evaluate to True if the status code was between 200 and 400 and False otherwise.
            if req:
                server_response = req_text

            # if the request fails the server might give a hint in the ExtendedInfo field
            else:
                if req_text:
                    logging.debug(f"Target {self.console}: {req_text['error']['code']}: {req_text['error']['message']}")
                    if '@Message.ExtendedInfo' in req_text['error']:
                        if type(req_text['error']['@Message.ExtendedInfo']) == list:
                            if 'Message' in req_text['error']['@Message.ExtendedInfo'][0]:
                                logging.debug(f"Target {self.console}: {req_text['error']['@Message.ExtendedInfo'][0]['Message']}")
                        elif type(req_text['error']['@Message.ExtendedInfo']) == dict:
                            if 'Message' in req_text['error']['@Message.ExtendedInfo']:
                                logging.debug(f"Target {self.console}: {req_text['error']['@Message.ExtendedInfo']['Message']}")
                        else:
                            pass

        request_duration = round(time.time() - request_start,2)
        logging.debug(f"Target {self.console}: Request duration: {request_duration}")
        return server_response


    def get_node(self, target):
        logging.debug(f"Target {target}: Get the Node info ...")
        server_pattern = re.compile(r"^([a-z]+\d{3})r-([a-z]{2,3}\d{3})(\..+)$")
        matches = re.match(server_pattern, target)
        node_name, pod, suffix = matches.groups()
    	
        node_regex = f"{node_name}.*-{pod}.*"
        result = [node for node in self.nodelist['nodeList'] if re.match(node_regex, node['name'], re.IGNORECASE)]
        if result:
            if len(result) > 1:
                logging.warning(f"Target {target}: More than one Node found in LXCA!")
                logging.warning(result)
                return

            logging.info(f"Target {target}: Node found in LXCA with name {result[0]['name']}!")
            return result[0]

        else:
            logging.error(f"Target {target}: No Node found in LXCA matching regex '{node_regex}'!")
            return

    def collect(self, target):
        inventory = {}
        logging.info(f"Target {target}: Collecting data ...")

        result = self.get_node(target)
        if not result:
            return inventory

        inventory.update({"name": target})
        node_info = dict(sorted(result.items()))
        output = json.dumps(node_info, indent=4, sort_keys=True)

        if output and output != "{}":
            filename = f"{target}_lxca.txt"
            output_file = open(filename, 'w')
            print(output, file = output_file)
            output_file.close()

        fields = ('serialNumber', 'manufacturer', 'productName', 'powerStatus')
        for field in fields:
            inventory.update({field: node_info.get(field)})

        if node_info.get('processors'):
            processors = node_info['processors']
            inventory.update({"ProcessorSummary": {
                        "Count": len(processors),
                        "Model": processors[0]['displayName'],
                    }
                })

            processor_info = []
            for processor in processors:
                processor_info.append({
                    "Description": processor['displayName'],
                    "Manufacturer": processor['manufacturer'],
                    "Model": processor['displayName'],
                    "NetboxName": f"CPU {processor['cores']}",
                    "PartNumber": processor['partNumber'],
                    "SerialNumber": processor['serialNumber'],
                    "TotalCores": processor['cores'],
                    "TotalThreads": processor['cores']*2
                })
            
            inventory.update({'Processors': processor_info})

        if node_info.get('pciDevices'):
            pcidevices = node_info['pciDevices']

            pcidevice_info = []
            existing = []
            for device in pcidevices:

                # nics show up multiple times if they have more than one physical port.We should only have one entry in the inventory.
                # Indicator is the PCI slot name
                if device.get('slotName') and device['slotName'] not in existing:
                    existing.append(device['slotName'])

                    device_class = device.get('class')
                    if device_class == 'Network controller':
                        netbox_name = "NIC"
                        if device.get('portInfo'):
                            port_speed = round(device['portInfo']['physicalPorts'][0]['speed'])
                            if port_speed > 0:
                                netbox_name = f"NIC {port_speed}Gb"
                    elif device_class == "DisplayController":
                        netbox_name = "GPU"
                    elif device_class == 'Mass storage controller':
                        netbox_name = "RAID"

                    pcidevice_info.append({
                        "DeviceClass": device_class,
                        "Description": device.get('name'),
                        "Manufacturer": device.get('manufacturer'),
                        "Model": device.get('FRU'),
                        "Name": device.get('productName'),
                        "NetboxName": netbox_name,
                        "PartNumber": device.get('partNumber'),
                        "SerialNumber": device.get('fruSerialNumber'),
                        "PciSlotName":device.get('slotName')
                    })

            inventory.update({'PCIDevices': pcidevice_info})
                
        if node_info.get('memoryModules'):
            dimms = node_info['memoryModules']
            TotalSystemMemoryGiB = len(dimms)*dimms[0]['capacity']
            inventory.update({"MemorySummary": {
                    "TotalSystemMemoryGiB": TotalSystemMemoryGiB
                }
            })

            memory_info = []
            for dimm in dimms:
                memory_info.append({
                    "Description": f"dimm.get('manufacturer']",
                    "Manufacturer": dimm.get('manufacturer'),
                    "Model": dimm.get('model'),
                    "Name": dimm.get('displayName'),
                    "NetboxName": f"RAM {TotalSystemMemoryGiB}GB",
                    "OperatingSpeedMhz": dimm.get('speed'),
                    "MemoryDeviceType": dimm.get('type'),
                    "PartNumber": dimm.get('partNumber'),
                    "SerialNumber": dimm.get('serialNumber'),
                    "CapacityMiB": dimm.get('capacity')
                })

            inventory.update({'Memory': memory_info})

        if node_info.get('raidSettings'):
            raidSettings = node_info['raidSettings']

            drive_info = []
            controller_info = []
            for controller in raidSettings:
                controller_info.append({
                    "DrivesAttached": len(controller['diskDrives']),
                    "Manufacturer": controller.get('manufacturer'),
                    "Description": controller.get('description'),
                    "Model": controller.get('model'),
                    "Name": controller.get('name'),
                    "NetboxName": "RAID",
                    "PartNumber": controller.get('partNumber'),
                    "SerialNumber": controller.get('serialNumber')
                })

                if len(controller['diskDrives']) > 0:
                    for drive in controller['diskDrives']:
                        if (drive['interfaceType'] == "SATA" or drive['interfaceType'] == "SAS") and (drive['mediaType'] == "SSD" or drive['mediaType'] == "HDD"):
                            netbox_name = f"{drive['mediaType']}"
                        elif (drive['interfaceType'] == "PCIe" or drive['interfaceType'] == "NVMe") and drive['mediaType'] == "SSD":
                            netbox_name = "NVMe"
                        else:
                            logging.warning(f"Target {self.console}: Unknown Drive Type! Protocol = {drive['interfaceType']}, MediaType = {drive['mediaType']}")
                            netbox_name = "HDD"
                        
                        netbox_name += f" {round(drive['capacity']/1024/1024/1024)}GB"

                        drive_info.append({
                            "CapacityBytes": drive.get('capacity'),
                            "Manufacturer": drive.get('manufacturer'),
                            "Description": drive.get('description'),
                            "Model": drive.get('model'),
                            "Name": drive.get('name'),
                            "NetboxName": netbox_name,
                            "PartNumber": drive.get('partNumber'),
                            "SerialNumber": drive.get('serialNumber'),
                            "MediaType": drive.get('mediaType'),
                            "Protocol": drive.get('interfaceType')
                        })

            inventory.update({'Drives': drive_info})
            inventory.update({'Controllers': controller_info})

        return inventory


    def close(self):

        if self._session:
            logging.info(f"Target {self.console}: Closing requests session.")
            self._session.close()
