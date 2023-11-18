import requests
import logging
import os
import re
import json

class NetboxConnection(object):
    def __init__(self, config):
        self.netbox_url = os.getenv("NETBOX_URL", config['netbox']['url'])
        self._netbox_token = os.getenv("NETBOX_TOKEN", config['netbox']['token'])
        self.netbox_query = os.getenv("NETBOX_QUERY", config['netbox']['query'])

        self.netbox_inventory_items_url = f"{self.netbox_url}/api/dcim/inventory-items/"
        self.netbox_devices_url = f"{self.netbox_url}/api/dcim/devices/"
        self.netbox_manufacturers_url = f"{self.netbox_url}/api/dcim/manufacturers/"
        self.netbox_regions_url = f"{self.netbox_url}/api/dcim/regions/"
        self.region = os.getenv("REGION", config['region'])

        logging.info(f"Establishing connection to Netbox {self.netbox_url}")
        self._headers = {'Content-type': 'application/json', "Authorization": f"Token {self._netbox_token}"}
        self._session = requests.session()

    def send_request(self, url, method, params=None, data=None):

        req = requests.Request(method=method, url=url, headers=self._headers, params=params, data=data)
        prepped = self._session.prepare_request(req)

        try:
            response = self._session.send(prepped, verify=False)
            response.raise_for_status()
        
        except requests.exceptions.HTTPError as err:
            logging.error(f"  Netbox : {err}: {response.content}")
            logging.debug(f"    Params: {params}")
            logging.debug(f"    Data: {data}")
            logging.debug(f"    Response: {response.content}")

        if method == "GET":
            if response.json():
                return response.json()

    def get_region(self):
        results = []
        url = self.netbox_regions_url
        params = {'q': self.region}
        response = self.send_request(url=url, method='GET', params=params)
        results = response.get('results')
        
        if not results:
            logging.error(f"  Netbox: Region {self.region} not found: {response['detail']}")
            exit(1)

        else:
            return results[0]

    def get_devices(self):
        devices = []
        url = self.netbox_devices_url
        params = {
            'region_id': self.get_region()['id'],
            'exclude': 'config_context'
        }
        params.update(self.netbox_query)

        page = self.send_request(url=url, method='GET', params=params)
        devices = page['results']
        
        while page['next']:
            page = self.send_request(url=page['next'], method='GET', params=params)
            devices.extend(page['results'])

        return devices

class NetboxInventoryUpdater(object):
    def __init__(self, config, device_name, netbox_connection):

        self.device_name = device_name
        self.netbox_connection = netbox_connection

    def _compare_dict(self, dict1, dict2):
        changes = [k for k, v in dict1.items() if dict2.get(k) != v ]
        res = [dict2.get(k) == v for k, v in dict1.items()]
        same = all(res)
        return same

    def get_manufacturer_id(self, manufacturer):
        results = []
        url = self.netbox_connection.netbox_manufacturers_url
        if manufacturer:
            query_manufacturer = manufacturer.split(" ")[0].replace("(R)","").lower()
            params = {'q': query_manufacturer}
            results = self.netbox_connection.send_request(url=url, method='GET', params=params)['results']
            
            if len(results) == 0:
                logging.warn(f"  Netbox {self.device_name}: No manufacturer found with {query_manufacturer} in the name! You should consider creating '{manufacturer}'.")

            elif len(results) > 1:
                logging.error(f"  Netbox {self.device_name}: More than one manufacturer found with name {query_manufacturer}!")

            else:
                return results[0]['id']

        device = self.get_device()
        server_manufacturer = device['device_type']['manufacturer']['id']
        return server_manufacturer

    def get_device(self):
        url = self.netbox_connection.netbox_devices_url
        params = {
            'name': self.device_name,
            'exclude': 'config_context'
        }
        results = self.netbox_connection.send_request(url=url, method='GET', params=params)['results']

        if len(results) == 0:
            logging.error(f"  Netbox {self.device_name}: No such device found!")
            return
        
        elif len(results) > 1:
            logging.error(f"  Netbox {self.device_name}: More than one device found!")
            return

        else:
            netbox_device = results[0]

        return netbox_device

    def get_device_model(self):
        manufacturer = ""
        model = ""
        netbox_device = self.get_device()
        if netbox_device:
            manufacturer = netbox_device['device_type']['manufacturer']['name']
            model = netbox_device['device_type']['model']
        return manufacturer, model

    def get_device_id(self):
        netbox_device = self.get_device()
        return netbox_device['id']

    def get_device_status(self):
        netbox_device = self.get_device()
        return netbox_device['status']['value']

    def get_device_region(self):
        netbox_device = self.get_device()
        matches = re.match(r'^(\w{2}-\w{2}-\d{1})[a-z]$', netbox_device['site']['slug'])
        return matches[1]

    def get_inventory(self):
        
        url = self.netbox_connection.netbox_inventory_items_url
        params = {'device': self.device_name}
        results = self.netbox_connection.send_request(url=url, method='GET', params=params)['results']
        return results

    def remove_inventory_item(self, item):

        url = item['url']
        logging.info(f"  Netbox {self.device_name}: Deleting item {item['name']}")
        results = self.netbox_connection.send_request(url, 'DELETE')

    def add_inventory_item(self, item):

        url = self.netbox_connection.netbox_inventory_items_url
        results = self.netbox_connection.send_request(url, 'POST', data=item)

    def update_inventory_item(self, item, item_id):

        url = self.netbox_connection.netbox_inventory_items_url + f"{item_id}/"
        results = self.netbox_connection.send_request(url, 'PATCH', data=item)

    def _convert_netbox_inventory(self, item):
        if item:
            converted_item = {
                'manufacturer': item['manufacturer'].get('id') if item['manufacturer'] else "",
                'description': item['description'],
                'name': item['name'],
                'device': item['device']['id'],
                'part_id': item['part_id'],
                'serial': item['serial']
            }
        else:
            converted_item = {}

        return converted_item

    def _check_item_amount(self, server_inventory, netbox_inventory):
        if len(netbox_inventory) > len(server_inventory) and len(netbox_inventory) > 0:
            logging.info(f"  Netbox {self.device_name}: Number of Netbox entries for {netbox_inventory[0]['name']} doesn't match:")
            logging.info(f"  Netbox {self.device_name}: Netbox: {len(netbox_inventory) }")
            logging.info(f"  Netbox {self.device_name}: Server: {len(server_inventory) }")
            logging.info(f"  Netbox {self.device_name}: Removing entries ...")
            for index in range(len(netbox_inventory) - len(server_inventory)):
                self.remove_inventory_item(netbox_inventory[index])
                netbox_inventory.pop(index)
        return netbox_inventory

    def _update_inventory_items(self, netbox_device_id, server_inventory, netbox_inventory):

        counter = 0
        for item in server_inventory:
            current_netbox_item = []
            try:
                current_netbox_item = netbox_inventory[counter] 
            except IndexError:
                pass

            # Dell has the real name in the Model, other have it in the Name
            description = item.get('Description', None)
            if description == None:
                if item.get('Name') in ['Network Adapter View','Adapter']:
                    description = item.get('Model', "")
                else:
                    description = item.get('Name', "")

            new_netbox_item = {
                'manufacturer': self.get_manufacturer_id(item['Manufacturer']),
                'description': description,
                'name': item.get('NetboxName',""),
                'device': netbox_device_id,
                'part_id': item.get('PartNumber', ""),
                'serial': item.get('SerialNumber', "")
            }
            old_netbox_item_json = json.dumps(self._convert_netbox_inventory(current_netbox_item))
            new_netbox_item_json = json.dumps(new_netbox_item).replace("null", '""')

            # no_change = self._compare_dict(new_netbox_item, old_netbox_item)
            # if no_change:
            if new_netbox_item_json == old_netbox_item_json:
                logging.info(f"  Netbox {self.device_name}: No change for {new_netbox_item['name']}")
            else:
                if current_netbox_item:
                    logging.info(f"  Netbox {self.device_name}: Updating item {new_netbox_item['name']}")
                    self.update_inventory_item(new_netbox_item_json, current_netbox_item['id'])
                else:
                    logging.info(f"  Netbox {self.device_name}: Adding item {new_netbox_item['name']}")
                    self.add_inventory_item(new_netbox_item_json)

            counter += 1

    def update_device_inventory(self, server_inventory):

        netbox_device_id = self.get_device_id()
        netbox_inventory = self.get_inventory()

        # Processor
        if server_inventory.get('Processors'):
            server_inventory_processors = server_inventory['Processors']
            netbox_inventory_processors = [item for item in netbox_inventory if re.match('.*CPU.*', item['name'], re.IGNORECASE)]
            netbox_inventory_processors = self._check_item_amount(server_inventory_processors, netbox_inventory_processors)

            self._update_inventory_items(
                netbox_device_id = netbox_device_id, 
                server_inventory = server_inventory_processors,
                netbox_inventory = netbox_inventory_processors
            )

        # Memory
        # We only write one Entry for all DIMMs with the total RAM capacity in the name
        if server_inventory.get('Memory'):
            server_inventory_memory = [server_inventory['Memory'][0]]

            dimm_capacity = round(int(server_inventory_memory[0]['CapacityMiB'])/1024)
            dimm_type = server_inventory_memory[0]['MemoryDeviceType']
            dimm_speed = server_inventory_memory[0]['OperatingSpeedMhz']
            dimm_manufacturer = server_inventory_memory[0]['Manufacturer']
            num_dimms = len(server_inventory['Memory'])

            # Put the description together from several parts of the DIMM information
            server_inventory_memory[0]['Description'] = f"{num_dimms}x {dimm_capacity}GB {dimm_type} {dimm_speed}MT/s {dimm_manufacturer}"
            netbox_inventory_memory = [item for item in netbox_inventory if re.match('.*RAM.*', item['name'], re.IGNORECASE)]
            netbox_inventory_memory = self._check_item_amount(server_inventory_memory, netbox_inventory_memory)

            self._update_inventory_items(
                netbox_device_id = netbox_device_id, 
                server_inventory = server_inventory_memory,
                netbox_inventory = netbox_inventory_memory
            )

        # PCIeDevices

        server_inventory_nics = []
        server_inventory_gpus = []
        pcidevices = server_inventory.get('PCIeDevices', server_inventory.get('PCIDevices'))
        if pcidevices:
            server_inventory_nics = [item for item in pcidevices if re.match("NIC.*", item.get('NetboxName', ""), re.IGNORECASE)]
            server_inventory_gpus = [item for item in pcidevices if re.match("GPU", item.get('NetboxName', ""), re.IGNORECASE) and not re.match("(Embedded|Integrated).*",item['Name'], re.IGNORECASE)]

        if server_inventory.get('NetworkAdapters') and not server_inventory_nics:
            server_inventory_nics = server_inventory['NetworkAdapters']

        # NetworkAdapters
        if server_inventory_nics:
            netbox_inventory_nics = [item for item in netbox_inventory if re.match('.*(NIC|Mellanox|Broadcom|Intel|Pensando).*', item['name'], re.IGNORECASE)]
            netbox_inventory_nics = self._check_item_amount(server_inventory_nics, netbox_inventory_nics)

            self._update_inventory_items(
                netbox_device_id = netbox_device_id, 
                server_inventory = server_inventory_nics,
                netbox_inventory = netbox_inventory_nics
            )

        # GPUs
        if server_inventory_gpus:
            netbox_inventory_gpus = [item for item in netbox_inventory if re.match('.*GPU.*', item['name'], re.IGNORECASE)]
            netbox_inventory_gpus = self._check_item_amount(server_inventory_gpus, netbox_inventory_gpus)

            self._update_inventory_items(
                netbox_device_id = netbox_device_id, 
                server_inventory = server_inventory_gpus,
                netbox_inventory = netbox_inventory_gpus
            )

        # Drives
        if server_inventory.get('Drives'):

            # SSD
            server_inventory_ssd = [item for item in server_inventory['Drives'] if (item['Protocol'] == "SATA" or item['Protocol'] == "SAS") and item['MediaType'] == "SSD"]

            if server_inventory_ssd:
                netbox_inventory_ssd = [item for item in netbox_inventory if re.match('.*(FLASH|SSD).*', item['name'], re.IGNORECASE)]
                netbox_inventory_ssd = self._check_item_amount(server_inventory_ssd, netbox_inventory_ssd)

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id, 
                    server_inventory = server_inventory_ssd,
                    netbox_inventory = netbox_inventory_ssd
                )

            # NVME
            server_inventory_nvme = [item for item in server_inventory['Drives'] if (item['Protocol'] == "PCIe" or item['Protocol'] == "NVMe") and item['MediaType'] == "SSD"]

            if server_inventory_nvme:
                netbox_inventory_nvme = [item for item in netbox_inventory if re.match('.*(NVMe|FLASH).*', item['name'], re.IGNORECASE)]
                netbox_inventory_nvme = self._check_item_amount(server_inventory_nvme, netbox_inventory_nvme)

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id, 
                    #new_netbox_item_name = new_netbox_item_name, 
                    server_inventory = server_inventory_nvme,
                    netbox_inventory = netbox_inventory_nvme
                )

            # HDD
            server_inventory_hdd = [item for item in server_inventory['Drives'] if item['Protocol'] == "SAS" and item['MediaType'] == "HDD"]

            if server_inventory_hdd:
                netbox_inventory_hdd = [item for item in netbox_inventory if re.match('.*(HDD).*', item['name'], re.IGNORECASE)]
                netbox_inventory_hdd = self._check_item_amount(server_inventory_hdd, netbox_inventory_hdd)

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id, 
                    #new_netbox_item_name = new_netbox_item_name, 
                    server_inventory = server_inventory_hdd,
                    netbox_inventory = netbox_inventory_hdd
                )

        # Controllers
        if server_inventory.get('Controllers'):
            
            # only get controllers that actually have disitems attached
            server_inventory_controller = [item for item in server_inventory['Controllers'] if item.get('DrivesAttached')]

            if server_inventory_controller:
                netbox_inventory_controller = [item for item in netbox_inventory if re.match('.*(RAID).*', item['name'], re.IGNORECASE)]
                netbox_inventory_controller = self._check_item_amount(server_inventory_controller, netbox_inventory_controller)

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id, 
                    server_inventory = server_inventory_controller,
                    netbox_inventory = netbox_inventory_controller
                )
