import requests
import logging
import os
import sys
import traceback
import re
import json

class NetboxInventoryUpdater(object):
    def __init__(self, config, device):

        self._netbox_url = os.getenv("NETBOX_URL", config['netbox_url'])
        self._netbox_token = os.getenv("NETBOX_TOKEN", config['netbox_token'])

        self._netbox_inventory_items_url = f"{self._netbox_url}/api/dcim/inventory-items/"
        self._netbox_devices_url = f"{self._netbox_url}/api/dcim/devices/"
        self._netbox_manufacturers_url = f"{self._netbox_url}/api/dcim/manufacturers/"

        self._headers = {'Content-type': 'application/json', "Authorization": f"Token {self._netbox_token}"}
        self._session = requests.session()
        self.device = device

    def _send_request(self, url, method, params=None, data=None):

        req = requests.Request(method=method, url=url, headers=self._headers, params=params, data=data)
        prepped = self._session.prepare_request(req)

        try:
            response = self._session.send(prepped, verify=False)
            response.raise_for_status()
        
        except requests.exceptions.HTTPError as err:
            logging.warning(f"Netbox {self.device}: {err}")
            logging.info(f"Params: {params}")
            logging.info(f"Data: {data}")
            logging.info(f"Response: {response.content}")

        except:
            logging.warning(f"Netbox {self.device}: URL: {url}")
            logging.exception(traceback.format_exc())
            exit(1)

        if method == "GET":
            if response.json():
                return response.json().get('results',response.json())

    def _compare_dict(self, dict1, dict2):
        changes = [k for k, v in dict1.items() if dict2.get(k) != v ]
        res = [dict2.get(k) == v for k, v in dict1.items()]
        same = all(res)
        return same

    def get_manufacturer_id(self, manufacturer):
        url = self._netbox_manufacturers_url
        query_manufacturer = manufacturer.split(" ")[0].replace("(R)","").lower()
        params = {'q': query_manufacturer}
        results = self._send_request(url=url, method='GET', params=params)
        if len(results) == 0:
            logging.warn(f"Netbox {self.device}: No manufacturer found with {query_manufacturer} in the name! You should consider creating '{manufacturer}'.")
            device = self.get_device(self.device)
            server_manufacturer = device[0]['device_type']['manufacturer']['id']
            return server_manufacturer
        elif len(results) > 1:
            logging.error(f"Netbox {self.device}: More than one manufacturer found with name {query_manufacturer}!")
            exit(1)
        else:
            return results[0]['id']

    def get_device(self, device):
        url = self._netbox_devices_url
        params = {'name': device}
        results = self._send_request(url=url, method='GET', params=params)
        return results

    def get_device_id(self, device):
        netbox_devices = self.get_device(device)
        if len(netbox_devices) == 0:
            logging.warning(f"Netbox {device}: No such device found!")
            return
        
        elif len(netbox_devices) > 1:
            logging.warning(f"Netbox {device}: More than one device found!")
            return

        else:
            netbox_device = netbox_devices[0]
        
        return netbox_device['id']


    def get_inventory(self, device):
        
        url = self._netbox_inventory_items_url
        params = {'device': device}
        results = self._send_request(url=url, method='GET', params=params)
        return results

    def remove_inventory_item(self, item):

        url = item['url']
        logging.info(f"Netbox {self.device}: Deleting item {item['name']}")
        results = self._send_request(url, 'DELETE')

    def add_inventory_item(self, item):

        url = self._netbox_inventory_items_url
        results = self._send_request(url, 'POST', data=item)

    def update_inventory_item(self, item, item_id):

        url = self._netbox_inventory_items_url + f"{item_id}/"
        results = self._send_request(url, 'PATCH', data=item)

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
            logging.info(f"Netbox {self.device}: Number of Netbox entries doesn't match. Removing entries ...")
            for index in range(len(netbox_inventory) - len(server_inventory)):
                self.remove_inventory_item(netbox_inventory[index])
                netbox_inventory.pop(index)
        return netbox_inventory

    def _update_inventory(self, new_netbox_item_name, netbox_device_id, server_inventory, netbox_inventory):

        counter = 0
        for item in server_inventory:
            current_netbox_item = []
            try:
                current_netbox_item = netbox_inventory[counter] 
            except IndexError:
                pass

            new_netbox_item = {
                'manufacturer': self.get_manufacturer_id(item['Manufacturer']),
                'description': item.get('Description', item.get('Model', "")),
                'name': new_netbox_item_name,
                'device': netbox_device_id,
                'part_id': item.get('PartNumber', ""),
                'serial': item.get('SerialNumber', "")
            }
            old_netbox_item_json = json.dumps(self._convert_netbox_inventory(current_netbox_item))
            new_netbox_item_json = json.dumps(new_netbox_item).replace("null", '""')

            # no_change = self._compare_dict(new_netbox_item, old_netbox_item)
            # if no_change:
            if new_netbox_item_json == old_netbox_item_json:
                logging.info(f"Netbox {self.device}: No change for {item['Name']}.")
            else:
                if current_netbox_item:
                    logging.info(f"Netbox {self.device}: Updating item {item['Name']}")
                    self.update_inventory_item(new_netbox_item_json, current_netbox_item['id'])
                else:
                    logging.info(f"Netbox {self.device}: Adding item {item['Name']}")
                    self.add_inventory_item(new_netbox_item_json)

            counter += 1
                


    def update_device_inventory(self, server_inventory):

        netbox_device_id = self.get_device_id(self.device)
        netbox_inventory = self.get_inventory(self.device)

        # Processor
        if server_inventory.get('Processors'):
            server_inventory_processor = server_inventory['Processors']
            netbox_inventory_processor = [item for item in netbox_inventory if re.match('.*CPU.*', item['name'])]
            netbox_inventory_processor = self._check_item_amount(server_inventory_processor, netbox_inventory_processor)
            new_netbox_item_name = f"CPU {server_inventory_processor[0]['TotalCores']}C"

            self._update_inventory(
                netbox_device_id = netbox_device_id, 
                new_netbox_item_name = new_netbox_item_name, 
                server_inventory = server_inventory_processor,
                netbox_inventory = netbox_inventory_processor
            )

        # Memory
        # We only write one Entry for all DIMMs with the total RAM capacity in the name
        if server_inventory.get('Memory'):
            server_inventory_memory = [server_inventory['Memory'][0]]
            # Put the description together from several parts of the DIMM information
            server_inventory_memory[0]['Description'] = f"{len(server_inventory['Memory'])}x {round(server_inventory_memory[0]['CapacityMiB']/1024)}GB {server_inventory_memory[0]['MemoryDeviceType']} {server_inventory_memory[0]['OperatingSpeedMhz']}MT/s {server_inventory_memory[0]['Manufacturer']}"
            netbox_inventory_memory = [item for item in netbox_inventory if re.match('.*RAM.*', item['name'])]
            netbox_inventory_memory = self._check_item_amount(server_inventory_memory, netbox_inventory_memory)
            new_netbox_item_name = f"RAM {server_inventory['MemorySummary']['TotalSystemMemoryGiB']}GB"

            self._update_inventory(
                netbox_device_id = netbox_device_id, 
                new_netbox_item_name = new_netbox_item_name, 
                server_inventory = server_inventory_memory,
                netbox_inventory = netbox_inventory_memory
            )

        # NetworkAdapters
        if server_inventory.get('NetworkAdapters'):
            server_inventory_processor = server_inventory['NetworkAdapters']
            netbox_inventory_processor = [item for item in netbox_inventory if re.match('.*(NIC|Mellanox|Broadcom|Intel|Pensando).*', item['name'])]
            netbox_inventory_processor = self._check_item_amount(server_inventory_processor, netbox_inventory_processor)
            new_netbox_item_name = f"NIC"

            self._update_inventory(
                netbox_device_id = netbox_device_id, 
                new_netbox_item_name = new_netbox_item_name, 
                server_inventory = server_inventory_processor,
                netbox_inventory = netbox_inventory_processor
            )
