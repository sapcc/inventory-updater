"""
Module for Netbox API interaction
"""
import logging
import os
import re
import json
import sys
import requests

class NetboxConnectionException(Exception):
    """
    Exception class for the Netbox Connection.
    """

class NetboxConnection:
    """
    Class for Netbox API connection
    """
    def __init__(self, config):
        self.region = os.getenv("REGION", config.get('region'))
        self.netbox_query = os.getenv("NETBOX_QUERY", config.get('netbox', {}).get('query'))

        self.netbox_url = os.getenv("NETBOX_URL", config.get('netbox', {}).get('url'))
        self.netbox_inventory_items_url = f"{self.netbox_url}/api/dcim/inventory-items/"
        self.netbox_devices_url = f"{self.netbox_url}/api/dcim/devices/"
        self.netbox_manufacturers_url = f"{self.netbox_url}/api/dcim/manufacturers/"
        self.netbox_regions_url = f"{self.netbox_url}/api/dcim/regions/"

        logging.info("Establishing connection to Netbox %s", self.netbox_url)
        netbox_token = os.getenv("NETBOX_TOKEN", config.get('netbox', {}).get('token'))

        if not netbox_token:
            logging.error("No NETBOX_TOKEN found in environment or config file")
            sys.exit(1)

        self._headers = {
            'Content-type': 'application/json',
            "Authorization": f"Token {netbox_token}"
        }
        self._session = requests.session()

    def send_request(self, url, method, params=None, data=None):
        """
        Send a request to Netbox API
        """
        req = requests.Request(
            method=method,
            url=url,
            headers=self._headers,
            params=params,
            data=data
        )

        prepped = self._session.prepare_request(req)
        response = None

        try:
            response = self._session.send(prepped, verify=False)
            response.raise_for_status()

        except requests.exceptions.HTTPError as err:
            raise NetboxConnectionException(
                f"Netbox HTTP Error: {err}"
            ) from err

        except requests.exceptions.ConnectionError as err:
            message = f"Netbox Connection Error: {err}"
            if response:
                message = f"Netbox Connection Error. Response : {err}: {response.content}"
            raise NetboxConnectionException(message) from err

        if method == "GET" and response.json():
            result = response.json()
            response.close()
            return result

        response.close()
        return response

    def get_region(self):
        """
        Get a region info from Netbox API
        """
        results = []
        url = self.netbox_regions_url
        params = {'q': self.region}
        response = self.send_request(url=url, method='GET', params=params)
        results = response.get('results')

        if not results:
            logging.error("  Netbox: Region %s not found: %s", self.region, response['detail'])
            sys.exit(1)

        else:
            return results[0]

    def get_devices(self):
        """
        Get all devices of the region from Netbox API
        """
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

class NetboxInventoryUpdater:
    """
    Class for Netbox Inventory interaction
    """
    def __init__(self, device_name, netbox_connection):

        self.device_name = device_name
        self.netbox_connection = netbox_connection

    def get_manufacturer_id(self, manufacturer, item_name=None):
        """
        Get a manufacturer info from Netbox API.

        Strips trademark/registered symbols with a regex, then tries progressively
        broader queries against Netbox's substring-search 'q' parameter:

          1. Full cleaned name  e.g. "Intel Corporation"  → no match
          2. Each individual word in the cleaned name — distinctive words first
             (generic suffixes like "Corporation", "Inc", "Ltd" are tried last):
               "Intel" → match ✓
          3. CamelCase-split tokens of the original name, e.g. "Skhynix" →
             ["Sk", "hynix"] — "hynix" matches "Hynix Semiconductor" ✓
        """
        _GENERIC_SUFFIXES = frozenset({
            'corporation', 'corp', 'incorporated', 'inc', 'limited', 'ltd',
            'company', 'co', 'group', 'holdings', 'international', 'technologies',
            'technology', 'semiconductor', 'systems', 'electronics',
        })
        # Well-known abbreviations that Netbox stores under their full trade name.
        _ALIASES = {
            'mlnx': 'Mellanox',
            'mellanox': 'Mellanox',
        }
        url = self.netbox_connection.netbox_manufacturers_url
        if manufacturer:
            # Strip trademark/registered symbols and normalise whitespace
            clean = re.sub(r'[\(®™]\s*(?:R|TM)\s*\)', '', manufacturer)
            clean = re.sub(r'[®™]', '', clean).strip()

            # Replace known abbreviations before any query logic
            clean = _ALIASES.get(clean.lower(), clean)

            # Build candidate query list, deduplicating while preserving order.
            # CamelCase split: "SKHynix" → ["SK", "Hynix"], "Skhynix" → ["Skhynix"]
            camel_tokens = re.findall(r'[A-Z]{2,}(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]', manufacturer)
            # For single-word tokens that may have a short prefix glued on (e.g. "Skhynix"),
            # also try progressively shorter suffixes so "hynix" is eventually queried.
            suffix_tokens = []
            for word in clean.split():
                if len(word) > 4:
                    for i in range(1, min(4, len(word) - 3)):
                        suffix_tokens.append(word[i:])
            candidates = (
                [clean]
                + sorted(clean.split(), key=lambda w: (w.lower() in _GENERIC_SUFFIXES, -len(w)))
                + camel_tokens
                + suffix_tokens
            )
            seen: set = set()
            unique_candidates = []
            for c in candidates:
                cl = c.lower()
                if cl and cl not in seen:
                    seen.add(cl)
                    unique_candidates.append(c)

            for query in unique_candidates:
                results = self.netbox_connection.send_request(
                    url=url, method='GET',
                    params={'q': query}
                )['results']

                if len(results) == 1:
                    logging.debug(
                        "  Netbox %s: Matched manufacturer '%s' using query '%s'.",
                        self.device_name, manufacturer, query
                    )
                    return results[0]['id']

                if len(results) > 1:
                    logging.error(
                        "  Netbox %s: More than one manufacturer found with query '%s'!",
                        self.device_name, query
                    )
                    return results[0]['id']

            logging.warning(
                "  Netbox %s: No manufacturer found for '%s'%s! "
                "You should consider creating it in Netbox.",
                self.device_name,
                manufacturer,
                f" (item: {item_name})" if item_name else ""
            )

        device = self.get_device()
        server_manufacturer = device['device_type']['manufacturer']['id']
        return server_manufacturer

    def get_device(self):
        """
        Get a device info from Netbox API
        """
        netbox_device = []

        url = self.netbox_connection.netbox_devices_url

        params = {
            'name': self.device_name,
            'exclude': 'config_context'
        }
        results = self.netbox_connection.send_request(
            url=url,
            method='GET',
            params=params
        )['results']

        if len(results) == 0:
            logging.error("  Netbox %s: No such device found!", self.device_name)
            return netbox_device

        if len(results) > 1:
            logging.error("  Netbox %s: More than one device found!", self.device_name)
            return netbox_device

        netbox_device = results[0]

        return netbox_device

    def get_device_model(self):
        """
        Get a device's model from Netbox API
        """
        manufacturer = None
        model = None

        netbox_device = self.get_device()
        if netbox_device:
            manufacturer = netbox_device['device_type']['manufacturer']['name']
            model = netbox_device['device_type']['model']
        return manufacturer, model

    def get_device_id(self):
        """
        Get the device id from Netbox API
        """
        netbox_device = self.get_device()
        return netbox_device['id']

    def get_device_status(self):
        """
        Get the device status from Netbox API
        """
        netbox_device = self.get_device()
        return netbox_device['status']['value']

    def get_device_region(self):
        """
        Get the device region from Netbox API
        """
        netbox_device = self.get_device()
        matches = re.match(r'^(\w{2}-\w{2}-\d{1})[a-z]$', netbox_device['site']['slug'])
        return matches[1]

    def get_inventory(self):
        """
        Get the device's inventory from Netbox API
        """
        url = self.netbox_connection.netbox_inventory_items_url
        params = {'device': self.device_name}
        results = self.netbox_connection.send_request(
            url=url,
            method='GET',
            params=params
        )['results']
        return results

    def remove_inventory_item(self, item):
        """
        Remove an inventory item from a device in Netbox
        """

        url = item['url']
        logging.info("  Netbox %s: Deleting item %s", self.device_name, item['name'])
        self.netbox_connection.send_request(url, 'DELETE')

    def add_inventory_item(self, item):
        """
        Add an inventory item to a device in Netbox
        """

        url = self.netbox_connection.netbox_inventory_items_url
        self.netbox_connection.send_request(url, 'POST', data=item)

    def update_inventory_item(self, item, item_id):
        """
        Update an inventory item of a device in Netbox
        """

        url = self.netbox_connection.netbox_inventory_items_url + f"{item_id}/"
        self.netbox_connection.send_request(url, 'PATCH', data=item)

    def _convert_netbox_inventory(self, item):
        """
        Convert an inventory item to the format we need to write it back to Netbox
        """
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
        """
        Check if the amount of items found matches the amount of inventory items in Netbox
        """
        if len(netbox_inventory) > len(server_inventory) and len(netbox_inventory) > 0:
            logging.info(
                "  Netbox %s: "
                "Number of Netbox entries for %s doesn't match:",
                self.device_name,
                netbox_inventory[0]['name']
            )
            logging.info("  Netbox %s: Netbox: %s", self.device_name, len(netbox_inventory))
            logging.info("  Netbox %s: Server: %s", self.device_name, len(server_inventory))
            logging.info("  Netbox %s: Removing entries ...", self.device_name)
            for index in range(len(netbox_inventory) - len(server_inventory)):
                self.remove_inventory_item(netbox_inventory[index])
                netbox_inventory.pop(index)
        return netbox_inventory

    def _update_inventory_items(self, netbox_device_id, server_inventory, netbox_inventory):
        """
        Update iventory items in Netbox
        """

        counter = 0
        for item in server_inventory:
            current_netbox_item = []
            try:
                current_netbox_item = netbox_inventory[counter]
            except IndexError:
                pass

            # Dell has the real name in the Model, others have it in the Name
            description = item.get('Description', None)
            if description is None:
                if item.get('Name') in ['Network Adapter View','Adapter']:
                    description = item.get('Model', "")
                else:
                    description = item.get('Name', "")

            new_netbox_item = {
                'manufacturer': self.get_manufacturer_id(item['Manufacturer'], item.get('NetboxName')),
                'description': description,
                'name': item.get('NetboxName',""),
                'device': netbox_device_id,
                'part_id': item.get('PartNumber', item.get('Model', "")),
                'serial': item.get('SerialNumber', "")
            }
            old_netbox_item_json = json.dumps(self._convert_netbox_inventory(current_netbox_item))
            new_netbox_item_json = json.dumps(new_netbox_item).replace("null", '""')

            # if no_change:
            if new_netbox_item_json == old_netbox_item_json:
                logging.info(
                    "  Netbox %s: No change for %s",
                    self.device_name,
                    new_netbox_item['name']
                )
            else:
                if current_netbox_item:
                    old = json.loads(old_netbox_item_json)
                    new = json.loads(new_netbox_item_json.replace('""', 'null'))
                    changed_fields = {
                        k: {'old': old.get(k), 'new': new.get(k)}
                        for k in new
                        if str(old.get(k)) != str(new.get(k))
                    }
                    if 'manufacturer' in changed_fields:
                        old_mfr = current_netbox_item.get('manufacturer') or {}
                        changed_fields['manufacturer'] = {
                            'old': old_mfr.get('name', old.get('manufacturer')),
                            'new': item.get('Manufacturer', new.get('manufacturer'))
                        }
                    logging.info(
                        "  Netbox %s: Updating item %s — changed: %s",
                        self.device_name,
                        new_netbox_item['name'],
                        changed_fields
                    )
                    self.update_inventory_item(new_netbox_item_json, current_netbox_item['id'])
                else:
                    logging.info(
                        "  Netbox %s: Adding item %s",
                        self.device_name,
                        new_netbox_item['name']
                    )
                    self.add_inventory_item(new_netbox_item_json)

            counter += 1

    def update_device_inventory_and_mac_serial(self, inventory):
        """
        Unified method to update both inventory items AND MAC/serial data.
        
        Args:
            inventory: Device inventory from redfish_collector
                       (includes 'mac_serial_data' key if available)
        """
        # UPDATE INVENTORY ITEMS (existing functionality)
        self.update_device_inventory(inventory)
        
        # UPDATE MAC/SERIAL IF PROVIDED (new functionality)
        mac_serial_data = inventory.get('mac_serial_data')
        if mac_serial_data:
            try:
                device = self.get_device()
                if not device:
                    logging.warning("  Netbox %s: Could not get device info", self.device_name)
                    return
                
                # Update device serial number
                if mac_serial_data.get('serial'):
                    self._update_device_serial(device, mac_serial_data['serial'])
                
                # Update interface MAC addresses
                if mac_serial_data.get('macs'):
                    self._update_interface_macs(device, mac_serial_data['macs'])
                    
            except Exception as err:
                logging.warning(
                    "  Netbox %s: Failed to update MAC/serial data: %s",
                    self.device_name, err
                )
                # Non-fatal error - don't fail the entire operation

    def _update_device_serial(self, device, serial_number):
        """Update device serial number if it differs from Netbox."""
        # Normalize both serials by stripping whitespace for comparison
        current_serial = str(device.get('serial', '')).strip()
        new_serial = str(serial_number).strip()
        
        if current_serial == new_serial:
            logging.info("  Netbox %s: Serial number already current", self.device_name)
            return
        
        url = f"{self.netbox_connection.netbox_devices_url}{device['id']}/"
        payload = json.dumps({"serial": serial_number})
        
        try:
            self.netbox_connection.send_request(url, 'PATCH', data=payload)
            logging.info(
                "  Netbox %s: Updated serial to %s",
                self.device_name, serial_number
            )
        except Exception as err:
            logging.warning(
                "  Netbox %s: Failed to update serial: %s",
                self.device_name, err
            )

    def _update_interface_macs(self, device, macs_dict):
        """Update MAC addresses for device interfaces."""
        try:
            # Fetch device interfaces
            url = f"{self.netbox_connection.netbox_url}/api/dcim/interfaces/"
            params = {'device_id': device['id']}
            response = self.netbox_connection.send_request(url, 'GET', params=params)
            interfaces = response.get('results', [])
            
            if not interfaces:
                logging.warning("  Netbox %s: No interfaces found", self.device_name)
                return
            
            # Update each interface MAC
            for mac_key, mac_address in macs_dict.items():
                self._update_single_interface_mac(interfaces, mac_key, mac_address)
                
        except Exception as err:
            logging.warning(
                "  Netbox %s: Failed to update interface MACs: %s",
                self.device_name, err
            )

    def _update_single_interface_mac(self, interfaces, interface_name, mac_address):
        """Update a single interface MAC address."""
        for interface in interfaces:
            if interface['name'].lower() == interface_name.lower():
                if interface.get('mac_address') == mac_address.upper():
                    logging.debug(
                        "  Netbox %s: MAC already current for %s",
                        self.device_name, interface_name
                    )
                    return
                
                try:
                    url = f"{self.netbox_connection.netbox_url}/api/dcim/interfaces/{interface['id']}/"
                    payload = json.dumps({"mac_address": mac_address.upper()})
                    
                    self.netbox_connection.send_request(url, 'PATCH', data=payload)
                    logging.info(
                        "  Netbox %s: Updated %s MAC to %s",
                        self.device_name, interface_name, mac_address
                    )
                except Exception as err:
                    logging.warning(
                        "  Netbox %s: Failed to update MAC for %s: %s",
                        self.device_name, interface_name, err
                    )
                return
        
        logging.debug(
            "  Netbox %s: Interface %s not found in Netbox",
            self.device_name, interface_name
        )

    def filter_items(self, inventory_items, filter_string):
        """
        Filter the Netbox inventory items by name
        """

        filtered_items = []
        expression = r'.*(' + filter_string + ').*'
        for item in inventory_items:
            if re.match(expression, item['name'], re.IGNORECASE):
                filtered_items.append(item)

        return filtered_items

    def update_device_inventory(self, server_inventory):
        """
        Go through the list of items we found on the server
        """

        netbox_device_id = self.get_device_id()
        netbox_inventory = self.get_inventory()

        # Processor
        if server_inventory.get('Processors'):
            server_inventory_processors = server_inventory['Processors']
            netbox_inventory_processors = self.filter_items(netbox_inventory, "CPU")
            netbox_inventory_processors = self._check_item_amount(
                server_inventory_processors,
                netbox_inventory_processors
            )

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
            server_inventory_memory[0]['Description'] = (
                f"{num_dimms}x "
                f"{dimm_capacity}GB "
                f"{dimm_type} "
                f"{dimm_speed}MT/s "
                f"{dimm_manufacturer}"
            )
            netbox_inventory_memory = self.filter_items(netbox_inventory, "RAM")
            netbox_inventory_memory = self._check_item_amount(
                server_inventory_memory,
                netbox_inventory_memory
            )

            self._update_inventory_items(
                netbox_device_id = netbox_device_id,
                server_inventory = server_inventory_memory,
                netbox_inventory = netbox_inventory_memory
            )

        # PCIeDevices

        server_inventory_nics = []
        server_inventory_gpus = []

        if server_inventory.get('NetworkAdapters'):
            server_inventory_nics = server_inventory['NetworkAdapters']

        pcidevices = server_inventory.get('PCIeDevices', server_inventory.get('PCIDevices'))
        if pcidevices:

            if not server_inventory_nics:
                # filter the NICs
                for item in pcidevices:
                    if re.match("NIC.*", item.get('NetboxName', ""), re.IGNORECASE):
                        server_inventory_nics.append(item)

            # filter the onboard GPUs
            for item in pcidevices:
                if re.match(
                    "GPU",
                    item.get('NetboxName', ""),
                    re.IGNORECASE
                ) and not re.match(
                    "(Embedded|Integrated).*",
                    item['Name'],
                    re.IGNORECASE):

                    server_inventory_gpus.append(item)

        # NetworkAdapters
        if server_inventory_nics:
            netbox_inventory_nics = self.filter_items(
                netbox_inventory,
                "NIC|Mellanox|Broadcom|Intel|Pensando"
            )

            netbox_inventory_nics = self._check_item_amount(
                server_inventory_nics,
                netbox_inventory_nics
            )

            self._update_inventory_items(
                netbox_device_id = netbox_device_id,
                server_inventory = server_inventory_nics,
                netbox_inventory = netbox_inventory_nics
            )

        # GPUs
        if server_inventory_gpus:
            netbox_inventory_gpus = self.filter_items(netbox_inventory, "GPU")
            netbox_inventory_gpus = self._check_item_amount(
                server_inventory_gpus,
                netbox_inventory_gpus
            )

            self._update_inventory_items(
                netbox_device_id = netbox_device_id,
                server_inventory = server_inventory_gpus,
                netbox_inventory = netbox_inventory_gpus
            )

        # Drives
        if server_inventory.get('Drives'):

            # SSD
            server_inventory_ssd = []
            for item in server_inventory['Drives']:
                if (item['Protocol'] == "SATA" or
                    item['Protocol'] == "SAS") and item['MediaType'] == "SSD":
                    server_inventory_ssd.append(item)

            if server_inventory_ssd:
                netbox_inventory_ssd = self.filter_items(netbox_inventory, "FLASH|SSD")
                netbox_inventory_ssd = self._check_item_amount(
                    server_inventory_ssd,
                    netbox_inventory_ssd
                )

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id,
                    server_inventory = server_inventory_ssd,
                    netbox_inventory = netbox_inventory_ssd
                )

            # NVME
            server_inventory_nvme = []
            for item in server_inventory['Drives']:
                if (item['Protocol'] == "PCIe" or
                    item['Protocol'] == "NVMe") and item['MediaType'] == "SSD":
                    server_inventory_nvme.append(item)

            if server_inventory_nvme:
                netbox_inventory_nvme = self.filter_items(netbox_inventory, "NVME|FLASH")
                netbox_inventory_nvme = self._check_item_amount(
                    server_inventory_nvme,
                    netbox_inventory_nvme
                )

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id,
                    server_inventory = server_inventory_nvme,
                    netbox_inventory = netbox_inventory_nvme
                )

            # HDD
            server_inventory_hdd = []
            for item in server_inventory['Drives']:
                if item['Protocol'] == "SAS" and item['MediaType'] == "HDD":
                    server_inventory_hdd.append(item)

            if server_inventory_hdd:
                netbox_inventory_hdd = self.filter_items(netbox_inventory, "HDD")
                netbox_inventory_hdd = self._check_item_amount(
                    server_inventory_hdd,
                    netbox_inventory_hdd
                )

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id,
                    server_inventory = server_inventory_hdd,
                    netbox_inventory = netbox_inventory_hdd
                )

        # Controllers
        if server_inventory.get('Controllers'):

            # only get controllers that actually have disk drives attached
            server_inventory_controller = []
            for item in server_inventory['Controllers']:
                if item.get('DrivesAttached'):
                    server_inventory_controller.append(item)

            if server_inventory_controller:
                netbox_inventory_controller = self.filter_items(netbox_inventory, "RAID")
                netbox_inventory_controller = self._check_item_amount(
                    server_inventory_controller,
                    netbox_inventory_controller
                )

                self._update_inventory_items(
                    netbox_device_id = netbox_device_id,
                    server_inventory = server_inventory_controller,
                    netbox_inventory = netbox_inventory_controller
                )

        # Trusted Platform Modules
        if server_inventory.get('TrustedModules'):

            server_inventory_tpm = server_inventory['TrustedModules']

            netbox_inventory_tpm = self.filter_items(netbox_inventory, "TPM")
            netbox_inventory_tpm = self._check_item_amount(
                server_inventory_tpm,
                netbox_inventory_tpm
            )

            self._update_inventory_items(
                netbox_device_id = netbox_device_id,
                server_inventory = server_inventory_tpm,
                netbox_inventory = netbox_inventory_tpm
            )

