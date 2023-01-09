import requests
import logging
import os
import time
import sys

class RedfishIventoryCollector(object):
    def __init__(self, config, target, host, usr, pwd):

        self._target = target
        self._host = host

        self._username = usr
        self._password = pwd

        self._timeout = int(os.getenv('TIMEOUT', config['timeout']))
        self._response_time = 0
        self._last_http_code = 0

        self._urls = {}
        self._inventory = {}

        self._start_time = time.time()
        
        self._session_url = ""
        self._auth_token = ""
        self._basic_auth = False
        self._session = ""

      
    def get_session(self):
        # Get the url for the server info and messure the response time
        logging.info(f"Target {self._target}: Connecting to server {self._host}")
        start_time = time.time()
        server_response = self.connect_server("/redfish/v1", noauth=True)
        self._response_time = round(time.time() - start_time,2)
        logging.info(f"Target {self._target}: Response time: {self._response_time} seconds.")

        if server_response:
            logging.debug(f"Target {self._target}: data received from server {self._host}.")
            session_service = self.connect_server(server_response['SessionService']['@odata.id'], basic_auth=True)
            if self._last_http_code == 200:
                sessions_url = f"https://{self._host}{session_service['Sessions']['@odata.id']}"
                session_data = {"UserName": self._username, "Password": self._password}
                self._session.auth = None
                result = ""

                # Try to get a session
                try:
                    result = self._session.post(sessions_url, json=session_data, verify=False, timeout=self._timeout)
                    result.raise_for_status()

                except requests.exceptions.ConnectionError as err:
                    logging.error(f"Target {self._target}: Error getting an auth token from server {self._host}: {err}")
                    self._basic_auth = True

                except requests.exceptions.HTTPError as err:
                    logging.warning(f"Target {self._target}: No session received from server {self._host}: {err}")
                    logging.warning(f"Target {self._target}: Switching to basic authentication.")
                    self._basic_auth = True

                if result:
                    if result.status_code in [200,201]:
                        self._auth_token = result.headers['X-Auth-Token']
                        self._session_url = result.json()['@odata.id']
                        logging.info(f"Target {self._target}: Got an auth token from server {self._host}!")

            else:
                logging.warning(f"Target {self._target}: Failed to get a session from server {self._host}!")

        else:
            logging.warning(f"Target {self._target}: No data received from server {self._host}!")
    
    def connect_server(self, command, noauth = False, basic_auth = False):
        logging.captureWarnings(True)
        
        req = ""
        req_text = ""
        server_response = ""
        self._last_http_code = 200
        request_duration = 0
        request_start = time.time()

        url = f"https://{self._host}{command}"

        # check if we already established a session with the server
        if not self._session:
            self._session = requests.Session()
        else:
            logging.debug(f"Target {self._target}: Using existing session.")
        self._session.verify = False
        self._session.headers.update({'charset': 'utf-8'})
        self._session.headers.update({'content-type': 'application/json'})

        if noauth:
            logging.debug(f"Target {self._target}: Using no auth")
        elif basic_auth or self._basic_auth:
            self._session.auth = (self._username, self._password)
            logging.debug(f"Target {self._target}: Using basic auth with user {self._username}")
        else:
            logging.debug(f"Target {self._target}: Using auth token")
            self._session.auth = None
            self._session.headers.update({'X-Auth-Token': self._auth_token})

        logging.debug(f"Target {self._target}: Using URL {url}")
        try:
            req = self._session.get(url, timeout = self._timeout)
            req.raise_for_status()

        except requests.exceptions.HTTPError as err:
            self._last_http_code = err.response.status_code
            if err.response.status_code == 401:
                logging.warning(f"Target {self._target}: Authorization Error: {err}")
            else:
                logging.warning(f"Target {self._target}: HTTP Error: {err}")

        except requests.exceptions.ConnectTimeout:
            logging.errwarningor(f"Target {self._target}: Timeout while connecting to {self._host}")

        except requests.exceptions.ReadTimeout:
            logging.warning(f"Target {self._target}: Timeout while reading data from {self._host}")

        except requests.exceptions.ConnectionError as err:
            logging.warning(f"Target {self._target}: Unable to connect to {self._host}: {err}")

        except:
            logging.warning(f"Target {self._target}: Unexpected error: {sys.exc_info()[0]}")
            logging.warning(f"Target {self._target}: URL: {url}")

        else:
            self._last_http_code = req.status_code

        if req != "":
            try: 
                req_text = req.json()

            except:
                logging.debug(f"Target {self._target}: No json data received.")

            # req will evaluate to True if the status code was between 200 and 400 and False otherwise.
            if req:
                server_response = req_text

            # if the request fails the server might give a hint in the ExtendedInfo field
            else:
                if req_text:
                    logging.debug(f"Target {self._target}: {req_text['error']['code']}: {req_text['error']['message']}")
                    if '@Message.ExtendedInfo' in req_text['error']:
                        if type(req_text['error']['@Message.ExtendedInfo']) == list:
                            if 'Message' in req_text['error']['@Message.ExtendedInfo'][0]:
                                logging.debug(f"Target {self._target}: {req_text['error']['@Message.ExtendedInfo'][0]['Message']}")
                        elif type(req_text['error']['@Message.ExtendedInfo']) == dict:
                            if 'Message' in req_text['error']['@Message.ExtendedInfo']:
                                logging.debug(f"Target {self._target}: {req_text['error']['@Message.ExtendedInfo']['Message']}")
                        else:
                            pass

        request_duration = round(time.time() - request_start,2)
        logging.debug(f"Target {self._target}: Request duration: {request_duration}")
        return server_response


    def _get_system_urls(self):

        systems = self.connect_server("/redfish/v1/Systems")

        if not systems:
            logging.warn(f"Target {self._target}: No Systems Info could be retrieved!")
            return

        # Get the server info for the labels
        self._urls.update({'Systems': systems['Members'][0]['@odata.id']})
        server_info = self.connect_server(self._urls['Systems'])

        if not server_info:
            logging.warn(f"Target {self._target}: No Server Info could be retrieved!")
            return

        fields = ('SKU', 'SerialNumber', 'Manufacturer', 'Model', 'PowerState', 'MemorySummary', 'ProcessorSummary')
        for field in fields:
            self._inventory.update({field: server_info.get(field)})

        # get the links of the parts for later
        if type(server_info['Links']['Chassis'][0]) == str:
            logging.warning(f"Target {self._target}: The Chassis Link is a string! {Manufacturer}/{Model}")
            self._urls.update({'Chassis': server_info['Links']['Chassis'][0]})
            self._urls.update({'ManagedBy': server_info['Links']['ManagedBy'][0]})
        else:
            for url in server_info['Links'].keys():
                if type(server_info['Links'][url]) == list and server_info['Links'][url] != []:
                    self._urls.update({url: server_info['Links'][url][0]['@odata.id']})

        urls = ('Memory', 'EthernetInterfaces', 'NetworkInterfaces', 'Processors', 'Storage', 'SimpleStorage')
        for url in urls:
            if url in server_info:
                self._urls.update({url: server_info[url]['@odata.id']})

    def _get_chassis_urls(self):
        logging.debug(f"Target {self._target}: Get the Power URLs.")
        chassis_info = self.connect_server(self._urls['Chassis'])
        if chassis_info:
            urls = ('Power', 'PCIeDevices', 'NetworkAdapters')
            for url in urls:
                if url in chassis_info:
                    self._urls.update({url: chassis_info[url]['@odata.id']})
                # Dell iDRAC has some of the URLs in the links section, e.g. PCIeDevices
                elif url in chassis_info['Links'] and chassis_info['Links'][url] != []:
                    self._urls.update({url: []})
                    for entry in chassis_info['Links'][url]:
                        self._urls[url].append(entry['@odata.id'])

    def _get_urls(self, url):
        urls= []
        logging.debug(f"Target {self._target}: Get the {url} URLs.")
        collection = self.connect_server(self._urls[url])
        if collection:
            for member in collection['Members']:
                urls.append(member['@odata.id'])
        
        return urls            

    def _get_storage_info(self, fields):
        logging.info(f"Target {self._target}: Get the storage data.")
        storage_collection = self.connect_server(self._urls['Storage'])

        if storage_collection:
            self._inventory.update({'Controllers': []})
            self._urls.update({'Drives': []})

            # From the storage collection we get the URL for every single storage controller
            for controller in storage_collection['Members']:
                # get the actual controller data
                controller_data = self.connect_server(controller['@odata.id'])
                if not controller_data:
                    continue
                if controller_data.get('StorageControllers'):
                    # Cisco sometimes uses a list instead of a dict
                    if type(controller_data['StorageControllers']) == list:
                        controller_details = controller_data['StorageControllers'][0]
                    else:
                        controller_details = controller_data['StorageControllers']
                else:
                    controller_details = controller_data


                controller_info = self._get_device_info(fields, controller_details)
                # HPE ILO5 is missing the Name in the details of the controllers
                controller_name = controller_details.get('Name', controller_data.get('Name'))
                if controller_info:
                    if controller_name:
                        controller_info.update({'Name': controller_name})
                    self._inventory['Controllers'].append(controller_info)
                
                # Get the drive URLs for later gathering the info
                for drive in controller_data['Drives']:
                    self._urls['Drives'].append(drive['@odata.id'])

    def _get_simple_storage_info(self, fields):
        logging.info(f"Target {self._target}: Get the simple storage data.")
        storage_collection = self.connect_server(self._urls['SimpleStorage'])
        if storage_collection:
            self._inventory.update({'Controllers': []})
            self._inventory.update({'Devices': []})

            for controller in storage_collection['Members']:
                controller_data = self.connect_server(controller['@odata.id'])
                if controller_data:
                    controller_info = self._get_device_info(fields, controller_data)
                    self._inventory['Controllers'].append(controller_info)
                    
                    if 'Devices' in controller_data:
                        for device in controller_data['Devices']:
                            device_info = self._get_device_info(fields, device)
                            self._inventory['Devices'].append(device_info)


    def _get_power_info(self, fields):
        logging.info(f"Target {self._target}: Get the PSU data.")
        power_data = self.connect_server(self._urls['Power'])
        if power_data:
            self._inventory.update({'PSU': []})
            for psu in power_data['PowerSupplies']:
                psu_info = self._get_device_info(fields, psu)
                self._inventory['PSU'].append(psu_info)

    def _get_memory_info(self, urls, fields):
        logging.info(f"Target {self._target}: Get the Memory data.")

        self._inventory.update({'Memory': []})
        for dimm_url in urls:
            dimm = self.connect_server(dimm_url)
            if dimm:
                dimm_info = self._get_device_info(fields, dimm)

                # HPE has the DIMM Manufacturer in the OEM data
                if 'Oem' in dimm:
                    if 'Hpe' in dimm['Oem']:
                        if dimm['Oem']['Hpe']['DIMMStatus'] != 'NotPresent':
                            dimm_info.update({'Manufacturer': dimm['Oem']['Hpe'].get('VendorName')})
                    
                self._inventory['Memory'].append(dimm_info)
                
    def _get_info_from_urls(self, urls, fields):
        devices = []
        for url in urls:
            device_info = self.connect_server(url)
            if device_info:
                device = self._get_device_info(fields, device_info)
                if device:
                    devices.append(device)

        return devices

    def _get_device_info(self, fields, device_info):
        current_device = {}
        if fields:
            for field in fields:
                field_value = device_info.get(field)
                # HPE and Cisco are having some field values filled with unnecessary spaces in the end
                if type(field_value) == str:
                    field_value = field_value.rstrip()
                current_device.update({field: field_value})

        else:
            current_device = device_info

        has_values = [current_device[k] for k in current_device.keys() if current_device[k] != "" and current_device[k] != None and k != "Name"]
        if has_values:
            return current_device

    def collect(self):

        logging.info(f"Target {self._target}: Collecting data ...")

        # Get the Ssystem URLs
        self._get_system_urls()

        # Get the chassis URLs
        if 'Chassis' in self._urls:
            self._get_chassis_urls()
        else:
            logging.warning(f"Target {self._target}: No Chassis URL provided! Cannot get Chassis data!")

        # Get the storage data
        if 'Storage' in self._urls:
            fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU')
            self._get_storage_info(fields)
        elif 'SimpleStorage' in self._urls:
            fields = ('Name', 'Model', 'Manufacturer', 'CapacityBytes')
            self._get_simple_storage_info(fields)
        else:
            logging.warning(f"Target {self._target}: No Storage URL provided! Cannot get Storage data!")

        # Get the drive data
        if 'Drives' in self._urls:
            logging.info(f"Target {self._target}: Get the drive data.")
            fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU', 'MediaType', 'CapacityBytes', 'Protocol')
            drives = self._get_info_from_urls(self._urls['Drives'], fields)
            self._inventory.update({'Drives': drives})
        else:
            logging.warning(f"Target {self._target}: No Drives URL provided! Cannot get drive data!")

        # Get the powersupply data
        if 'Power' in self._urls:
            fields = ('Name', 'Manufacturer', 'Model', 'SerialNumber', 'PartNumber', 'SKU')
            self._get_power_info(fields)
        else:
            logging.warning(f"Target {self._target}: No Power URL provided! Cannot get PSU data!")

        # Get the memory data
        if 'Memory' in self._urls:
            dimm_urls = self._get_urls('Memory')
            if dimm_urls:
                fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU', 'CapacityMiB', 'OperatingSpeedMhz', 'MemoryDeviceType')
                self._get_memory_info(urls=dimm_urls, fields=fields)
            else:
                logging.warning(f"Target {self._target}: No DIMM URLs found!")

        else:
            logging.warning(f"Target {self._target}: No Memory URL provided! Cannot get memory data!")

        # Get the processor data
        if 'Processors' in self._urls:
            logging.info(f"Target {self._target}: Get the CPU data.")
            proc_urls = self._get_urls('Processors')
            if proc_urls:
                fields = ('Name', 'Manufacturer', 'Model', 'SerialNumber', 'PartNumber', 'SKU', 'ProcessorType', 'TotalCores', 'TotalThreads')
                processors = self._get_info_from_urls(proc_urls, fields)
                self._inventory.update({'Processors': processors})
            else:
                logging.warning(f"Target {self._target}: No Processors found!")

        else:
            logging.warning(f"Target {self._target}: No Processors URL provided! Cannot get Processors data!")

        # HPE provides the NIC info in the Chassis/PCIeDevices
        if 'PCIeDevices' in self._urls:
            logging.info(f"Target {self._target}: Get the PCIeDevices data.")
            if type(self._urls['PCIeDevices']) == list:
                pcie_urls = self._urls['PCIeDevices']
            else:
                pcie_urls = self._get_urls('PCIeDevices')

            if pcie_urls:
                fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU', 'DeviceType')
                pcie_devices = self._get_info_from_urls(pcie_urls, fields)
                self._inventory.update({'PCIeDevices': pcie_devices})
            else:
                logging.warning(f"Target {self._target}: No PCIe URLs found!")

        else:
            logging.warning(f"Target {self._target}: No PCIeDevices URL provided!")

        # Dell providess the Nic info in the Chassis/NetworkAdapters
        if 'NetworkAdapters' in self._urls:
            logging.info(f"Target {self._target}: Get the NetworkAdapters data.")
            nic_urls = self._get_urls('NetworkAdapters')
            if nic_urls:
                fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU')
                nic_devices = self._get_info_from_urls(nic_urls, fields)
                self._inventory.update({'NetworkAdapters': nic_devices})
            else:
                logging.warning(f"Target {self._target}: No NIC URLs found!")

        else:
            logging.warning(f"Target {self._target}: No NetworkAdapters URL provided!")


        duration = round(time.time() - self._start_time,2)
        logging.info(f"Target {self._target}: Scrape duration: {duration} seconds")

        return self._inventory

    def close_session(self):

        if self._auth_token:
            logging.debug(f"Target {self._target}: Deleting Redfish session with server {self._host}")
            session_url = f"https://{self._host}{self._session_url}"
            headers = {'x-auth-token': self._auth_token}

            logging.debug(f"Target {self._target}: Using URL {session_url}")

            response = requests.delete(session_url, verify=False, timeout=self._timeout, headers=headers)
            response.close()

            if response:
                logging.info(f"Target {self._target}: Redfish Session deleted successfully.")
            else:
                logging.warning(f"Target {self._target}: Failed to delete session with server {self._host}")
                logging.warning(f"Target {self._target}: Token: { self._auth_token}")

        else:
            logging.debug(f"Target {self._target}: No Redfish session existing with server {self._host}")

        if self._session:
            logging.info(f"Target {self._target}: Closing requests session.")
            self._session.close()
