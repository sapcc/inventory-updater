"""
handles the redfish inventory collection requests
"""
import logging
import time
import re
import requests

class CollectorException(Exception):
    """
    exception class for the collector
    """

class RedfishIventoryCollector:
    """
    collects the inventory from a server using Redfish
    """

    def __init__(self, timeout, target, ip_address, usr, pwd):

        self._target = target
        self.ip_address = ip_address

        self._username = usr
        self._password = pwd

        self._timeout = timeout
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
        """
        get a session from the server's remote management interface using Redfish
        """
        # Get the url for the server info and messure the response time
        logging.info("  Target %s: Connecting to server %s", self._target, self.ip_address)
        start_time = time.time()
        server_response = self.connect_server("/redfish/v1", noauth=True)
        self._response_time = round(time.time() - start_time,2)
        logging.info("  Target %s: Response time: %s seconds.", self._target, self._response_time)

        if server_response:
            logging.debug(
                "  Target %s: data received from server %s.",
                self._target,
                self.ip_address
            )
            session_service = self.connect_server(
                server_response['SessionService']['@odata.id'],
                basic_auth=True
            )
            if self._last_http_code == 200:
                sessions_url = f"https://{self.ip_address}{session_service['Sessions']['@odata.id']}"
                session_data = {"UserName": self._username, "Password": self._password}
                self._session.auth = None
                result = ""

                # Try to get a session
                try:
                    result = self._session.post(
                        sessions_url,
                        json=session_data,
                        verify=False,
                        timeout=self._timeout
                    )
                    result.raise_for_status()

                except requests.exceptions.ConnectTimeout as err:
                    logging.warning(
                        "  Target %s: A Connection Timeout occured %s: %s",
                        self._target,
                        self.ip_address,
                        err
                    )

                except requests.exceptions.ConnectionError:
                    logging.warning(
                        "  Target %s: Failed to get an auth token from server %s. Retrying ...",
                        self._target,
                        self.ip_address
                    )
                    try:
                        result = self._session.post(
                            sessions_url, json=session_data, verify=False, timeout=self._timeout
                        )
                        result.raise_for_status()

                    except requests.exceptions.ConnectionError as excptn:
                        logging.error(
                            "  Target %s: Error getting an auth token from server %s: %s",
                            self._target,
                            self.ip_address,
                            excptn
                        )
                        self._basic_auth = True

                except requests.exceptions.ReadTimeout as err:
                    logging.warning(
                        "  Target %s: A Read Timeout occured %s: %s",
                        self._target,
                        self.ip_address,
                        err
                    )

                except requests.exceptions.HTTPError as err:
                    logging.warning(
                        "  Target %s: No session received from server %s: %s",
                        self._target,
                        self.ip_address,
                        err
                    )
                    logging.warning("  Target %s: Switching to basic authentication.", self._target)
                    self._basic_auth = True

                if result:
                    if result.status_code in [200,201]:
                        self._auth_token = result.headers['X-Auth-Token']
                        self._session_url = result.json()['@odata.id']
                        logging.info("  Target %s: Got an auth token from server %s!", self._target, self.ip_address)

            else:
                logging.warning("  Target %s: Failed to get a session from server %s!",
                    self._target,
                    self.ip_address
                )

        else:
            logging.warning("  Target %s: No data received from server %s!", self._target, self.ip_address)

    def connect_server(self, command, noauth = False, basic_auth = False):
        """
        connect to the server and get the data
        """

        logging.captureWarnings(True)

        req = ""
        req_text = ""
        server_response = ""
        self._last_http_code = 0
        request_start = time.time()

        url = f"https://{self.ip_address}{command}"

        # check if we already established a session with the server
        if not self._session:
            self._session = requests.Session()
        else:
            logging.debug("  Target %s: Using existing session.", self._target)
        self._session.verify = False
        self._session.headers.update({'charset': 'utf-8'})
        self._session.headers.update({'content-type': 'application/json'})

        if noauth:
            logging.debug("  Target %s: Using no auth")
        elif basic_auth or self._basic_auth:
            self._session.auth = (self._username, self._password)
            logging.debug("  Target %s: Using basic auth with user %s", self._target, self._username)
        else:
            logging.debug("  Target %s: Using auth token")
            self._session.auth = None
            self._session.headers.update({'X-Auth-Token': self._auth_token})

        logging.debug("  Target %s: Using URL %s", self._target, url)
        try:
            req = self._session.get(url, timeout = self._timeout)
            req.raise_for_status()

        except requests.exceptions.ConnectionError:
            logging.warning(
                "  Target %s: Connection Error with %s. Retrying ...",
                self._target,
                self.ip_address
            )
            try:
                req = self._session.get(url, timeout = self._timeout)
                req.raise_for_status()
            except requests.exceptions.ConnectionError as e:
                logging.error(
                    "  Target %s: Unable to connect to %s: %s",
                    self._target,
                    self.ip_address,
                    e
                )

        except requests.exceptions.RequestException as err:
            if err.response:
                logging.error(
                    "  Target %s: Unable to connect to %s: Status Code %s",
                    self._target,
                    err.response.url,
                    err.response.status_code
                )
                logging.error("  Target %s: %s", self._target, err.response.text)
            else:
                logging.error("  Target %s: Unable to connect: %s", self._target, self.ip_address)

        if req != "":
            self._last_http_code = req.status_code
            try:
                req_text = req.json()

            except ValueError:
                logging.debug("  Target %s: No json data received.", self._target)

            # req evaluates to True if the status code was between 200 and 400, False otherwise.
            if req:
                server_response = req_text

            # if the request fails the server might give a hint in the ExtendedInfo field
            else:
                if req_text:
                    if "error" in req_text and '@Message.ExtendedInfo' in req_text['error']:

                        logging.debug(
                            "  Target %s: %s: %s",
                            self._target, req_text['error']['code'],
                            req_text['error']['message']
                        )
                        if isinstance(req_text['error']['@Message.ExtendedInfo'], list):
                            if 'Message' in req_text['error']['@Message.ExtendedInfo'][0]:
                                logging.debug(
                                    "  Target %s: %s",
                                    self._target,
                                    req_text['error']['@Message.ExtendedInfo'][0]['Message']
                                )
                        elif isinstance(req_text['error']['@Message.ExtendedInfo'], dict):
                            if 'Message' in req_text['error']['@Message.ExtendedInfo']:
                                logging.debug(
                                    "  Target %s: %s",
                                    self._target,
                                    req_text['error']['@Message.ExtendedInfo']['Message']
                                )
                        else:
                            pass
                    # workaround for Cisco UCSC-C480-M5 returning a 503 but still delivering the data
                    else:
                        server_response = req_text

        request_duration = round(time.time() - request_start,2)
        logging.debug("  Target %s: Request duration: %s", self._target, request_duration)
        return server_response


    def _get_system_urls(self):

        systems = self.connect_server("/redfish/v1/Systems")

        if not systems:
            raise CollectorException(f"  Target {self._target}: No Systems Info could be retrieved!")

        # Get the server info for the labels
        self._urls.update({'Systems': systems['Members'][0]['@odata.id']})
        server_info = self.connect_server(self._urls['Systems'])

        if not server_info:
            logging.warning("  Target %s: No Server Info could be retrieved!", self._target)
            return

        fields = (
            'SKU',
            'SerialNumber',
            'Manufacturer',
            'Model',
            'PowerState',
            'MemorySummary',
            'ProcessorSummary'
        )

        for field in fields:
            self._inventory.update({field: server_info.get(field)})

        logging.info("  Target %s: Server powerstate: %s", self._target, self._inventory['PowerState'])

        # get the links of the parts for later
        for link in server_info['Links'].keys():
            # some Cisco servers have the links as strings
            if isinstance(server_info['Links'][link], str):
                logging.warning("  Target %s: The Link is a string!")
                self._urls.update({link: server_info['Links'][link][0]})
            if isinstance(server_info['Links'][link], list) and server_info['Links'][link] != []:
                if isinstance(server_info['Links'][link][0], str):
                    url = server_info['Links'][link][0]
                else:
                    url = server_info['Links'][link][0]['@odata.id']
                self._urls.update({link: url})

        urls = (
            'Memory',
            'EthernetInterfaces',
            'NetworkInterfaces',
            'Processors',
            'Storage',
            'BaseNetworkAdapters'
        )

        for url in urls:
            if url in server_info:
                self._urls.update({url: server_info[url]['@odata.id']})

    def _get_chassis_urls(self):
        logging.debug("  Target %s: Get the Power URLs.")
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
                        if isinstance(entry, str):
                            link = entry
                        else:
                            link = entry['@odata.id']
                        self._urls[url].append(link)

    def _get_urls(self, url):
        urls= []
        logging.debug("  Target %s: Get the {url} URLs.")
        collection = self.connect_server(self._urls[url])
        if collection:
            for member in collection['Members']:
                urls.append(member['@odata.id'])

        return urls

    def _get_storage_info(self, fields):
        logging.info("  Target %s: Get the storage data.", self._target)
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
                    if isinstance(controller_data['StorageControllers'], list):
                        controller_details = controller_data['StorageControllers'][0]
                    else:
                        controller_details = controller_data['StorageControllers']
                else:
                    controller_details = controller_data


                controller_info = self._get_device_info(controller_details, fields)
                # HPE ILO5 is missing the Name in the details of the controllers
                controller_name = controller_details.get('Name', controller_data.get('Name'))
                if controller_info:
                    if controller_name:
                        controller_info.update({'Name': controller_name.rstrip()})

                    # Get the amount of drives attached to the controller
                    if controller_data.get('Drives@odata.count'):
                        controller_info.update({'DrivesAttached': controller_data['Drives@odata.count']})

                    controller_info['NetboxName'] = "RAID"
                    self._inventory['Controllers'].append(controller_info)

                # Get the drive URLs for later gathering the info
                for drive in controller_data['Drives']:
                    self._urls['Drives'].append(drive['@odata.id'])

    def _get_power_info(self, fields):
        logging.info("  Target %s: Get the PSU data.", self._target)
        power_data = self.connect_server(self._urls['Power'])
        if power_data:
            self._inventory.update({'PSU': []})
            for psu in power_data['PowerSupplies']:
                psu_info = self._get_device_info(psu, fields)
                self._inventory['PSU'].append(psu_info)

    def _get_memory_info(self, urls, fields):
        logging.info("  Target %s: Get the Memory data.", self._target)

        self._inventory.update({'Memory': []})
        for dimm_url in urls:
            dimm = self.connect_server(dimm_url)
            if dimm:
                dimm_info = self._get_device_info(dimm, fields)
                if dimm_info:
                    dimm_info['NetboxName'] = f"RAM {round(self._inventory['MemorySummary']['TotalSystemMemoryGiB'])}GB"

                    # HPE has the DIMM Manufacturer in the OEM data
                    if 'Oem' in dimm:
                        if 'Hpe' in dimm['Oem']:
                            if dimm['Oem']['Hpe']['DIMMStatus'] != 'NotPresent':
                                dimm_info.update({'Manufacturer': dimm['Oem']['Hpe'].get('VendorName')})

                    self._inventory['Memory'].append(dimm_info)

    def _get_info_from_urls(self, urls, fields=None):
        devices = []
        for url in urls:
            device_info = self.connect_server(url)
            if device_info:
                device = self._get_device_info(device_info, fields)
                if device:
                    devices.append(device)

        return devices

    def _get_device_info(self, device_info, fields):
        current_device = {}
        if fields:
            for field in fields:
                field_value = device_info.get(field)
                # HPE and Cisco: some field values filled with unnecessary spaces in the end
                if isinstance(field_value, str):
                    field_value = field_value.rstrip()
                current_device.update({field: field_value})

        else:
            current_device = device_info

        has_values = [current_device[k] for k in current_device.keys() if current_device[k] != "" and current_device[k] is not None and k != "Name"]
        if has_values:
            return current_device

    def collect(self):
        """
        collect the inventory from the server
        """
        logging.info("  Target %s: Collecting data ...", self._target)

        # Get the Ssystem URLs
        self._get_system_urls()

        # Get the chassis URLs
        if 'Chassis' in self._urls:
            self._get_chassis_urls()
        else:
            logging.warning("  Target %s: No Chassis URL provided! Cannot get Chassis data!", self._target)

        # Get the storage data
        if 'Storage' in self._urls:
            fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU')
            self._get_storage_info(fields)
        else:
            logging.warning("  Target %s: No Storage URL provided! Cannot get Storage data!", self._target)

        # Get the drive data
        if 'Drives' in self._urls:
            logging.info("  Target %s: Get the drive data.", self._target)
            fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU', 'MediaType', 'CapacityBytes', 'Protocol')
            drives = self._get_info_from_urls(self._urls['Drives'], fields)

            drives_updated = []
            for drive in drives:
                if drive['CapacityBytes'] > 0:
                    if (drive['Protocol'] == "SATA" or drive['Protocol'] == "SAS") and (drive['MediaType'] == "SSD" or drive['MediaType'] == "HDD"):
                        drive['NetboxName'] = f"{drive['MediaType']} {round(drive['CapacityBytes']/1024/1024/1024)}GB"
                    elif ((drive['Protocol'] == "PCIe" or drive['Protocol'] == "NVMe") and drive['MediaType'] == "SSD") or re.match(r'^.*NVMe.*$', drive['Name']) :
                        drive['NetboxName'] = f"NVMe {round(drive['CapacityBytes']/1024/1024/1024)}GB"
                    else:
                        logging.warning("  Target %s: Unknown Drive Type! Protocol = %s, MediaType = %s", self._target, drive['Protocol'], drive['MediaType'])
                    drives_updated.append(drive)

            self._inventory.update({'Drives': drives_updated})
        else:
            logging.warning("  Target %s: No Drives URL provided! Cannot get drive data!")

        # Get the powersupply data
        if 'Power' in self._urls:
            fields = ('Name', 'Manufacturer', 'Model', 'SerialNumber', 'PartNumber', 'SKU')
            self._get_power_info(fields)
        else:
            logging.warning("  Target %s: No Power URL provided! Cannot get PSU data!", self._target)

        # Get the memory data
        if 'Memory' in self._urls:
            dimm_urls = self._get_urls('Memory')
            if dimm_urls:
                fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU', 'CapacityMiB', 'OperatingSpeedMhz', 'MemoryDeviceType')
                self._get_memory_info(urls=dimm_urls, fields=fields)
            else:
                logging.warning("  Target %s: No DIMM URLs found!", self._target)

        else:
            logging.warning("  Target %s: No Memory URL provided! Cannot get memory data!", self._target)

        # Get the processor data
        if 'Processors' in self._urls:
            logging.info("  Target %s: Get the CPU data.", self._target)
            proc_urls = self._get_urls('Processors')
            if proc_urls:
                fields = ('Name', 'Manufacturer', 'Model', 'SerialNumber', 'PartNumber', 'SKU', 'ProcessorType', 'TotalCores', 'TotalThreads', 'Description')
                processors = self._get_info_from_urls(proc_urls, fields)
                processors_updated = []
                for processor in processors:

                    if processor['ProcessorType'] == 'CPU':
                        processor['NetboxName'] = f"CPU {processor['TotalCores']}C"
                    elif processor['ProcessorType'] == 'GPU':
                        # The NVIDIA GPUs might appear as well here as CPUs with ProcessorType == 'CPU'. We need to filter them out to avoid duplicate entries.
                        continue
                    else:
                        logging.warning("  Target %s: Unknown Processor Type for %s: %s.", self._target, processor['Name'], processor['ProcessorType'])

                    processor['Description'] = processor['Model'] if processor['Model'] else processor['Description']
                    processors_updated.append(processor)

                self._inventory.update({'Processors': processors_updated})
            else:
                logging.warning("  Target %s: No Processors found!", self._target)

        else:
            logging.warning("  Target %s: No Processors URL provided! Cannot get Processors data!")

        # HPE provides the NIC info in the Chassis/PCIeDevices
        if 'PCIeDevices' in self._urls:
            logging.info("  Target %s: Get the PCIeDevices data.", self._target)
            if isinstance(self._urls['PCIeDevices'], list):
                pcie_urls = self._urls['PCIeDevices']
            else:
                pcie_urls = self._get_urls('PCIeDevices')

            if pcie_urls:
                fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU', 'Links', 'PCIeFunctions', 'Id')
                pcie_devices = self._get_info_from_urls(pcie_urls, fields=fields)

                pcie_devices_updated = []
                # Get the DeviceClass
                for pcie_device in pcie_devices:

                    pcie_device_functions_urls = []
                    pcie_functions = ""

                    # Lenovo and Dell
                    if pcie_device.get('Links'):
                        pcie_functions = pcie_device['Links'].get('PCIeFunctions')
                        pcie_device.pop("Links")

                    # HPE
                    if pcie_device.get('PCIeFunctions'):
                        # Did we get the pcie_functions already above?
                        # Lenovo has both entries (Links and PCIeFunctions)
                        if not pcie_functions:
                            pcie_functions_link = [pcie_device['PCIeFunctions']['@odata.id']]
                            pcie_function_result = self._get_info_from_urls(pcie_functions_link, fields=None)
                            if pcie_function_result:
                                pcie_functions = pcie_function_result[0]['Members']
                        pcie_device.pop("PCIeFunctions")

                    if pcie_functions:
                        for member in pcie_functions:
                            pcie_device_functions_urls.append(member['@odata.id'])

                    pcie_device_functions = self._get_info_from_urls(pcie_device_functions_urls, fields=None)

                    if pcie_device_functions:
                        try:
                            pcie_device['DeviceClass'] = pcie_device_functions[0]['DeviceClass']

                        except (KeyError, AttributeError):
                            pcie_device['DeviceClass'] = ""

                        if pcie_device['DeviceClass'] == "NetworkController":
                            pcie_device['NetboxName'] = "NIC"
                        elif pcie_device['DeviceClass'] == "DisplayController":
                            pcie_device['NetboxName'] = "GPU"
                        elif pcie_device['DeviceClass'] == "MassStorageController":
                            pcie_device['NetboxName'] = "RAID"

                    pcie_devices_updated.append(pcie_device)

                self._inventory.update({'PCIeDevices': pcie_devices_updated})
            else:
                logging.warning("  Target %s: No PCIe URLs found!", self._target)

        else:
            logging.warning("  Target %s: No PCIeDevices URL provided!", self._target)

        # Dell and HPE Gen11 provide the Nic info in the Chassis/NetworkAdapters
        if 'NetworkAdapters' in self._urls:
            logging.info("  Target %s: Get the NetworkAdapters data.", self._target)
            nic_urls = self._get_urls('NetworkAdapters')
            if nic_urls:
                fields = ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU', 'NetworkPorts', 'Ports')
                nic_devices = self._get_info_from_urls(nic_urls, fields)
                nic_devices_updated = []
                for nic in nic_devices:
                    port_speed = 0
                    # HPE Gen11 Calls it 'Ports'
                    nic_ports_url = nic['NetworkPorts'] if nic['NetworkPorts'] else nic.get('Ports')
                    if nic_ports_url:
                        nic['Ports'] = []
                        self._urls['NetworkPorts'] = nic_ports_url['@odata.id']
                        ports = self._get_urls('NetworkPorts')
                        ports_info = self._get_info_from_urls(ports)
                        for port_info in ports_info:
                            current_port_speed = 0
                            if isinstance(port_info['SupportedLinkCapabilities'], list) and 'CapableLinkSpeedMbps' in port_info['SupportedLinkCapabilities'][0]:
                                current_port_speed = round((port_info['SupportedLinkCapabilities'][0]['CapableLinkSpeedMbps'][-1])/1000)
                            elif 'CapableLinkSpeedMbps' in port_info['SupportedLinkCapabilities']:
                                current_port_speed = round((port_info['SupportedLinkCapabilities']['CapableLinkSpeedMbps'][-1])/1000)
                            else:
                                logging.warning("  Target %s: No CapableLinkSpeedMbps found!", self._target)
                            if current_port_speed > port_speed:
                                port_speed = current_port_speed

                            # HPE Gen11, Lenovo v3
                            if 'Ethernet' in port_info:
                                if isinstance(port_info['Ethernet']['AssociatedMACAddresses'], list):
                                    port_mac = port_info['Ethernet']['AssociatedMACAddresses'][0]
                                else:
                                    port_mac = port_info['Ethernet']['AssociatedMACAddresses']

                            # Dell R750xd, XE9680
                            else:
                                port_mac = port_info.get('AssociatedNetworkAddresses')

                            nic['Ports'].append({'PortSpeed': current_port_speed, 'MAC': port_mac})

                    nic['NetboxName'] = f"NIC {port_speed}Gb" if port_speed else "NIC"
                    nic.pop('NetworkPorts')
                    nic_devices_updated.append(nic)

                self._inventory.update({'NetworkAdapters': nic_devices_updated})
            else:
                logging.warning("  Target %s: No NIC URLs found!")

        else:
            logging.warning("  Target %s: No NetworkAdapters URL provided!")


        duration = round(time.time() - self._start_time,2)
        logging.info("  Target %s: Scrape duration: %s seconds", self._target, duration)

        return self._inventory

    def close_session(self):
        """
        close the session with the server
        """
        if self._auth_token:
            logging.debug(
                "  Target %s: Deleting Redfish session with server %s",
                self._target,
                self.ip_address
            )
            session_url = f"https://{self.ip_address}{self._session_url}"
            headers = {'x-auth-token': self._auth_token}

            logging.debug("  Target %s: Using URL %s", self._target, session_url)

            try:
                response = requests.delete(
                    session_url,
                    verify=False,
                    timeout=self._timeout,
                    headers=headers
                )
            except requests.exceptions.ReadTimeout as err:
                logging.warning(
                    "  Target %s: Failed to delete session with server %s: %s",
                    self._target,
                    self.ip_address,
                    err
                )
            else:
                response.close()
                logging.info("  Target %s: Redfish Session deleted successfully.", self._target)

        else:
            logging.debug(
                "  Target %s: No Redfish session existing with server %s",
                self._target,
                self.ip_address
            )

        if self._session:
            logging.info("  Target %s: Closing requests session.", self._target)
            self._session.close()
