"""
handles the redfish inventory collection requests
"""
import logging
import time
import socket
import requests

class CollectorException(Exception):
    """
    exception class for the collector
    """

class RedfishIventoryCollector:
    """
    collects the inventory from a server using Redfish
    """

    def __init__(self, timeout, target, usr, pwd):

        self.target = target
        self.ip_address = self.get_bmc_ip_address(target)


        self._username = usr
        self._password = pwd

        self.timeout = timeout
        self._response_time = 0
        self.last_http_code = 0

        self._urls = {
            "Systems_Root": "/redfish/v1/Systems",
            "Chassis_Root": "/redfish/v1/Chassis",
        }
        self._inventory = {}

        self._start_time = time.time()

        self.session_url = None
        self._auth_token = None
        self._basic_auth = False
        self._session = None

    def get_bmc_ip_address(self, target):
        """
        Get the IP address of the target.
        """

        try:
            return socket.gethostbyname(target)
        except socket.gaierror as err:
            raise CollectorException(f"DNS lookup failed for Remote Board {target}: {err}") from err

    def get_session(self):
        """
        get a session from the server's remote management interface using Redfish
        """
        # Get the url for the server info and messure the response time
        logging.info("  Target %s: Connecting to server %s", self.target, self.ip_address)
        start_time = time.time()
        server_response = self.connect_server("/redfish/v1", noauth=True)

        if not server_response:
            logging.error(
                "  Target %s: No data received from server %s!",
                self.target,
                self.ip_address
            )
            self._session = None
            return

        self._response_time = round(time.time() - start_time,2)
        logging.info("  Target %s: Response time: %s seconds.", self.target, self._response_time)

        session_service = self.connect_server(
            server_response['SessionService']['@odata.id'],
            basic_auth=True
        )

        if not self.last_http_code == 200:
            logging.warning("  Target %s: Failed to get a session from server %s!",
                self.target,
                self.ip_address
            )
            return

        sessions_url = (
            f"https://{self.ip_address}"
            f"{session_service['Sessions']['@odata.id']}"
        )
        session_data = {"UserName": self._username, "Password": self._password}
        self._session.auth = None
        result = ""

        # Try to get a session
        try:
            result = self._session.post(
                sessions_url,
                json=session_data,
                verify=False,
                timeout=self.timeout
            )
            result.raise_for_status()

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as err:
            logging.warning(
                "  Target %s: A timeout occured %s: %s",
                self.target,
                self.ip_address,
                err
            )

        except requests.exceptions.ConnectionError:
            logging.warning(
                "  Target %s: Failed to get an auth token from server %s. Retrying ...",
                self.target,
                self.ip_address
            )
            try:
                result = self._session.post(
                    sessions_url, json=session_data, verify=False, timeout=self.timeout
                )
                result.raise_for_status()

            except requests.exceptions.ConnectionError as excptn:
                logging.error(
                    "  Target %s: Error getting an auth token from server %s: %s",
                    self.target,
                    self.ip_address,
                    excptn
                )
                self._basic_auth = True

        except requests.exceptions.HTTPError as err:
            logging.warning(
                "  Target %s: No session received from server %s: %s",
                self.target,
                self.ip_address,
                err
            )
            logging.warning("  Target %s: Switching to basic authentication.", self.target)
            self._basic_auth = True

        if result:
            if result.status_code in [200,201]:
                self._auth_token = result.headers['X-Auth-Token']
                self.session_url = result.json()['@odata.id']
                logging.info(
                    "  Target %s: Got an auth token from server %s!",
                    self.target,
                    self.ip_address
                )


    def connect_server(self, command, noauth = False, basic_auth = False):
        """
        connect to the server and get the data
        """

        logging.captureWarnings(True)

        server_req = ""
        server_response = ""
        self.last_http_code = 0
        request_start = time.time()

        url = f"https://{self.ip_address}{command}"

        # check if we already established a session with the server
        if not self._session:
            self._session = requests.Session()
        else:
            logging.debug("  Target %s: Using existing session.", self.target)
        self._session.verify = False
        self._session.headers.update({'charset': 'utf-8'})
        self._session.headers.update({'content-type': 'application/json'})

        if noauth:
            logging.debug("  Target %s: Using no auth", self.target)
        elif basic_auth or self._basic_auth:
            self._session.auth = (self._username, self._password)
            logging.debug(
                "  Target %s: Using basic auth with user %s",
                self.target,
                self._username
            )
        else:
            logging.debug("  Target %s: Using auth token", self.target)
            self._session.auth = None
            self._session.headers.update({'X-Auth-Token': self._auth_token})

        logging.debug("  Target %s: Using URL %s", self.target, url)
        try:
            server_req = self._session.get(url, timeout = self.timeout)
            server_req.raise_for_status()

        except requests.exceptions.ConnectionError:
            logging.warning(
                "  Target %s: Connection Error with IP %s. Retrying ...",
                self.target,
                self.ip_address
            )
            try:
                server_req = self._session.get(url, timeout = self.timeout)
                server_req.raise_for_status()
            except requests.exceptions.ConnectionError as e:
                logging.error(
                    "  Target %s: Unable to connect to IP %s: %s",
                    self.target,
                    self.ip_address,
                    e
                )

        except requests.exceptions.RequestException as err:
            if err.response:
                logging.error(
                    "  Target %s: Unable to connect to %s: Status Code %s",
                    self.target,
                    err.response.url,
                    err.response.status_code
                )
                logging.error("  Target %s: %s", self.target, err.response.text)
            else:
                logging.error("  Target %s: Unable to connect to URL %s", self.target, url)

        if server_req != "":
            self.last_http_code = server_req.status_code
            server_response = self._check_req_text(server_req)

        request_duration = round(time.time() - request_start,2)
        logging.debug(
            "  Target %s: Request duration: %s",
            self.target,
            request_duration
        )
        return server_response

    def _check_req_text(self, req):
        """extract the text from the request"""
        req_text = ""

        try:
            req_text = req.json()

        except ValueError:
            logging.debug("  Target %s: No json data received.", self.target)

        # req evaluates to True if the status code was between 200 and 400, False otherwise.
        # workaround for Cisco UCSC-C480-M5 returning 503 but still delivering the data
        if req or req.status_code == 503:
            return req_text

        # if the request fails the server might give a hint in the ExtendedInfo field
        if req_text:
            if "error" in req_text and '@Message.ExtendedInfo' in req_text['error']:
                logging.debug(
                    "  Target %s: %s: %s",
                    self.target, req_text['error']['code'],
                    req_text['error']['message']
                )

                if isinstance(req_text['error']['@Message.ExtendedInfo'], list):
                    if 'Message' in req_text['error']['@Message.ExtendedInfo'][0]:
                        logging.debug(
                            "  Target %s: %s",
                            self.target,
                            req_text['error']['@Message.ExtendedInfo'][0]['Message']
                        )

                elif isinstance(req_text['error']['@Message.ExtendedInfo'], dict):
                    if 'Message' in req_text['error']['@Message.ExtendedInfo']:
                        logging.debug(
                            "  Target %s: %s",
                            self.target,
                            req_text['error']['@Message.ExtendedInfo']['Message']
                        )
                else:
                    pass

        return req_text

    def _get_system_urls(self):

        systems = self.connect_server(self._urls['Systems_Root'])

        if not systems:
            logging.error(
                "  Target %s: No Systems Info could be retrieved!",
                self.target
            )
            return

        if not systems.get('Members'):
            logging.error(
                "  Target %s: No Systems Members found!",
                self.target
            )
            return

        if len(systems['Members']) > 1:
            logging.warning(
                "  Target %s: More than one System found!",
                self.target
            )

        # Get the server info for the labels
        self._urls.update({'Systems': systems['Members'][0]['@odata.id']})
        server_info = self.connect_server(self._urls['Systems'])

        if not server_info:
            logging.warning("  Target %s: No Server Info could be retrieved!", self.target)
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

        logging.info("  Target %s: Server powerstate: %s",
                        self.target,
                        self._inventory['PowerState']
                    )

        # get the links of the parts for later
        # for link in server_info['Links'].keys():
        #     # some Cisco servers have the links as strings
        #     if isinstance(server_info['Links'][link], str):
        #         logging.warning("  Target %s: The Link is a string!")
        #         self._urls.update({link: server_info['Links'][link][0]})
        #     if isinstance(server_info['Links'][link], list) and server_info['Links'][link] != []:
        #         if isinstance(server_info['Links'][link][0], str):
        #             url = server_info['Links'][link][0]
        #         else:
        #             url = server_info['Links'][link][0]['@odata.id']
        #         self._urls.update({link: url})

        urls = (
            'Memory',
            'EthernetInterfaces',
            'NetworkInterfaces',
            'Processors',
            'Storage',
            'SimpleStorage',
            'BaseNetworkAdapters'
        )

        for url in urls:
            if url in server_info:
                self._urls.update({url: server_info[url]['@odata.id']})

    def _get_chassis_urls(self):
        logging.debug("  Target %s: Get the Chassis URLs.", self.target)

        chassis = self.connect_server(self._urls['Chassis_Root'])

        if not chassis:
            logging.warning("  Target %s: No Chassis could be retrieved!", self.target)
            return

        for chassi in chassis['Members']:
            chassi_info = self.connect_server(chassi['@odata.id'])

            if not chassi_info:
                logging.warning("  Target %s: Chassis has no info! %s",
                    self.target,
                    chassi['@odata.id']
                )
                continue

            urls = ('Power', 'PCIeDevices', 'NetworkAdapters')
            for url in urls:
                if not self._urls.get(url):
                    self._urls.update({url: []})

                if url in chassi_info:
                    self._urls[url].append(chassi_info[url]['@odata.id'])
                # Dell iDRAC has some of the URLs in the links section, e.g. PCIeDevices
                elif url in chassi_info['Links'] and chassi_info['Links'][url] != []:
                    for entry in chassi_info['Links'][url]:
                        if isinstance(entry, str):
                            link = entry
                        else:
                            link = entry['@odata.id']
                        self._urls[url].append(link)

    def _get_urls(self, url):
        urls= []
        logging.debug("  Target %s: Get the %s URLs.", self.target, url)
        if isinstance(self._urls[url], list):
            device_urls = self._urls[url]
        else:
            device_urls = [self._urls[url]]

        for device_url in device_urls:
            collection = self.connect_server(device_url)
            if collection and collection.get('Members'):
                for member in collection['Members']:
                    urls.append(member['@odata.id'])

        return urls

    def _get_storage_info(self, fields):
        logging.info("  Target %s: Get the storage data.", self.target)
        self._inventory.update({'Controllers': []})
        self._urls.update({'Drives': []})

        storage_collection = self.connect_server(self._urls['Storage'])

        if storage_collection:
            self._get_storage_details(storage_collection, fields)

        if self._urls.get('SimpleStorage') and not self._inventory['Controllers']:
            # Some Cisco and SuperMicro servers have the storage info in SimpleStorage
            simple_storage = self.connect_server(self._urls['SimpleStorage'])
            if simple_storage:
                pass
            # Get the storage details in case the Storage url has no proper infos (Supermicro)
            # Need to write a function similar to _get_storage_details for this case.

    def _get_storage_details(self, storage_collection, fields):
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
                    controller_info.update(
                        {'DrivesAttached': controller_data['Drives@odata.count']}
                    )

                controller_info['NetboxName'] = "RAID"
                self._inventory['Controllers'].append(controller_info)

                # Get the drive URLs for later gathering the info
                for drive in controller_data['Drives']:
                    self._urls['Drives'].append(drive['@odata.id'])

    def _get_power_info(self, fields):
        logging.info("  Target %s: Get the PSU data.", self.target)
        power_data = self.connect_server(self._urls['Power'])
        if power_data:
            self._inventory.update({'PSU': []})
            for psu in power_data['PowerSupplies']:
                psu_info = self._get_device_info(psu, fields)
                self._inventory['PSU'].append(psu_info)

    def _get_memory_info(self, fields):
        logging.info("  Target %s: Get the Memory data.", self.target)

        dimm_urls = self._get_urls('Memory')
        if not dimm_urls:
            logging.warning("  Target %s: No DIMM URLs found!", self.target)
            return

        self._inventory.update({'Memory': []})
        for dimm_url in dimm_urls:
            dimm = self.connect_server(dimm_url)
            if not dimm:
                continue

            dimm_info = self._get_device_info(dimm, fields)
            if not dimm_info:
                continue

            ram_rounded = round(self._inventory['MemorySummary']['TotalSystemMemoryGiB'])
            dimm_info['NetboxName'] = f"RAM {ram_rounded}GB"

            # HPE has the DIMM Manufacturer in the OEM data
            oem_data = dimm.get('Oem', {}).get('Hpe', {})
            if oem_data.get('DIMMStatus') != 'NotPresent':
                dimm_info['Manufacturer'] = oem_data.get('VendorName')

            self._inventory['Memory'].append(dimm_info)

    def _get_info_from_urls(self, urls, fields=None):
        devices = []
        for url in urls:
            device_info = self.connect_server(url)
            if not device_info:
                continue

            device = self._get_device_info(device_info, fields)
            if not device:
                continue

            devices.append(device)

        return devices

    def _get_device_info(self, device_info, fields):
        '''extract certain fields from the data'''
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

        has_values = [
            v for k, v in current_device.items()
            if v != "" and v is not None and k != "Name"
        ]

        if has_values:
            return current_device

        return None

    def _get_port_info(self, port_info):
        '''get the port speed of the NIC'''
        port = (
            {
                'PortSpeed': 0, 
                'MAC': None
            }
        )

        # Get the MAC address
        # HPE Gen11, Lenovo v3
        if 'Ethernet' in port_info:
            macs = port_info['Ethernet']['AssociatedMACAddresses']
            if isinstance(macs, list):
                port['MAC'] = macs[0]
            else:
                port['MAC'] = macs

        # Dell R750xd, XE9680
        else:
            port['MAC'] = port_info.get('AssociatedNetworkAddresses')

        if not 'SupportedLinkCapabilities' in port_info and not 'CurrentSpeedGbps' in port_info:
            logging.warning(
                "  Target %s: No CurrentSpeedGbps and SupportedLinkCapabilities found for Port %s!",
                self.target,
                port_info['@odata.id']
            )
            return port

        current_port_speed_gbps = 0
        if 'CurrentSpeedGbps' in port_info:
            current_port_speed_gbps = (
                port_info.get('CurrentSpeedGbps') or
                port_info.get('MaxSpeedGbps') or
                0
            )
        else:
            speed = 0
            capabilities = port_info.get('SupportedLinkCapabilities', [])
            if isinstance(capabilities, list) and capabilities:
                speed = (
                    capabilities[0].get('CapableLinkSpeedMbps') or
                    capabilities[0].get('LinkSpeedMbps') or
                    0
                )
            elif isinstance(capabilities, dict):
                speed = (
                    capabilities.get('CapableLinkSpeedMbps') or
                    capabilities.get('LinkSpeedMbps') or
                    0
                )

            if isinstance(speed, list):
                speed = speed[-1]

            speed = int(speed)
            # Even though the name is CapableLinkSpeedMbps,
            # the speed is sometimes in bits/second (seen on HPE Gen11)
            if speed > 1048576:
                current_port_speed_gbps = round(speed / 1024 / 1024 / 1024)
            else:
                current_port_speed_gbps = round(speed / 1000)
        port['PortSpeed'] = current_port_speed_gbps

        return port

    def _get_drive_info(self, fields):
        """
        get the drive info
        """

        logging.info("  Target %s: Get the drive data.", self.target)
        drives = self._get_info_from_urls(self._urls['Drives'], fields)

        drives_updated = []
        for drive in drives:
            if not drive['PartNumber']:
                drive['PartNumber'] = drive['Model']

            if drive['CapacityBytes'] > 0:
                if (drive['Protocol'] in ["PCIe", "NVMe"] and
                        drive['MediaType'] == "SSD") or "NVMe" in drive['Name']:
                    drive['NetboxName'] = (
                        f"NVMe {round(drive['CapacityBytes']/1024/1024/1024)}GB"
                    )
                elif (drive['Protocol'] in ["SATA", "SAS", None] and
                    drive['MediaType'] in ["SSD", "HDD"]):
                    drive['NetboxName'] = (
                        f"{drive['MediaType']} {round(drive['CapacityBytes']/1024/1024/1024)}GB"
                    )
                    # Supermicro is missing the Protocol for SSDs
                    drive['Protocol'] = getattr(drive, 'Protocol', 'SATA')
                else:
                    logging.warning(
                        "  Target %s: Unknown Drive Type! Protocol = %s, MediaType = %s",
                        self.target, drive['Protocol'],
                        drive['MediaType']
                    )
                drives_updated.append(drive)

        self._inventory.update({'Drives': drives_updated})

    def _get_processor_info(self, fields):

        logging.info("  Target %s: Get the CPU data.", self.target)
        proc_urls = self._get_urls('Processors')
        if not proc_urls:
            logging.warning("  Target %s: No Processors found!", self.target)
            return

        processors = self._get_info_from_urls(proc_urls, fields)
        processors_updated = []
        for processor in processors:

            if processor['ProcessorType'] == 'CPU':
                processor['NetboxName'] = f"CPU {processor['TotalCores']}C"
            elif processor['ProcessorType'] == 'GPU':
                # The NVIDIA GPUs might appear as well here as
                # CPUs with ProcessorType == 'CPU'.
                # We need to filter them out to avoid duplicate entries.
                continue
            else:
                logging.warning(
                    "  Target %s: Unknown Processor Type for %s: %s.",
                    self.target,
                    processor['Name'],
                    processor['ProcessorType']
                )

            if processor['Model']:
                processor['Description'] = processor['Model']
            processors_updated.append(processor)

        self._inventory.update({'Processors': processors_updated})

    def _get_pci_devices_info(self, fields):
        """
        get the PCIe devices info
        """

        logging.info("  Target %s: Get the PCIeDevices data.", self.target)
        if isinstance(self._urls['PCIeDevices'], list):
            pcie_urls = self._urls['PCIeDevices']
        else:
            pcie_urls = self._get_urls('PCIeDevices')

        if not pcie_urls:
            logging.warning("  Target %s: No PCIe URLs found!", self.target)
            return

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
                    pcie_function_result = self._get_info_from_urls(
                        pcie_functions_link, fields=None)
                    if pcie_function_result:
                        pcie_functions = pcie_function_result[0]['Members']
                pcie_device.pop("PCIeFunctions")

            if pcie_functions:
                for member in pcie_functions:
                    pcie_device_functions_urls.append(member['@odata.id'])

            pcie_device_functions = self._get_info_from_urls(
                pcie_device_functions_urls, fields=None)

            if pcie_device_functions:
                try:
                    pcie_device['DeviceClass'] = pcie_device_functions[0]['DeviceClass']

                except (KeyError, AttributeError):
                    pcie_device['DeviceClass'] = ""

                device_class_to_name = {
                    "NetworkController": "NIC",
                    "DisplayController": "GPU",
                    "MassStorageController": "RAID"
                }
                pcie_device['NetboxName'] = device_class_to_name.get(pcie_device['DeviceClass'], "")

            pcie_devices_updated.append(pcie_device)

        self._inventory.update({'PCIeDevices': pcie_devices_updated})

    def _get_network_info(self, fields):
        logging.info("  Target %s: Get the NetworkAdapters data.", self.target)
        nic_urls = self._get_urls('NetworkAdapters')
        if not nic_urls:
            logging.warning("  Target %s: No NIC URLs found!", self.target)
            return

        network_cards = self._get_info_from_urls(nic_urls, fields)
        network_cards_updated = []
        for nic in network_cards:
            port_speed_gbps = 0
            # HPE Gen11 Calls it 'Ports'
            nic_ports_url = nic['NetworkPorts'] if nic['NetworkPorts'] else nic.get('Ports')
            if nic_ports_url:
                self._urls['NetworkPorts'] = nic_ports_url['@odata.id']
                ports = self._get_urls('NetworkPorts')
                ports_info = self._get_info_from_urls(ports)
                nic['Ports'] = []
                for port_info in ports_info:
                    nic['Ports'].append(self._get_port_info(port_info))

                port_speed_gbps = max((port.get('PortSpeed') or 0) for port in nic['Ports'])

            nic['NetboxName'] = f"NIC {port_speed_gbps}Gb" if port_speed_gbps else "NIC"
            nic.pop('NetworkPorts')
            network_cards_updated.append(nic)

        self._inventory.update({'NetworkAdapters': network_cards_updated})

    def _collect_component_data(self, component, method, component_name, fields=None):
        if component in self._urls and self._urls[component]:
            if fields:
                method(fields)
            else:
                method()
        else:
            logging.warning(
                "  Target %s: No %s URL provided! Cannot get %s data!",
                self.target,
                component,
                component_name
            )

    def collect(self):
        """
        collect the inventory from the server
        """
        logging.info("  Target %s: Collecting data ...", self.target)

        # Get the System URLs
        self._get_system_urls()
        if not self._urls.get('Systems'):
            return

        # Collect data for different components
        self._collect_component_data('Chassis', self._get_chassis_urls, "Chassis")
        self._collect_component_data(
            'Storage', self._get_storage_info, "Storage",
            ('Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU')
        )
        self._collect_component_data(
            'Drives', self._get_drive_info, "drive",
            (
            'Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU',
            'MediaType', 'CapacityBytes', 'Protocol'
            )
        )
        self._collect_component_data(
            'Power', self._get_power_info, "PSU",
            ('Name', 'Manufacturer', 'Model', 'SerialNumber', 'PartNumber', 'SKU')
        )
        self._collect_component_data(
            'Memory', self._get_memory_info, "memory",
            (
            'Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU',
            'CapacityMiB', 'OperatingSpeedMhz', 'MemoryDeviceType'
            )
        )
        self._collect_component_data(
            'Processors', self._get_processor_info, "Processors",
            (
            'Name', 'Manufacturer', 'Model', 'SerialNumber', 'PartNumber', 'SKU',
            'ProcessorType', 'TotalCores', 'TotalThreads', 'Description'
            )
        )
        self._collect_component_data(
            'PCIeDevices', self._get_pci_devices_info, "PCIeDevices",
            (
            'Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU',
            'Links', 'PCIeFunctions', 'Id'
            )
        )
        self._collect_component_data(
            'NetworkAdapters', self._get_network_info, "NetworkAdapters",
            (
            'Name', 'Model', 'Manufacturer', 'SerialNumber', 'PartNumber', 'SKU',
            'NetworkPorts', 'Ports'
            )
        )

        duration = round(time.time() - self._start_time, 2)
        logging.info("  Target %s: Scrape duration: %s seconds", self.target, duration)

        return self._inventory

    def close_session(self):
        """
        close the session with the server
        """
        if self._auth_token:
            logging.debug(
                "  Target %s: Deleting Redfish session with server %s",
                self.target,
                self.ip_address
            )
            session_url = f"https://{self.ip_address}{self.session_url}"
            headers = {'x-auth-token': self._auth_token}

            logging.debug("  Target %s: Using URL %s", self.target, session_url)

            try:
                response = requests.delete(
                    session_url,
                    verify=False,
                    timeout=self.timeout,
                    headers=headers
                )
            except requests.exceptions.ReadTimeout as err:
                logging.warning(
                    "  Target %s: Failed to delete session with server %s: %s",
                    self.target,
                    self.ip_address,
                    err
                )
            else:
                response.close()
                logging.info(
                    "  Target %s: Redfish Session deleted successfully.",
                    self.target
                )

        else:
            logging.debug(
                "  Target %s: No Redfish session existing with server %s",
                self.target,
                self.ip_address
            )

        if self._session:
            logging.info("  Target %s: Closing requests session.", self.target)
            self._session.close()
