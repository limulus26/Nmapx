from typing import Any, Tuple
import requests
from dataclasses import dataclass
from xml.etree import ElementTree
from lxml import html
from cpe import CPE
IGNORED_CPES = {"cpe:/o:linux:linux_kernel"}

class OutputParser:
    """
    Parse Nmap raw XML output
    """

    @staticmethod
    def parse_nmap_xml(xml: str) -> Tuple[str, Any]:
        """
        Parse XML and return details for the scanned ports
        @param xml: NMAP results in XML file
        @return: tuple NMAP arguments, port details
        """
        parsed_data = []
        root = ElementTree.fromstring(xml)
        nmap_args = root.attrib['args']
        for host in root.findall('host'):
            for address in host.findall('address'):
                curr_address = address.attrib['addr']
                data = {
                    'address': curr_address,
                    'ports': []
                }
                states = host.findall('ports/port/state')
                ports = host.findall('ports/port')
                for i in range(len(ports)):
                    if states[i].attrib['state'] == 'closed' or states[i].attrib['state'] == 'filtered':
                        continue  # Skip closed ports
                    port_id = ports[i].attrib['portid']
                    protocol = ports[i].attrib['protocol']
                    services = ports[i].findall('service')
                    script_list = []
                    script_output = []
                    service_name = ""
                    service_product = ""
                    service_version = ""
                    for service in services:
                        for key in ['name', 'product', 'version']:
                            if key in service.attrib:
                                if key == 'name':
                                    service_name = service.attrib['name']
                                elif key == 'product':
                                    service_product = service.attrib['product']
                                elif key == 'version':
                                    service_version = service.attrib['version']
                    scripts = ports[i].findall('script')
                    for script in scripts:
                        script_list.append(script.attrib['id'])
                        script_output.append(script.attrib['output'])
                    data['ports'].append({
                        'port_id': port_id,
                        'protocol': protocol,
                        'service_name': service_name,
                        'service_product': service_product,
                        'service_version': service_version,
                        'scripts': script_list,
                        'script_outputs': script_output
                    })
                parsed_data.append(data)
        return nmap_args, parsed_data