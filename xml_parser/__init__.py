from typing import Any, Tuple
import requests
from dataclasses import dataclass
from xml.etree import ElementTree
from lxml import html
from cpe import CPE
IGNORED_CPES = {"cpe:/o:linux:linux_kernel"}

@dataclass
class NIST:
    summary: str
    link: str
    score: str

class NISTHTML:

    def __init__(self):
        """
        Some CPEs return too many false positives,
        so they are ignored right away.
        """
        self.raw_html = None
        self.parsed_results = []
        self.url = "https://nvd.nist.gov/vuln/search/results"
        self.ignored_cpes = IGNORED_CPES

    def get(self, cpe: str) -> str:
        """
        Run a CPE search on the NIST website. If the CPE has 
        no version then skip the search as it will return too
        many false positives.
        @param cpe: CPE identifier coming from Nmap, like cpe:/a:openbsd:openssh:8.0
        @return:
        """
        params = {
            'form_type': 'Basic',
            'results_type': 'overview',
            'search_type': 'all',
            'isCpeNameSearch': 'false',
            'query': cpe
        }
        if cpe in self.ignored_cpes:
            return ""
        valid_cpe = CPE(cpe)
        if not valid_cpe.get_version()[0]:
            return ""
        response = requests.get(
            url=self.url,
            params=params
        )
        response.raise_for_status()
        return response.text
    
    def parse(self, html_data: str) -> list[NIST]:
        """
        Parse NIST web search. Not aware of any REST API offered that doesn't require
        parsing. It is assumed that this method is never called directly by end users,
        so no further checks are done of the HTML file contents.
        @param html_data: RAW HTML used for scraping
        @return: List of advisories, if any
        """
        self.parsed_results = []
        if html_data:
            nist_html = html.fromstring(html_data)
            # 1:1 match between 3 elements, use parallel array
            summary = nist_html.xpath("//*[contains(@data-testid, 'vuln-summary')]")
            cve = nist_html.xpath("//*[contains(@data-testid, 'vuln-detail-link')]")
            score = nist_html.xpath("//*[contains(@data-testid, 'vuln-cvss2-link')]")
            for i in range(len(summary)):
                nist = NIST(
                    summary=summary[i].text,
                    link="https://nvd.nist.gov/vuln/detail/" + cve[i].text,
                    score=score[i].text
                )
                self.parsed_results.append(nist)
        return self.parsed_results
    
    def correlate_nmap_with_nist(self, parsed_xml: Any) -> dict[str, list[NIST]]:
        correlated_cpe = {}
        for row_data in parsed_xml:
            ports = row_data['ports']
            for port_data in ports:
                for cpe in port_data['cpes']:
                    raw_nist = self.get(cpe)
                    cpes = self.parse(raw_nist)
                    correlated_cpe[cpe] = cpes
        return correlated_cpe

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
                    if states[i].attrib['state'] == 'closed':
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