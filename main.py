#!/usr/bin/env python
import sys
import argparse
import logging
import os
from typing import List
from rich.console import Console
from rich import print as rprint
from xml_parser import OutputParser
from scan_ui import fill_simple_table
from nmap_runner import NmapRunner



def get_targets(target_list: List[str], cli_args: argparse.Namespace) -> str:
    if target_list[0].endswith(".txt"):
        return ["-iL", target_list[0]]
    else:
        return [','.join(target_list)]

if __name__ == "__main__":
    console = Console()
    arg_parser = argparse.ArgumentParser(
        description="Run all your nmap scans, display nicely, and output all fieldwork files",
        prog=__file__
    )
    arg_parser.add_argument(
        'targets',
        action='store',
        nargs='*',
        help=(f"One or more targets, in Nmap format (scanme.homenmap.org, microsoft.com/24, 192.168.0.1; "
              f"10.0.0-255.1-254) or a targets file (.txt only).")
    )

    args = arg_parser.parse_args()

    discovered_ports = ""
    scans = [
        {'name': '1.0_discovery_scan',
         'flags': ["-Pn", "-oA", "results/1.0_discovery_scan", "-T4", "--top-ports", "1000"]},
        {'name': '2.0_script_scan',
         'flags': ["-sCV","-Pn", "-oA", "results/2.0_script_scan", "-T4", "-p"]},
        {'name': '3.0_quick_udp_scan',
         'flags': ["-sU", "-Pn", "-oA", "results/3.0_quick_udp_scan", "-T4", "--top-ports", "100"]},
        {'name': '4.0_full_tcp_scan',
         'flags': ["-sU", "-Pn", "-oA", "results/4.0_full_tcp_scan", "-T4", "-p-"]},
        {'name': '5.0_source_port_scan',
         'flags': ["-g53","-Pn", "-oA", "results/5.0_source_port_scan", "-T4", "-p-"]},
        {'name': '6.0_IPv6_scan',
         'flags': ["-6","-Pn", "-oA", "results/6.0_IPv6_scan", "-T4", "-p-"]},
        {'name': '7.0_full_udp_scan',
         'flags': ["-Pn", "-oA", "results/7.0_full_udp_scan", "-T4", "-p-"]},
        {'name': '8.0_full_service_scan',
         'flags': ["-sCV","-Pn", "-oA", "results/8.0_full_service_scan", "-T4", "-p-"]},
    ]

    try:
        if not os.path.exists('results'):
            os.makedirs('results')

        for scan in scans:
            console.log(f"Initialising {scan['name']}...")
            scanner = NmapRunner()
            scan_targets = get_targets(args.targets, args)
            stderr = scanner.scan(hosts=scan_targets, flags=scan['flags'], ports=discovered_ports)

            if os.path.exists('results/' + scan['name'] + '.xml'):
                with open('results/' + scan['name'] + '.xml', 'r') as xml:
                    xml_data = xml.read()
                    rundata, parsed = OutputParser.parse_nmap_xml(xml_data)
                    nmap_table = fill_simple_table(exec_data=rundata, parsed_xml=parsed)
                    console.print(nmap_table)
                    for entry in parsed:
                        for port in entry['ports']:
                            discovered_ports += port['port_id'] + ","
            else:
                print('XML file not found! Please include "-oA" or "-oX" in the nmap command')
    except ValueError:
        logging.exception("There was an error")
        sys.exit(100)
    except KeyboardInterrupt:
        console.log("Scan interrupted, exiting...")
        pass
    sys.exit(0)
