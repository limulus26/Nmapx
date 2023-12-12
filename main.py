#!/usr/bin/env python
import sys
import argparse
import logging
import os
import datetime
from typing import List
from rich.console import Console
from xml_parser import OutputParser
from scan_ui import fill_simple_table
from nmap_runner import NmapRunner
from xml.etree.ElementTree import ParseError



def get_targets(targets: str, cli_args: argparse.Namespace):
    if targets[0].endswith(".txt"):
        with open(targets[0], "r") as target_file:
            return [line.rstrip('\n') for line in target_file]
    else:
        return targets[0].split(",")

if __name__ == "__main__":
    console = Console()
    arg_parser = argparse.ArgumentParser(
        description="Run all your nmap scans, display nicely, and output all fieldwork files",
        prog=__file__
    )
    arg_parser.add_argument(
        '-t',
        '--targets',
        action='store',
        nargs='*',
        help=(f"One or more targets, in Nmap format (scanme.homenmap.org, microsoft.com/24, 192.168.0.1; "
              f"10.0.0-255.1-254) or a targets file (.txt only)."),
        required=True
    )
    arg_parser.add_argument(
        '-o',
        '--output',
        action='store',
        nargs='*',
        help=(f"The name of the output folder to be created inside the results folder to save scan output."
              f"Defaults to <date>_<time>/."),
        required=False
    )
    arg_parser.add_argument(
        '--rescan',
        action='store',
        help=(f'Force Nmapx to rescan targets even if it finds existing scan logs.'),
        required=False
    )
    # arg_parser.add_argument(
    #     '-s',
    #     '--scans',
    #     action='store',
    #     nargs='*',
    #     help=(f"A file containing a list of custom nmap scans to be run. Will use default list if omitted."),
    #     required=False
    # )

    args = arg_parser.parse_args()

    discovered_ports = []
    scans = [
        # {'name': '0.0_host_scan',
        #  'flags': ["-T4", "--open"]}
        # {'name': '1.0_discovery_scan',
        #  'flags': [, "-T4", "--top-ports", "1000", "--open"]},
        # {'name': '2.0_script_scan',
        #  'flags': ["-sCV", "-T4", "-p"]},
        # {'name': '3.0_quick_udp_scan',
        #  'flags': ["-sU", "-T4", "--top-ports", "100"]},
        {'name': '4.0_full_tcp_scan',
         'flags': ["-sT", "-T4", "-p-", "--open"]},
        {'name': '5.0_source_port_scan',
         'flags': ["-g", "53", "-T4", "-p-", "--open"]},
        {'name': '6.0_IPv6_scan',
         'flags': ["-6", "-T4", "-p-", "--open"]},
        {'name': '7.0_full_udp_scan',
         'flags': ["-sU", "-T4", "-p-", "--open"]},
        {'name': '8.0_full_tcp_service_scan',
         'flags': ["-sCV", "-T4", "-p-", "--open"]},
        {'name': '9.0_full_udp_service_scan',
         'flags': ["-sUCV", "-T4", "-p-", "--open"]},
        {'name': '10.0_closed_ports_scan',
         'flags': ["-dd", "T4", "-p-"]},
        {'name': '11.0_dead_tcp_scan',
         'flags': ["-sT", "-T4", "-p-", "--open"]}
    ]

    if not os.path.exists('results'):
            os.mkdir('results')

    if args.output:
        results_path = 'results/' + args.output[0]
    else:
        console.log("No output directory defined, defaulting to datetime for directory...")
        results_path = 'results/' + str(datetime.datetime.now())

    if not os.path.exists(results_path):
        console.log("Directory does not exist yet. Creating...")
        os.mkdir(results_path)

    try:
        sudo_password = input('Enter sudo password: ')
        scanner = NmapRunner()
        scan_targets = get_targets(args.targets, args)
        for scan in scans:
            console.log(f"Initialising {scan['name']}...")
            scan_path = results_path + "/" + scan['name']
            if not os.path.exists(scan_path):
                os.mkdir(scan_path)

            for host in scan_targets:
                ports_list = ','.join(set(discovered_ports))
                host_path = scan_path + "/" + host
            
                # Check if host has been scanned before
                if not os.path.exists(host_path + ".xml") or args.rescan:
                    stderr = scanner.scan(host=host, scan=scan, host_path=host_path, ports=ports_list, sudo=sudo_password)

                if os.path.exists(host_path + ".xml"):
                    with open(host_path + ".xml", 'r') as xml:
                        xml_data = xml.read()
                        try:
                            rundata, parsed = OutputParser.parse_nmap_xml(xml_data)
                            nmap_table = fill_simple_table(exec_data=rundata, parsed_xml=parsed)
                            console.print(nmap_table)
                            for entry in parsed:
                                for port in entry['ports']:
                                    discovered_ports.append(port['port_id'])
                        except ParseError:
                            console.log(f'XML file for {host} found but was empty. Scan was most likely interrupted.')
                        except Exception as e:
                            console.log(f'XML file for {host} found but {e}')
                else:
                    console.log(f'XML file for {host} not found! Something went wrong with the scan output')
    except ValueError:
        logging.exception("There was an error")
        sys.exit(100)
    except KeyboardInterrupt:
        console.log("Scan interrupted, exiting...")
        pass
    sys.exit(0)
