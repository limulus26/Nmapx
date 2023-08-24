import shutil
import subprocess
import os
from typing import Any, List

from xml_parser import OutputParser

class NmapRunner:

    def __init__(self):
        """
        Create a Nmap executor
        """
        self.nmap_report_file = None
        found_sudo = shutil.which('sudo', mode=os.F_OK | os.X_OK)
        if not found_sudo:
            raise ValueError(f"SUDO is missing")
        self.sudo = found_sudo
        found_nmap = shutil.which('nmap', mode=os.F_OK | os.X_OK)
        if not found_nmap:
            raise ValueError(f"NMAP is missing")
        self.nmap = found_nmap

    def scan(
            self,
            *,
            host: str,
            sudo: bool = True,
            scan: dict[str, Any],
            host_path: str,
            ports: str
    ):
        command = ["nmap"]
        if sudo:
            command.insert(0, self.sudo)
        command.extend(["-oA", host_path])
        command.extend(scan['flags'])
        if command[-1] == "-p":
            if not len(ports) == 0:
                command.append(ports)
            else:
                print("No ports discovered. Skipping service scan...")
                return 
        command.append(host)
        print(f"Executing '{command}'...")
        completed = subprocess.run(
            command,
            capture_output=True,
            shell=False,
            check=True
        )
        completed.check_returncode()
        # args, data = OutputParser.parse_nmap_xml(completed.stdout.decode('utf-8'))
        return completed.stderr