import shutil
import subprocess
import os

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
            hosts: str,
            sudo: bool = True,
            flags: str,
            ports: str
    ):
        command = ["nmap"]
        if sudo:
            command.insert(0, self.sudo)
        command.extend(flags)
        if command[-1] == "-p":
            command.append(ports)
        command.append(hosts)
        completed = subprocess.run(
            command,
            capture_output=True,
            shell=False,
            check=True
        )
        completed.check_returncode()
        # args, data = OutputParser.parse_nmap_xml(completed.stdout.decode('utf-8'))
        return completed.stderr