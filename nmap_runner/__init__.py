import shutil
import subprocess
import os
import time
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
            sudo: str,
            scan: dict[str, Any],
            host_path: str,
            ports: str,
            timeout: int
    ):
        command = ["nmap"]
        
        command.extend(["-oA", host_path])
        command.extend(scan['flags'])
        if command[-1] == "-p":
            if not len(ports) == 0:
                command.append(ports)
            else:
                print("No ports discovered. Skipping service scan...")
                return 
        command.append(host)
        if sudo:
            sudoCommand = "sudo -S"
            command = sudoCommand.split() + command
            sudo_password = bytes(sudo, 'utf-8')
        print(f"Executing '{' '.join(command)}'...")
        try:
            completed = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            start_time = time.time()
            completed.stdin.write(sudo_password)
            completed.stdin.close()
            while completed.poll() is None:
                elapsed_time = time.time() - start_time
                print(f"\r[{float(elapsed_time):.2f}/{timeout}s]", end="")
                time.sleep(0.1)
                if elapsed_time >= timeout:
                    completed.kill()
                    raise Exception("Scan took longer than 5 minutes. Something's probably stuck. Skipping...")   
                time.sleep(1)
        except KeyboardInterrupt as e:
            raise KeyboardInterrupt
        except Exception as e:
            print(e)
        except:
            print("An unknown error occurred.")

        return 'Standard error placeholder.'