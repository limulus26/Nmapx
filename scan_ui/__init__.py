from rich.table import Table
from typing import Any
from xml_parser import NISTHTML

def create_scan_table(*, cli: str) -> Table:
    """
    Create a table for the CLI
    :param cli: Full Nmap arguments used on the run
    :return: Skeleton table, no data
    """
    nmap_table = Table(title=f"Nmap run info: {cli}")
    nmap_table.add_column("IP", justify="right", style="cyan", no_wrap=True)
    nmap_table.add_column("Protocol", justify="right", style="cyan", no_wrap=True)
    nmap_table.add_column("Port ID", justify="right", style="magenta", no_wrap=True)
    nmap_table.add_column("Service", justify="right", style="green")
    nmap_table.add_column("Scripts", justify="right", style="blue")
    nmap_table.add_column("Script Output", justify="right", style="yellow")
    return nmap_table

def fill_simple_table(*, exec_data: str, parsed_xml: list[dict[Any, Any]]) -> Table:
    """
    Convenience method to create a simple UI table with Nmap XML output
    :param  exec_data: Arguments and options used to run Nmap
    :param parsed_xml: Nmap data as a dictionary
    :return: Populated table
    """
    nmap_table = create_scan_table(cli=exec_data)
    for row_data in parsed_xml:
        address = row_data['address']
        ports = row_data['ports']
        for port_data in ports:
            nmap_table.add_row(
                address,
                port_data['protocol'],
                port_data['port_id'],
                f"{port_data['service_name']} {port_data['service_product']} {port_data['service_version']}",
                "\n".join(port_data['scripts']),
                "\n".join(port_data['script_outputs'])
            )
    return nmap_table