import json


class TxtFileLoader():
    ether_types: dict
    sap_types: dict
    pid_types: dict
    arp_types: dict
    ipv4_protocols: dict
    tcp_upd_ports : dict
    icmp_types: dict

    def __init__(self):
        all_data = self._load_file()
        self.ether_types = all_data["ether_types"][0]
        self.sap_types = all_data["sap_types"][0]
        self.pid_types = all_data["pid_types"][0]
        self.arp_types = all_data["arp_types"][0]
        self.ipv4_protocols = all_data["ipv4_protocols"][0]
        self.tcp_upd_ports = all_data["tcp_udp_ports"][0]
        self.icmp_types = all_data["icmp_types"][0]

    def _load_file(self):
        with open(".\Files-to-load\\type_data_file.txt", "r") as file:
            data = json.load(file)
            return data
