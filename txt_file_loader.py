import json


class TxtFileLoader():
    ether_types: dict
    sap_types: dict
    pid_types: dict

    def __init__(self):
        all_data = self._load_file()
        self.ether_types = all_data["ether_types"][0]
        self.sap_types = all_data["sap_types"][0]
        self.pid_types = all_data["pid_types"][0]

    def _load_file(self):
        with open(".\Files-to-load\\type_data_file.txt", "r") as file:
            data = json.load(file)
            return data
