import txt_file_loader
import consts


class IeeeAnalyzer:
    def __init__(self, txt_loader: txt_file_loader.TxtFileLoader) -> None:
        self.txt_loader = txt_loader

    def process_LLC_SNAP(self, node):
        pid_type = self.txt_loader.pid_types.get(node.raw_hexa_frame[consts.PID_START:consts.PID_END])
        node.other_attributes["pid"] = pid_type

    def process_LLC(self,node):
        sap_type = self.txt_loader.sap_types.get(node.raw_hexa_frame[consts.SAP_START:consts.SAP_END])
        node.other_attributes["sap"] = sap_type
