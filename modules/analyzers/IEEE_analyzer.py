from modules import txt_file_loader
from util import consts
from model import packet_frame


class IeeeAnalyzer:
    """
    class that is called when frame type is IEEE
    it finds all necessary information for that packet
    """

    def __init__(self, txt_loader: txt_file_loader.TxtFileLoader) -> None:
        self.txt_loader = txt_loader

    def process_LLC_SNAP(self, node: packet_frame.Node) -> None:
        """
        method that finds pid for IEEE LLC & SNAP packet
        """
        pid_type = self.txt_loader.pid_types.get(node.raw_hexa_frame[consts.PID_START:consts.PID_END].upper())
        if pid_type:
            node.other_attributes["pid"] = pid_type

    def process_LLC(self, node: packet_frame.Node) -> None:
        """
        method that finds sap for IEEE LLC packet
        """
        sap_type = self.txt_loader.sap_types.get(node.raw_hexa_frame[consts.SAP_START:consts.SAP_END].upper())
        if sap_type:
            node.other_attributes["sap"] = sap_type
