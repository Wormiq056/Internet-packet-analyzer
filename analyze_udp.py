import txt_file_loader
import util
import data_node
import ethernet_analyzer
import consts


class AnalyzeUdp:
    """
    class that filter all packets other than ICMP protocol packets
    and finds complete communications and partial communications
    """
    analyzed_nodes = []
    frame_number = 1
    number_complete_comm = 1
    number_partial_comm = 1
    complete_comms = []
    partial_comms = []
    checked_ips = {}

    def __init__(self, packets: list, file_name: str) -> None:
        self.packets = packets
        self.file_name = file_name
        self.txt_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.txt_loader)

        self._start()

    def _start(self) -> None:
        """
        mathod that filters node for protocol UDP and app protocol TFTP
        """
        for packet in self.packets:
            node = data_node.Node()
            util.find_general_data(node, packet, self.frame_number)
            self.frame_number += 1
            util.find_frame_type(node)
            if node.frame_type == "ETHERNET II":
                self.ethernet_analyzer.process_ethernet(node)
                if node.other_attributes.get("protocol") == "UDP" and node.other_attributes.get(
                        "app_protocol") == "TFTP":
                    self.analyzed_nodes.append(node)


