import txt_file_loader
import util
import data_node
import ethernet_analyzer
import consts


class AnalyzeTcp:
    analyzed_nodes = []
    frame_number = 1
    number_complete_comm = 1
    number_partial_comm = 1
    complete_comms = []
    partial_comms = []
    checked_ips = {}

    def __init__(self, packets: list, file_name: str, protocol) -> None:
        self.packets = packets
        self.file_name = file_name
        self.txt_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.txt_loader)
        self.protocol = protocol
        self._start()

    def _start(self):
        for packet in self.packets:
            node = data_node.Node()
            util.find_general_data(node, packet, self.frame_number)
            self.frame_number += 1
            util.find_frame_type(node)
            if node.frame_type == "ETHERNET II":
                self.ethernet_analyzer.process_ethernet(node)
                if node.other_attributes.get("protocol") == "TCP" and node.other_attributes.get(
                        "app_protocol") == self.protocol:
                    self.analyzed_nodes.append(node)

