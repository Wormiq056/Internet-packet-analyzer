from typing import List

import ruamel.yaml
from util import util, consts
from model import packet_frame
from modules.analyzers import IEEE_analyzer, ethernet_analyzer
from modules import txt_file_loader


class AnalyzeAll:
    """
    class that handles analyzation of all packets and writing them to output-all.yaml
    """
    frame_number = 1
    finished_nodes = []
    unique_ipv4_ips = {}

    def __init__(self, packets: List[str], file_name: str):
        self.packets = packets
        self.file_name = file_name
        self.file_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.file_loader)
        self.ieee_analyzer = IEEE_analyzer.IeeeAnalyzer(self.file_loader)
        self._start()

    def _start(self) -> None:
        """
        this method finds general information of packets and its frame time
        """
        for packet in self.packets:
            node = packet_frame.Node()
            if packet[:consts.DST_END].upper() == "01000C000000":
                packet = packet[52:]
            util.find_general_data(node, packet, self.frame_number)
            self.frame_number += 1
            util.find_frame_type(node)
            self.process_packet_by_frame(node)
            self.finished_nodes.append(node)

        self._analyze()
        self._output()

    def _analyze(self) -> None:
        """
        this method analyzes all IPv4 packets for statistics
        """
        for node in self.finished_nodes:
            if node.other_attributes.get("ether_type") == "IPv4":
                if self.unique_ipv4_ips.get(node.other_attributes.get("src_ip")) is None:
                    self.unique_ipv4_ips[node.other_attributes.get("src_ip")] = 1
                else:
                    self.unique_ipv4_ips[node.other_attributes.get("src_ip")] += 1

    def process_packet_by_frame(self, node: packet_frame.Node) -> None:
        """
        this method chooses which analyzer should be called based on frame type
        """
        if node.frame_type == "ETHERNET II":
            self.ethernet_analyzer.process_ethernet(node)
        elif node.frame_type == "IEEE 802.3 LLC & SNAP":
            self.ieee_analyzer.process_LLC_SNAP(node)
        elif node.frame_type == "IEEE 802.3 LLC":
            self.ieee_analyzer.process_LLC(node)

    def _output(self) -> None:
        """
        this method writes packet information and ip statistics to yaml file
        """

        CS = ruamel.yaml.comments.CommentedSeq
        yaml = ruamel.yaml.YAML()
        yaml.indent(sequence=4, offset=2)

        file_list = []
        for node in self.finished_nodes:
            node_dict = node.return_dict()
            file_list.append(node_dict)
        packets_dict = CS(file_list)
        for i in range(len(packets_dict)):
            packets_dict.yaml_set_comment_before_after_key(i + 1, before='\n')
        output_dict = {'name': "Matus Rusnak ID 116286", 'pcap_name': self.file_name, "packets": packets_dict}

        statistics_list = []
        for k, v in self.unique_ipv4_ips.items():
            statistics_list.append({"node": k, "number_of_sent_packets": v})
        statistics_dict = CS(statistics_list)
        for i in range(len(statistics_dict)):
            statistics_dict.yaml_set_comment_before_after_key(i + 1, before='\n')

        max_keys = [key for key, value in self.unique_ipv4_ips.items() if
                    value == max(self.unique_ipv4_ips.values())]

        with open("./out/output-all.yaml", "w") as file:
            yaml.dump(output_dict, file)
            file.write('\n')
            yaml.dump({"ipv4_senders": statistics_dict}, file)
            file.write('\n')
            yaml.dump({"max_send_packets_by": max_keys}, file)
