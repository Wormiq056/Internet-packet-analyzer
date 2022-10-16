from typing import List

from modules import txt_file_loader
from util import util, consts
from model import packet_frame
from modules.analyzers import ethernet_analyzer
import ruamel.yaml


class AnalyzeUdp:
    """
    class that filter all packets other than UDP protocol packets
    and finds complete communications
    """
    tftp_nodes = []
    udp_nodes = []
    frame_number = 1
    number_complete_comm = 1
    complete_comms = []

    def __init__(self, packets: List[str], file_name: str) -> None:
        self.packets = packets
        self.file_name = file_name
        self.txt_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.txt_loader)

        self._start()

    def _start(self) -> None:
        """
        method that filters node for protocol UDP and app protocol TFTP
        """
        for packet in self.packets:
            node = packet_frame.Node()
            if packet[:consts.DST_END].upper() == "01000C000000":
                packet = packet[52:]
            util.find_general_data(node, packet, self.frame_number)
            self.frame_number += 1
            util.find_frame_type(node)
            if node.frame_type == "ETHERNET II":
                self.ethernet_analyzer.process_ethernet(node)
                if node.other_attributes.get("protocol") == "UDP":
                    if node.other_attributes.get("app_protocol") == "TFTP":
                        self.tftp_nodes.append(node)
                    else:
                        self.udp_nodes.append(node)

        self.find_communications()

        self.output()

    def find_start_of_comm(self) -> packet_frame.Node:
        """
        helper method that finds start of communication
        :return: node which starts communication
        """
        for node in self.udp_nodes:
            if node.other_attributes.get("dst_port") == 69:
                return node

    def find_dst_port(self, src_port: int) -> int:
        """
        helper method that finds dst port for given src port
        :param src_port: port of start node
        :return: dst port
        """
        for node in self.udp_nodes:
            if node.other_attributes.get("dst_port") == src_port:
                return node.other_attributes.get("src_port")

    def find_communications(self) -> None:
        """
        method that finds communication in filtered nodes
        """
        for start_node in self.tftp_nodes:
            src_port = start_node.other_attributes.get("src_port")
            dst_port = self.find_dst_port(src_port)
            communication = []
            if dst_port is None:
                self.complete_comms.append(communication)
                continue
            for node in self.udp_nodes:
                if util.compare_ports(src_port, dst_port, node):
                    communication.append(node)
                    src_port = node.other_attributes.get("src_port")
                    dst_port = node.other_attributes.get("dst_port")

            communication.insert(0, start_node)
            self.complete_comms.append(communication)

    def output(self) -> None:
        """
        method that outputs complete and partial communications into output_udp.yaml
        """
        CS = ruamel.yaml.comments.CommentedSeq
        yaml = ruamel.yaml.YAML()
        yaml.indent(sequence=4, offset=2)
        complete_comm_list = []

        for comm in self.complete_comms:
            src_comm = comm[0].other_attributes.get("src_ip")
            dst_comm = comm[0].other_attributes.get("dst_ip")
            comm_CS = CS(node.return_dict() for node in comm)
            for i in range(len(comm_CS)):
                comm_CS.yaml_set_comment_before_after_key(i + 1, before='\n')
            dict_to_append = {"number_comm": self.number_complete_comm, "src_comm": src_comm, "dst_comm": dst_comm,
                              "packets": comm_CS}
            self.number_complete_comm += 1
            complete_comm_list.append(dict_to_append)

        output_dict = {'name': 'Matus Rusnak ID 116286', 'pcap_name': self.file_name, 'filter_name': 'UDP',
                       'complete_comms': complete_comm_list}

        with open("./out/output_udp.yaml", "w") as file:
            yaml.dump(output_dict, file)
