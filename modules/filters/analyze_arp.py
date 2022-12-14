from typing import List

from modules import txt_file_loader
from util import util, consts
from model import packet_frame
from modules.analyzers import ethernet_analyzer
import ruamel.yaml
from collections import defaultdict


class AnalyzeArp:
    """
    class that filter packets for arp packets and analyzes complete and partial communications
    """
    analyzed_nodes = []
    frame_number = 1
    number_complete_comm = 1
    number_partial_comm = 1
    complete_comms = []
    partial_comms = []
    ip_bucket = defaultdict(list)

    def __init__(self, packets: List[str], file_name: str) -> None:
        self.packets = packets
        self.file_name = file_name
        self.txt_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.txt_loader)

        self._start()

    def _start(self) -> None:
        """
        method that filters arp packets
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
                if node.other_attributes.get("ether_type") == "ARP":
                    self.analyzed_nodes.append(node)

        self._sort_by_ip()
        self._find_communications()
        self._check_requests()
        self.output()

    def _check_requests(self) -> None:
        """
        this method checks if reply has not been called to ip that previous request was called
        """
        for node in self.partial_comms:
            for comm in self.complete_comms:
                if comm[-1].other_attributes.get("src_ip") == node.other_attributes.get("dst_ip"):
                    if comm[-1].frame_number > node.frame_number:
                        comm.append(node)
                        comm.sort(key=lambda x: x.frame_number)
                        self.partial_comms.remove(node)
        self.partial_comms.sort(key=lambda x: x.frame_number)

    def _sort_by_ip(self) -> None:
        """
        method that sorts packets by their ip address and checks if they are already partial
        """
        for node in self.analyzed_nodes:
            if node.other_attributes.get("src_ip") == node.other_attributes.get("dst_ip"):
                self.partial_comms.append(node)
                continue
            elif node.other_attributes.get("src_ip") == "0.0.0.0":
                self.partial_comms.append(node)
                continue
            key = tuple(sorted([node.other_attributes.get("src_ip"), node.other_attributes.get("dst_ip")]))
            self.ip_bucket[key].append(node)

    def _find_communications(self) -> None:
        """
        method that sends list of packets filtered by IP to be processed
        """
        for ip_bucket in self.ip_bucket.values():
            self._process_bucket(ip_bucket)

    def _process_bucket(self, bucket: List[packet_frame.Node]) -> None:
        """
        method that finds complete and partial communications by looping through filtered packets
        states indicate what next packet I am looking for

        state 0 = finding request
        state 1 = found request finding reply
        """
        current_state = 0
        comm = []

        for node in bucket:
            if current_state == 0:
                if node.other_attributes.get("arp_opcode") == "REPLY":
                    self.partial_comms.append(node)
                else:
                    comm.append(node)
                    current_state = 1
            elif current_state == 1:
                if node.other_attributes.get("arp_opcode") == "REPLY":
                    comm.append(node)
                    self.complete_comms.append(comm)
                    comm = []
                    current_state = 0
                else:
                    comm.append(node)
        if comm:
            for node in comm:
                self.partial_comms.append(node)

    def output(self) -> None:
        """
        method that outputs complete and partial communications into output_arp.yaml
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
                              "packet": comm_CS}
            self.number_complete_comm += 1
            complete_comm_list.append(dict_to_append)

        output_dict = {'name': 'Matus Rusnak ID 116286', 'pcap_name': self.file_name, 'filter_name': 'ARP',
                       'complete_comms': complete_comm_list}

        partial_list = []
        for node in self.partial_comms:
            partial_dict = {"number_comm": self.number_partial_comm, "packets": node.return_dict()}
            partial_list.append(partial_dict)
            self.number_partial_comm += 1

        partial_list_cs = CS(partial_list)
        for i in range(len(partial_list_cs)):
            partial_list_cs.yaml_set_comment_before_after_key(i + 1, before='\n')
        final_partial_dict = {"partial_comms": partial_list_cs}

        with open("./out/output_arp.yaml", "w") as file:
            yaml.dump(output_dict, file)
            file.write('\n')
            yaml.dump(final_partial_dict, file)
