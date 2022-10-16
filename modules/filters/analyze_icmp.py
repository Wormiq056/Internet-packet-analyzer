from typing import List

from modules import txt_file_loader
from util import util, consts
from model import packet_frame
from modules.analyzers import ethernet_analyzer
import ruamel.yaml
from collections import defaultdict
import itertools


class AnalyzeIcmp:
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
    nodes_by_id = defaultdict(list)
    merged_fragmented_nodes = []

    def __init__(self, packets: List[str], file_name: str) -> None:
        self.packets = packets
        self.file_name = file_name
        self.txt_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.txt_loader)

        self._start()

    def _start(self) -> None:
        """
        this method filters packets for ICMP packets
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
                if node.other_attributes.get("protocol") == "ICMP":
                    self.analyzed_nodes.append(node)
        self.sort_by_id()
        self.find_comms()
        self.output()

    def sort_by_id(self) -> None:
        """
        this method merges ip fragments based on id
        """
        for node in self.analyzed_nodes:
            self.nodes_by_id[node.other_attributes.get("id")].append(node)
        self.merged_fragmented_nodes = list(self.nodes_by_id.values())

    def find_comms(self) -> None:
        """
        this method finds icmp request reply pairs for communications
        """
        pair_dict = {}
        for merged_packet in self.merged_fragmented_nodes:

            if merged_packet[-1].other_attributes.get("icmp_type") != "ECHO REQUEST" and merged_packet[-1] \
                    .other_attributes.get("icmp_type") != "ECHO REPLY":
                self.partial_comms.append(merged_packet)
                continue
            packet_id = merged_packet[-1].raw_hexa_frame[consts.ICMP_PACKET_ID_START:consts.ICMP_PACKET_ID_END]
            if merged_packet[-1].other_attributes.get("icmp_type") == "ECHO REPLY":
                request = pair_dict.get(packet_id)
                if request:
                    self.complete_comms.append([request, merged_packet])
                    pair_dict[packet_id] = None
                else:
                    self.partial_comms.append(merged_packet)
            else:
                pair_dict[packet_id] = merged_packet

    def output(self) -> None:
        """
        method that outputs complete and partial communications into output_icmp.yaml
        """
        CS = ruamel.yaml.comments.CommentedSeq
        yaml = ruamel.yaml.YAML()
        yaml.indent(sequence=4, offset=2)
        complete_comm_list = []

        for comm_list in self.complete_comms:
            comm = list(itertools.chain(*comm_list))
            src_comm = comm[0].other_attributes.get("src_ip")
            dst_comm = comm[0].other_attributes.get("dst_ip")
            comm_CS = CS(node.return_dict() for node in comm)
            for i in range(len(comm_CS)):
                comm_CS.yaml_set_comment_before_after_key(i + 1, before='\n')
            dict_to_append = {"number_comm": self.number_complete_comm, "src_comm": src_comm, "dst_comm": dst_comm,
                              "packets": comm_CS}
            self.number_complete_comm += 1
            complete_comm_list.append(dict_to_append)

        output_dict = {'name': 'Matus Rusnak ID 116286', 'pcap_name': self.file_name, 'filter_name': 'ICMP',
                       'complete_comms': complete_comm_list}

        partial_list = []
        for node_list in self.partial_comms:
            partial_dict = {"number_comm": self.number_partial_comm, "packets": node_list[0].return_dict()}
            partial_list.append(partial_dict)
            self.number_partial_comm += 1

        partial_list_cs = CS(partial_list)
        for i in range(len(partial_list_cs)):
            partial_list_cs.yaml_set_comment_before_after_key(i + 1, before='\n')
        final_partial_dict = {"partial_comms": partial_list_cs}

        with open("./out/output_icmp.yaml", "w") as file:
            yaml.dump(output_dict, file)
            file.write('\n')
            yaml.dump(final_partial_dict, file)
