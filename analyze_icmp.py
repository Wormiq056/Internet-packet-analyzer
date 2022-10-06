import txt_file_loader
import util
import data_node
import ethernet_analyzer
import consts
import ruamel.yaml


class AnalyzeIcmp():
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

    def process_icmp_type(self, node: data_node.Node) -> None:
        """
        method that finds icmp type
        """
        hexadecimal_icmp = node.raw_hexa_frame[consts.ICMP_TYPE_START:consts.ICMP_TYPE_END]
        decimal_icmp = util.convert_to_decimal(hexadecimal_icmp)
        icmp_type = self.txt_loader.icmp_types.get(str(decimal_icmp))
        node.other_attributes["icmp_type"] = icmp_type

    def _start(self) -> None:
        """
        this method filters packets for ICMP packets

        """
        for packet in self.packets:
            node = data_node.Node()
            util.find_general_data(node, packet, self.frame_number)
            self.frame_number += 1
            util.find_frame_type(node)
            if node.frame_type == "ETHERNET II":
                self.ethernet_analyzer.process_ethernet(node)
                if node.other_attributes.get("protocol") == "ICMP":
                    self.process_icmp_type(node)
                    self.analyzed_nodes.append(node)

        self.find_comms()
        self.output()

    def find_comms(self) -> None:
        for i in range(len(self.analyzed_nodes)):
            found_comm = False
            communication = []
            start_node = self.analyzed_nodes[i]
            src_ip = str(start_node.other_attributes.get("src_ip"))
            dst_ip = str(start_node.other_attributes.get("dst_ip"))
            if self.checked_ips.get(src_ip + dst_ip) or self.checked_ips.get(dst_ip + src_ip):
                continue
            current_node = self.analyzed_nodes[i]
            for j in range(i + 1, len(self.analyzed_nodes)):
                if util.check_next_comm(current_node, self.analyzed_nodes[j]):
                    communication.append(self.analyzed_nodes[j])
                    found_comm = True
                    current_node = self.analyzed_nodes[j]
                elif util.check_if_partial_comm(current_node,
                                                self.analyzed_nodes[j]) and current_node not in self.partial_comms:
                    self.partial_comms.append(current_node)
                    current_node = self.analyzed_nodes[j]
            if found_comm:
                communication.insert(0, start_node)
                self.complete_comms.append(communication)
                src_ip = str(start_node.other_attributes.get("src_ip"))
                dst_ip = str(start_node.other_attributes.get("dst_ip"))
                self.checked_ips[src_ip + dst_ip] = True
                self.checked_ips[dst_ip + src_ip] = True

    def output(self) -> None:
        """
        method that outputs complete and partial communications into output_icmp.yaml
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

        output_dict = {'name': 'Matus Rusnak ID 116286', 'pcap_name': self.file_name, 'filter_name': 'ICMP',
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

        with open("output_icmp.yaml", "w") as file:
            yaml.dump(output_dict, file)
            file.write('\n')
            yaml.dump(final_partial_dict, file)
