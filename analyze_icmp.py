import txt_file_loader
import util
import data_node
import ethernet_analyzer
import consts


class AnalyzeIcmp():
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

    def process_icmp_type(self, node):
        hexadecimal_icmp = node.raw_hexa_frame[consts.ICMP_TYPE_START:consts.ICMP_TYPE_END]
        decimal_icmp = util.convert_to_decimal(hexadecimal_icmp)
        icmp_type = self.txt_loader.icmp_types.get(str(decimal_icmp))
        node.other_attributes["icmp_type"] = icmp_type

    def _start(self):
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

    def find_comms(self):
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
                elif util.check_if_partial_comm(current_node, self.analyzed_nodes[j]):
                    self.partial_comms.append(current_node)
                    current_node = self.analyzed_nodes[j]
            if found_comm:
                communication.insert(0, start_node)
                self.complete_comms.append(communication)
                src_ip = str(start_node.other_attributes.get("src_ip"))
                dst_ip = str(start_node.other_attributes.get("dst_ip"))
                self.checked_ips[src_ip + dst_ip] = True
                self.checked_ips[dst_ip + src_ip] = True

        print('test')
        models = {node.frame_number for node in self.partial_comms}
        print(len(self.partial_comms))
        print(len(models))