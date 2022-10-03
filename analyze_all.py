import ruamel.yaml
import util
import data_node
import ethernet_analyzer
import txt_file_loader



class AnalyzeAll:
    frame_number = 1
    finished_nodes = []

    def __init__(self, packets: list, file_name: str):
        self.packets = packets
        self.file_name = file_name
        self.file_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.file_loader)
        self._start()

    def _start(self) -> None:
        for packet in self.packets:
            node = util.find_general_data(packet, self.frame_number)
            util.find_frame_type(node)
            self.process_packet_by_frame(node)
            self.finished_nodes.append(node)
            self.frame_number += 1
        self._output()

    def process_packet_by_frame(self, node: data_node.Node) -> None:
        if node.frame_type == "ETHERNET II":
            self.ethernet_analyzer.process_ethernet(node)

    def _output(self):
        with open("output-all.yaml", "w") as file:
            file_dict = []
            for node in self.finished_nodes:
                node_dict = node.return_dict()
                file_dict.append(node_dict)
            yaml = ruamel.yaml.YAML()
            yaml.indent(sequence=4, offset=2)
            yaml.compact(seq_seq=False, seq_map=False)
            output_dict = {'name': "Matus Rusnak 116286", 'pcap_name': self.file_name, "packets": file_dict}
            yaml.dump(output_dict, file)

# class MyDumper(yaml.SafeDumper):
#     def write_line_break(self, data=None):
#         super().write_line_break(data)
#
#         if len(self.indents) == 1:
#             super().write_line_break()
#
#
# print(yaml.dump(data, Dumper=MyDumper, sort_keys=False))
