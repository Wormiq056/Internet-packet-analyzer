import sys


from ruamel.yaml.main import round_trip_dump as yaml_dump

import data_node

ETHER_TYPE_VALUES = ['0200', '0201', '0800', '0801', '0805', '0806', '8035', '809B', '80F3', '8100', '8137',
                     '86DD', '880B', '8847', '8848', '8863', '8864']
INDENTATION = 10

class AnalyzeAll:
    frame_number = 1
    finished_nodes = []

    def __init__(self, packets: list):
        self.packets = packets
        self._start()

    def _start(self) -> None:
        for packet in self.packets:
            new_node = data_node.Node()
            self._get_general_data(packet, new_node)
            self._get_frame_type(new_node)
            self.finished_nodes.append(new_node)
            self.frame_number += 1
        self._output()

    def _get_frame_type(self, node) -> None:
        if node.hexa_frame[24:28].upper() in ETHER_TYPE_VALUES:
            node.frame_type = 'ETHERNET II'
        else:
            if node.hexa_frame[28:32].upper() == "FFFF":
                node.frame_type = "IEEE 802.3 RAW"
            else:
                node.frame_type = "IEEE 802.3 LLC"

    def _get_general_data(self, packet, new_node):
        new_node.frame_number = self.frame_number
        new_node.src_mac = packet[12:24]
        new_node.dst_mac = packet[:12]
        new_node.hexa_frame = packet
        if len(packet) / 2 < 60:
            new_node.len_frame_medium = 64
        else:
            new_node.len_frame_medium = len(packet) / 2
        new_node.len_frame_pcap = new_node.len_frame_medium - 4


    def _output(self):
        with open("output-all.yaml","w") as file:

            for i in range(len(self.finished_nodes)):
                #print(self.finished_nodes[i].frame_number)
                node_dict = self.finished_nodes[i].return_dict(self.finished_nodes[i])

                yaml_dump(node_dict,file)
                #file.write(yaml.dump(node_dict,indent = INDENTATION))
