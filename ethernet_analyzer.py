import data_node
import util
import txt_file_loader
import consts


class EthernetAnalyzer:

    def __init__(self, txt_loader: txt_file_loader.TxtFileLoader) -> None:
        self.txt_loader = txt_loader

    def process_ethernet(self, node: data_node.Node) -> None:
        ether_type = str(
            self.txt_loader.ether_types.get(node.raw_hexa_frame[consts.ETHER_TYPE_START:consts.ETHER_TYPE_END].upper()))
        node.other_attributes["ether_type"] = ether_type

        if ether_type == "IPv4":
            self.process_ipv4(node)

        if ether_type == "ARP":
            self.process_arp(node)

    def process_arp(self, node: data_node.Node) -> None:
        arp_opcode = self.txt_loader.arp_types.get(node.raw_hexa_frame[consts.ARP_START:consts.ARP_END].upper())
        node.other_attributes["arp_opcode"] = arp_opcode
        node.other_attributes["src_ip"] = util.get_ip_adress(
            node.raw_hexa_frame[consts.ARP_SRC_START:consts.ARP_SRC_END])
        node.other_attributes["dst_ip"] = util.get_ip_adress(
            node.raw_hexa_frame[consts.ARP_DST_START:consts.ARP_DST_END])

    def process_ipv4(self, node: data_node.Node) -> None:
        node.other_attributes["src_ip"] = util.get_ip_adress(node.raw_hexa_frame[consts.IP_SRC_START:consts.IP_SRC_END])
        node.other_attributes["dst_ip"] = util.get_ip_adress(node.raw_hexa_frame[consts.IP_DST_START:consts.IP_DST_END])
