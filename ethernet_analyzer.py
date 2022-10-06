import data_node
import util
import txt_file_loader
import consts


class EthernetAnalyzer:
    """
    class that is called when ETHERNET II packet needs to be analyzed
    """

    def __init__(self, txt_loader: txt_file_loader.TxtFileLoader) -> None:
        self.txt_loader = txt_loader

    def process_ethernet(self, node: data_node.Node) -> None:
        """
        this method finds ethernet type for given packet
        """
        ether_type = str(
            self.txt_loader.ether_types.get(node.raw_hexa_frame[consts.ETHER_TYPE_START:consts.ETHER_TYPE_END].upper()))
        node.other_attributes["ether_type"] = ether_type

        if ether_type == "IPv4":
            self.process_ipv4(node)

        if ether_type == "ARP":
            self.process_arp(node)

    def process_arp(self, node: data_node.Node) -> None:
        """
        this method find arp opcode if ethernet type is ARP
        """
        arp_opcode = self.txt_loader.arp_types.get(node.raw_hexa_frame[consts.ARP_START:consts.ARP_END].upper())
        node.other_attributes["arp_opcode"] = arp_opcode
        node.other_attributes["src_ip"] = util.get_ip_adress(
            node.raw_hexa_frame[consts.ARP_SRC_START:consts.ARP_SRC_END])
        node.other_attributes["dst_ip"] = util.get_ip_adress(
            node.raw_hexa_frame[consts.ARP_DST_START:consts.ARP_DST_END])

    def process_tcp_udp(self, node: data_node.Node) -> None:
        """
        this methods finds src and dst ports if packet protol is TCP or UDP
        """
        src_port = util.convert_to_decimal(node.raw_hexa_frame[consts.SRC_PORT_START:consts.SRC_PORT_END])
        dst_port = util.convert_to_decimal(node.raw_hexa_frame[consts.DST_PORT_START:consts.DST_PORT_END])
        node.other_attributes["src_port"] = src_port
        node.other_attributes["dst_port"] = dst_port

        if self.txt_loader.tcp_upd_ports.get(str(src_port)) is not None:
            node.other_attributes["app_protocol"] = self.txt_loader.tcp_upd_ports.get(str(src_port))
        if self.txt_loader.tcp_upd_ports.get(str(dst_port)) is not None:
            node.other_attributes["app_protocol"] = self.txt_loader.tcp_upd_ports.get(str(dst_port))

    def process_ipv4(self, node: data_node.Node) -> None:
        """
        this method finds src IP, dst IP and IPv4 protocol if packet ethernet type is IPv4
        """
        node.other_attributes["src_ip"] = util.get_ip_adress(node.raw_hexa_frame[consts.IP_SRC_START:consts.IP_SRC_END])
        node.other_attributes["dst_ip"] = util.get_ip_adress(node.raw_hexa_frame[consts.IP_DST_START:consts.IP_DST_END])
        ipv4_protocol = self.txt_loader.ipv4_protocols.get(
            node.raw_hexa_frame[consts.IPV4_PROTOCOL_START:consts.IPV4_PROTOCOL_END])
        node.other_attributes["protocol"] = ipv4_protocol

        if ipv4_protocol == "TCP" or ipv4_protocol == "UDP":
            self.process_tcp_udp(node)
