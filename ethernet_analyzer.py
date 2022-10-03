import data_node
import util
class EthernetAnalyzer:

    @staticmethod
    def process_ethernet(node: data_node.Node) -> None:
        if node.raw_hexa_frame[28:32] == "0800":
            node.other_attributes["ether_type"] = "IPv4"
            #self.process_ipv4(node)
        elif node.raw_hexa_frame[28:32] == "86DD":
            node.other_attributes["ether_type"] = "IPv6"
        elif node.raw_hexa_frame[28:32] == "0806":
            node.other_attributes["ether_type"] = "ARP"




    def process_ipv4(self,node: data_node.Node) -> None:
        node.other_attributes["src_ip"] = util.get_ip_adress(node.hexa_frame[12:24])
        node.other_attributes["dst_ip"] = util.get_ip_adress(node.hexa_frame[:12])
        return None