import data_node
import consts

"""
this file contains many helper functions that are general, meaning are used in multiple other modules
"""


def get_ip_adress(adress: str) -> str:
    """
    return IP address from mac address
    :param adress: address to be converted
    :return: correct IP address
    """

    bytes = ["".join(x) for x in zip(*[iter(adress)] * 2)]
    bytes = [int(x, 16) for x in bytes]
    return ".".join(str(x) for x in bytes)


def adjust_mac_adress(adress: str) -> str:
    """
     helper function that adjusts mac address for correct yaml output
    :param adress: address to be adjusted
    :return: correct format of address
    """

    result = ':'.join(adress[i:i + 2] for i in range(0, len(adress), 2))
    return result.upper()


def find_general_data(node: data_node.Node, packet: str, frame_number: int) -> None:
    """
    this helper method gives given node general packet information
    :param node: object to store data in
    :param packet: current packet for node
    :param frame_number: number of packet that is beeing analyzed
    """
    node.frame_number = frame_number
    node.src_mac = adjust_mac_adress(packet[consts.SRC_START:consts.SRC_END])
    node.dst_mac = adjust_mac_adress(packet[:consts.DST_END])
    node.raw_hexa_frame = packet
    if (len(packet) / 2) < 60:
        node.len_frame_medium = 64
        node.len_frame_pcap = int((len(packet) / 2))
    else:
        node.len_frame_pcap = int(len(packet) / 2)
        node.len_frame_medium = int(node.len_frame_pcap + 4)


def convert_to_decimal(hex: str) -> int:
    """
    simple helper function which converts hexadecimal number to a decimal
    :param hex: hexadecimal to be converted
    :return: decimal value
    """
    return int(hex, base=16)


def convert_decimal_to_binary(dec: int) -> bin:
    """
    simple helper function which converts decimal into a binary
    :param dec: decimal number to convert
    :return: input in binary
    """
    num_of_bits = 16
    return bin(dec)[2:].zfill(num_of_bits)


def convert_binary_todecimal(bin: bin) -> int:
    """
    function which converts binary to decimal
    :param bin: number to convert
    :return: decimal output
    """
    return int(bin, 2)


def find_frame_type(node: data_node.Node) -> None:
    """
    helper functions which finds correct frame time for given packet
    :param node: node which contains packet information
    """
    if int(node.raw_hexa_frame[consts.ETHERNET_START:consts.ETHERNET_END], base=16) > 1536:
        node.frame_type = 'ETHERNET II'
    else:
        if node.raw_hexa_frame[consts.IEEE_START:consts.IEEE_END].upper() == "FFFF":
            node.frame_type = "IEEE 802.3 RAW"

        elif node.raw_hexa_frame[consts.IEEE_START:consts.IEEE_END].upper() == "AAAA":
            node.frame_type = "IEEE 802.3 LLC & SNAP"
        else:
            node.frame_type = "IEEE 802.3 LLC"


def compare_ports(src_port: int, dst_port: int, node) -> bool:
    """
    not yet needed
    :param node1:
    :param node2:
    :return:
    """
    src_node = node.other_attributes.get("src_port")
    dst_node = node.other_attributes.get("dst_port")

    if src_port == dst_node and dst_port == src_node or src_port == src_node and dst_port == dst_node:
        return True
    return False


def check_next_comm(node1: data_node.Node, node2: data_node.Node) -> bool:
    src1 = node1.other_attributes.get("src_ip")
    dst1 = node1.other_attributes.get("dst_ip")
    src2 = node2.other_attributes.get("src_ip")
    dst2 = node2.other_attributes.get("dst_ip")
    if src1 == dst2 and dst1 == src2:
        return True
    else:
        return False


def check_if_partial_comm(node1: data_node.Node, node2: data_node.Node) -> bool:
    src1 = node1.other_attributes.get("src_ip")
    dst1 = node1.other_attributes.get("dst_ip")
    src2 = node2.other_attributes.get("src_ip")
    dst2 = node2.other_attributes.get("dst_ip")
    if src1 == src2 and dst1 == dst2:
        return True
    else:
        return False
