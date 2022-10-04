import data_node
import consts


def get_ip_adress(adress: str) -> str:
    bytes = ["".join(x) for x in zip(*[iter(adress)] * 2)]
    bytes = [int(x, 16) for x in bytes]
    return ".".join(str(x) for x in bytes)


def adjust_mac_adress(adress: str) -> str:
    result = ':'.join(adress[i:i + 2] for i in range(0, len(adress), 2))
    return result.upper()


def find_general_data(packet: str, frame_number: int) -> data_node.Node:
    node = data_node.Node()
    node.frame_number = frame_number
    node.src_mac = adjust_mac_adress(packet[consts.SRC_START:consts.SRC_END])
    node.dst_mac = adjust_mac_adress(packet[:consts.DST_END])
    node.raw_hexa_frame = packet
    if (len(packet) / 2) < 60:
        node.len_frame_medium = 64
        node.len_frame_pcap = 60
    else:
        node.len_frame_pcap = int(len(packet) / 2)
        node.len_frame_medium = int(node.len_frame_pcap + 4)

    return node

def convert_to_decimal(hex: str)-> int:
    return int(hex, base=16)

def find_frame_type(node: data_node.Node) -> None:
    if int(node.raw_hexa_frame[consts.ETHERNET_START:consts.ETHERNET_END], base=16) > 1536:
        node.frame_type = 'ETHERNET II'
    else:
        if node.raw_hexa_frame[consts.IEEE_START:consts.IEEE_END].upper() == "FFFF":
            node.frame_type = "IEEE 802.3 RAW"

        elif node.raw_hexa_frame[consts.IEEE_START:consts.IEEE_END].upper() == "AAAA":
            node.frame_type = "IEEE 802.3 LLC & SNAP"
        else:
            node.frame_type = "IEEE 802.3 LLC"
