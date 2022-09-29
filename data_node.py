from dataclasses import dataclass, asdict


@dataclass(init=False)
class Node:
    frame_number: int
    len_frame_pcap: int
    len_frame_medium: int
    frame_type: str
    src_mac: str  # placeholder
    dst_mac: str  # placeholder

    other_attributes = {}  # placeholder
    hexa_frame = str

    @staticmethod
    def return_dict(node) -> dict:
        new_dict = {"frame_number": node.frame_number, "len_frame_pcap": node.len_frame_pcap,
                    "len_frame_medium": node.len_frame_medium, "frame_type": node.frame_type, 'src_mac': node.src_mac,
                    'dst_mac': node.dst_mac, "hexa_frame": node.hexa_frame}

        return new_dict
