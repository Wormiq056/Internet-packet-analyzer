
from ruamel.yaml.scalarstring import LiteralScalarString

class Node:
    raw_hexa_frame: str
    frame_number: int
    len_frame_pcap: int
    len_frame_medium: int
    frame_type: str
    src_mac: str
    dst_mac: str

    hexa_frame = str

    def __init__(self):
        self.other_attributes ={}

    def _adjust_hexa_frame(self, hexa_frame: str) -> str:
        new_frame = ' '.join(hexa_frame[i:i + 2] for i in range(0, len(hexa_frame), 2))
        result_frame = '\n'.join(new_frame[i:i + 48] for i in range(0, len(new_frame), 48))
        result_frame+='\n'
        return LiteralScalarString(result_frame.upper())

    def return_dict(self) -> dict:
        new_dict = {"frame_number": self.frame_number, "len_frame_pcap": self.len_frame_pcap,
                    "len_frame_medium": self.len_frame_medium, "frame_type": self.frame_type, 'src_mac': self.src_mac,
                    'dst_mac': self.dst_mac}
        new_dict.update(self.other_attributes)
        new_dict["hexa_frame"] = self._adjust_hexa_frame(self.raw_hexa_frame)
        return new_dict
