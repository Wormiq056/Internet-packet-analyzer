from modules import txt_file_loader
from util import util, consts
from model import packet_frame
from modules.analyzers import ethernet_analyzer
from collections import defaultdict
import ruamel.yaml


class AnalyzeTcp:
    """
     class that filter all packets other than TCP protocol packets
    and finds complete communications and partial communications for given protocol
    """
    analyzed_nodes = []
    frame_number = 1
    number_complete_comm = 1
    number_partial_comm = 1
    complete_comms = []
    partial_comms = []
    ip_buckets = defaultdict(list)

    def __init__(self, packets: list, file_name: str, protocol: str) -> None:
        self.packets = packets
        self.file_name = file_name
        self.txt_loader = txt_file_loader.TxtFileLoader()
        self.ethernet_analyzer = ethernet_analyzer.EthernetAnalyzer(self.txt_loader)
        self.protocol = protocol
        self._start()

    def _start(self) -> None:
        """
        method that filters packets for TCP

        """
        for packet in self.packets:
            node = packet_frame.Node()
            if packet[:consts.DST_END].upper() == "01000C000000":
                packet = packet[52:]
            util.find_general_data(node, packet, self.frame_number)
            self.frame_number += 1
            util.find_frame_type(node)
            if node.frame_type == "ETHERNET II":
                self.ethernet_analyzer.process_ethernet(node)
                if node.other_attributes.get("protocol") == "TCP" and node.other_attributes.get(
                        "app_protocol") == self.protocol:
                    self.analyzed_nodes.append(node)
        self._sort_by_ip()
        self._find_communications()
        self.output()

    def _sort_by_ip(self) -> None:
        """
        method that sorts filtered packets by ip addresses and ports into a list
        """
        for node in self.analyzed_nodes:
            key = tuple(sorted([node.other_attributes.get("dst_ip"),
                                node.other_attributes.get("src_ip"),
                                str(node.other_attributes.get("dst_port")),
                                str(node.other_attributes.get("src_port"))]))
            self.ip_buckets[key].append(node)

    def _find_communications(self) -> None:
        """
        method that sends sorted packets by ip and ports to be processed
        """
        for ip_port_bucket in self.ip_buckets.values():
            self._process_bucket(ip_port_bucket)

    def _return_flags(self, bits: bin) -> list:
        """
        helper method which returns flags for tcp packet
        :param bits: flag in binary
        :return: list of found flags
        """
        return_list = []
        if bits[1] == '1':
            return_list.append("ACK")
        if bits[4] == '1':
            return_list.append("SYN")
        if bits[5] == '1':
            return_list.append("FIN")
        return return_list

    def _process_bucket(self, bucket):
        """
        this method analyzes packets for complete and partial communication
        if works based on states that are changed by flags of packet
        states:

        state 0 = finding syn
        state 1 =  finding syn ack or syn
        state 2 = found syn ack finding ack
        state 3 = found syn finding ack
        state 4 = found syn syn ack finding ack
        state 6 = connect established
        """
        current_state = 0
        comm = []
        for packet in bucket:
            flags = self._return_flags(util.convert_decimal_to_binary(
                util.convert_to_decimal(packet.raw_hexa_frame[consts.TCP_FLAGS_START:consts.TCP_FLAGS_END]))[10:])
            if current_state == 0:
                if flags != ["SYN"]:
                    comm.append(packet)
                else:
                    self.partial_comms.append(comm)
                    comm = [packet]
                    current_state = 1
            elif current_state == 1:
                if flags == ["SYN"]:
                    current_state = 3
                    comm.append(packet)
                elif flags == ["ACK", "SYN"]:
                    current_state = 2
                    comm.append(packet)
                else:
                    current_state = 0
                    comm.append(packet)
                    self.partial_comms.append(comm)
                    comm = []
            elif current_state == 2:
                if flags == ["ACK"]:
                    comm.append(packet)
                    current_state = 6
                elif flags == ["SYN"]:
                    current_state = 1
                    self.partial_comms.append(comm)
                    comm = [packet]
                else:
                    current_state = 0
                    comm.append(packet)
                    self.partial_comms.append(comm)
                    comm = []
            elif current_state == 3:
                if flags == ["ACK"]:
                    current_state = 4
                    comm.append(packet)
                elif flags == ["SYN"]:
                    current_state = 1
                    self.partial_comms.append(comm)
                    comm = [packet]
                else:
                    current_state = 0
                    comm.append(packet)
                    self.partial_comms.append(comm)
                    comm = []
            elif current_state == 4:
                if flags == ["ACK"]:
                    current_state = 6
                    comm.append(packet)
                elif flags == ["SYN"]:
                    current_state = 1
                    self.partial_comms.append(comm)
                    comm = [packet]
                else:
                    current_state = 0
                    comm.append(packet)
                    self.partial_comms.append(comm)
                    comm = []
            elif current_state == 6:
                if flags == ["FIN"]:
                    current_state = 0
                    comm.append(packet)
                    self.complete_comms.append(comm)
                    comm = []
                elif flags == ["ACK", "FIN"]:
                    current_state = 0
                    comm.append(packet)
                    self.complete_comms.append(comm)
                    comm = []
                elif flags == ["SYN"]:
                    current_state = 1
                    self.partial_comms.append(comm)
                    comm = [packet]
                else:
                    current_state = 6
                    comm.append(packet)
        if current_state == 0 or current_state == 6:
            self.partial_comms.append(comm)

    def output(self) -> None:
        """
        method that outputs complete and partial communications into output_tcp.yaml
        """
        CS = ruamel.yaml.comments.CommentedSeq
        yaml = ruamel.yaml.YAML()
        yaml.indent(sequence=4, offset=2)
        complete_comm_list = []

        for comm in self.complete_comms:
            if comm:
                src_comm = comm[0].other_attributes.get("src_ip")
                dst_comm = comm[0].other_attributes.get("dst_ip")
                comm_CS = CS(node.return_dict() for node in comm)
                for i in range(len(comm_CS)):
                    comm_CS.yaml_set_comment_before_after_key(i + 1, before='\n')
                dict_to_append = {"number_comm": self.number_complete_comm, "src_comm": src_comm, "dst_comm": dst_comm,
                                  "packet": comm_CS}
                self.number_complete_comm += 1
                complete_comm_list.append(dict_to_append)

        output_dict = {'name': 'Matus Rusnak ID 116286', 'pcap_name': self.file_name, 'filter_name': self.protocol,
                       'complete_comms': complete_comm_list}

        partial_list_dict = []

        for node in self.partial_comms[0]:
            partial_list_dict.append(node.return_dict())

        partial_list_cs = CS(partial_list_dict)
        for i in range(len(partial_list_cs)):
            partial_list_cs.yaml_set_comment_before_after_key(i + 1, before='\n')
        final_partial_dict = {"partial_comms": [{"number_comm": 1}, {"packets": partial_list_cs}]}

        with open("./out/output_tcp.yaml", "w") as file:
            yaml.dump(output_dict, file)
            file.write('\n')
            yaml.dump(final_partial_dict, file)
