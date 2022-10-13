from scapy.all import *
from binascii import *
import analyze_all as all
import analyze_icmp as icmp
import analyze_udp as udp
import analyze_arp as arp
import analyze_tcp as tcp

FILE_PATH = ".\AiS-materials\packets\\trace-1.pcap"
FILE_NAME = "trace-20.pcap"


def main():
    # analyze_icmp()
    #analyze_all()
    # analyze_udp()
    analyze_arp()
    #analyze_tcp()


def analyze_arp() -> None:
    raw_packets = rdpcap(FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    arp.AnalyzeArp(packets, FILE_NAME)


def analyze_icmp() -> None:
    raw_packets = rdpcap(FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    icmp.AnalyzeIcmp(packets, FILE_NAME)


def analyze_udp() -> None:
    raw_packets = rdpcap(FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    udp.AnalyzeUdp(packets, FILE_NAME)


def analyze_all() -> None:
    raw_packets = rdpcap(FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    all.AnalyzeAll(packets, FILE_NAME)


def analyze_tcp() -> None:
    raw_packets = rdpcap(FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    tcp.AnalyzeTcp(packets, FILE_NAME, "HTTP")


if __name__ == '__main__':
    main()
