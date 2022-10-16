import argparse
from scapy.all import *
from binascii import *
from modules.filters import analyze_udp as udp, analyze_tcp as tcp, analyze_icmp as icmp, analyze_arp as arp, \
    analyze_all as all

PCAP_FILE_NAME = "frag.pcap"
PCAP_FILE_PATH = ".\packets\\" + PCAP_FILE_NAME

CORRECT_PROTOCOLS = ["TFTP", "ICMP", "ARP", "HTTP", "HTTPS", "TELNET", "SSH", "FTP-DATA", "FTP-CONTROL"]


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-p",
        type=str,
        help="Specifies protocol to be parsed",
    )

    args = parser.parse_args()

    if args.p is not None:
        if args.p.upper() in CORRECT_PROTOCOLS:
            if args.p.upper() == "ICMP":
                analyze_icmp()
            elif args.p.upper() == "ARP":
                analyze_arp()
            elif args.p.upper() == "TFTP":
                analyze_udp()
            else:
                analyze_tcp(args.p.upper())

        else:
            print("{} is a incorrect protocol".format(args.p.upper()))
    else:
        analyze_all()


def analyze_arp() -> None:
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    arp.AnalyzeArp(packets, PCAP_FILE_NAME)


def analyze_icmp() -> None:
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    icmp.AnalyzeIcmp(packets, PCAP_FILE_NAME)


def analyze_udp() -> None:
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    udp.AnalyzeUdp(packets, PCAP_FILE_NAME)


def analyze_all() -> None:
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    all.AnalyzeAll(packets, PCAP_FILE_NAME)


def analyze_tcp(protocol: str) -> None:
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    tcp.AnalyzeTcp(packets, PCAP_FILE_NAME, protocol)


if __name__ == '__main__':
    main()
