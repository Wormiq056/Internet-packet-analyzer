import argparse
import os
from scapy.all import *
from binascii import *
from modules.filters import analyze_udp as udp, analyze_tcp as tcp, analyze_icmp as icmp, analyze_arp as arp, \
    analyze_all as all
from util import consts

PCAP_FILE_NAME = "trace-2.pcap"
PCAP_FILE_PATH = ".\packets\\" + PCAP_FILE_NAME




def main():
    """
    main function which is called when program is started
    this function takes an argument -p as protocol to indicate which protocol should be analyzed from a pcap file
    if no argument is given it analyzes all packets
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-p",
        type=str,
        help="Specifies protocol to be parsed",
    )

    parser.add_argument(
        "-f",
        type=str,
        help="Name of pcap file to be analyzed. If it is not given program analyzes const file defined above"
    )
    args = parser.parse_args()

    if args.f is not None:
        global PCAP_FILE_NAME
        PCAP_FILE_NAME = args.f
        global PCAP_FILE_PATH
        PCAP_FILE_PATH = ".\packets\\" + PCAP_FILE_NAME

        if PCAP_FILE_NAME[-5:] != ".pcap":
            print("Incorrect file type")
            print("File need to be a .pcap type")
            return
        if not os.path.exists(PCAP_FILE_PATH):
            print("{} is not in .\\packets".format(PCAP_FILE_NAME))
            print("Please add file to directory")
            return



    if args.p is not None:
        if args.p.upper() in consts.CORRECT_PROTOCOLS:
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
    """
    function that is called when parameter for protocol was ARP
    starts the analyzation of packet communication with arp protocol
    """
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    arp.AnalyzeArp(packets, PCAP_FILE_NAME)


def analyze_icmp() -> None:
    """
    function that is called when paramater -p was icmp and it starts
    the analyzation of communication between packets with icmp protocol
    """
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    icmp.AnalyzeIcmp(packets, PCAP_FILE_NAME)


def analyze_udp() -> None:
    """
    function which is called when parameter -p was tftp
    it starts the analyzation of tftp packets and their communications
    """
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    udp.AnalyzeUdp(packets, PCAP_FILE_NAME)


def analyze_all() -> None:
    """
    function which is called when paramter -p was not given
    it starts the analyzation of all packets
    """
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    all.AnalyzeAll(packets, PCAP_FILE_NAME)


def analyze_tcp(protocol: str) -> None:
    """
    function which is called when parameter -p had an tcp protocol
    it starts the analyzation of given tcp protocol and its communications
    """
    raw_packets = rdpcap(PCAP_FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    tcp.AnalyzeTcp(packets, PCAP_FILE_NAME, protocol)


if __name__ == '__main__':
    main()
