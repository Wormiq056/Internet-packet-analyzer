from scapy.all import *
from binascii import *
import analyze_all as all

FILE_PATH = ".\AiS-materials\packets\\trace-20.pcap"
FILE_NAME = "trace-20.pcap"


def main():
    analyze_all()


def analyze_all():
    raw_packets = rdpcap(FILE_PATH)
    packets = []
    for packet in raw_packets:
        packets.append(hexlify(raw(packet)).decode())

    all.AnalyzeAll(packets, FILE_NAME)


if __name__ == '__main__':
    main()
