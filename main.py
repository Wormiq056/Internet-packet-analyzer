from scapy.all import *
from binascii import *
import analyze_all as all
def main():
    # raw_packets =packets = rdpcap(".\AiS-materials\packets\eth-1.pcap")
    raw_packets = packets = rdpcap(".\AiS-materials\packets\\trace-20.pcap")
    packets = []
    for packet in raw_packets:
        #print(packet.wirelen) # kolko ma bytov packet alebo vydelit 2
        #print(hexlify(raw(packet)).decode())
        packets.append(hexlify(raw(packet)).decode())
    #print(len(packets[0])/2)

    analyze_all = all.AnalyzeAll(packets)


if __name__ == '__main__':
    main()