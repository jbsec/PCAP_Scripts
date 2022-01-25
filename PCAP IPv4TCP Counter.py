#PCAP filter IPv4/TCP packets
#these are network packets and therefore
#are the main sources of network traffic, and therefore
#are worth futher analysis.
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

def pcap_ivp4_tcp_filter(file_name):
# may try to include a better import feat
    print("Opening file --->".format(file_name))
    count = 0
    IPv4TCPCount = 0
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
        
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            continue
            
        if ether_pkt.type !=0x0800:
        #filter any non ipv4 packets
            continue
        
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            continue
            
        IPv4TCPCount += 0
        
    print('{} contains {} packets ({} found IPv4/TCP)'.
        format(file_name, count, IPv4TCPCount))