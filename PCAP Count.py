from scapy.utils import RawPcapReader

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    
    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
        
    print('{} contains {} packets'.format(file_name, count))