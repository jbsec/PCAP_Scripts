# Github repo based on Vnetman
# Network PCAP analyser

import argparse  # for parsing arguments
import os.path 
import pyshark
import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.12 import Ether
from scapy.layer.inet import IP, UDP, TCP

# first method
def render_csv_row(pkt_sh, pkt_sc, fh_csv):
    ether_pkt_sc = Ether(pkt_sc)
    if ether_pkt_sc != 0x800: #if pkt does not match
    print('Ignoring non-IP packet')
    return False
    
    ip_pkt_sc = ether_pkt_sc[IP]
    proto = ip_pkt_sc.fields['proto']
    if proto == 17P
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)
        l4_proto_name = 'UDP'
        l4_sport = udp_pkt_sc.sport
        l4_dport = udp_pkt_sc.dport
    elif proto == 6:
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)
        l4_proto_name = 'TCP'
        l4_sport = tcp_pkt_sc.sport
        l4_dport = tcp_pkt_sc.dport
    else:
        print("No tcp or udp detected...")
        return False
        
    # pkt structure is as follows l4,len,dstport,dstip,txt,l4proto etc.
    print(fmt.format(pkt_sh.no,               # {0}
                     pkt_sh.time,             # {1}
                     pkt_sh.protocol,         # {2}
                     l4_proto_name,           # {3}
                     pkt_sh.info,             # {4}
                     pkt_sh.source,           # {5}
                     l4_sport,                # {6}
                     pkt_sh.destination,      # {7}
                     l4_dport,                # {8}
                     pkt_sh.length,           # {9}
                     l4_payload_bytes.hex()), # {10}
          file=fh_csv)

    return True

# Credit to the Vnetman for the OS part below V V V 

def pcap2csv(in_pcap, out_csv):
    """Main entry function called from main to process the pcap and
    generate the csv file.
    in_pcap = name of the input pcap file (guaranteed to exist)
    out_csv = name of the output csv file (will be created)
    This function walks over each packet in the pcap file, and for
    each packet invokes the render_csv_row() function to write one row
    of the csv.
    """

    # Open the pcap file with PyShark in "summary-only" mode, since this
    # is the mode where the brief textual description of the packet (e.g.
    # "Standard query 0xf3de A www.cisco.com", "Client Hello" etc.) are
    # made available.
    pcap_pyshark = pyshark.FileCapture(in_pcap, only_summaries=True)
    pcap_pyshark.load_packets()
    pcap_pyshark.reset()

    frame_num = 0
    ignored_packets = 0
    with open(out_csv, 'w') as fh_csv:
        # Open the pcap file with scapy's RawPcapReader, and iterate over
        # each packet. In each iteration get the PyShark packet as well,
        # and then call render_csv_row() with both representations to generate
        # the CSV row.
        for (pkt_scapy, _) in RawPcapReader(in_pcap):
            try:
                pkt_pyshark = pcap_pyshark.next_packet()
                frame_num += 1
                if not render_csv_row(pkt_pyshark, pkt_scapy, fh_csv):
                    ignored_packets += 1
            except StopIteration:
                # Shouldn't happen because the RawPcapReader iterator should also
                # exit before this happens.
                break

    print('{} packets read, {} packets not written to CSV'.
          format(frame_num, ignored_packets))
#--------------------------------------------------

def command_line_args():
    """Helper called from main() to parse the command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<input pcap file>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--csv', metavar='<output csv file>',
                        help='csv file to create', required=True)
    args = parser.parse_args()
    return args
#--------------------------------------------------

def main():
    """Program main entry"""
    args = command_line_args()

    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" does not exist'.format(args.pcap),
              file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(args.csv):
        print('Output csv file "{}" already exists, '
              'won\'t overwrite'.format(args.csv),
              file=sys.stderr)
        sys.exit(-1)

    pcap2csv(args.pcap, args.csv)
#--------------------------------------------------

if __name__ == '__main__':
    main()