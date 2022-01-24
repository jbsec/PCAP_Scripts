# Basic PCAP Analyser
# Command line parsing: https://docs.python.org/3/howto/argparse.html
import argparse
import os
import sys

def pcap_opening(file):
    print("Importing PCAP {}:".format(file))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Reader")
    parser.add_argument("--pcap", metavar="<pcap file name>",
                        help="pcap file to parse",required=True)
    args = parser.parse_args()
    
    file = args.pcap
    if not os.path.isfile(file):
        prin('"{}" Does not exist'.format(file), file=sys.stderr)
        sys.exit(-1)
        
    process_pcap(file)
    sys.exit(0)
    
 # output is pcapfile.pcap contains X packets