#based on open source project:
#https://github.com/Netwok-Analyzer/
#precusory code for ddos detection in pcap files
import dpkt
import socket
import argparse
THRES=10000

def dosattempt(pcap): # find LOIC downloads 
    for ts,buf in pcap:
        try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        src = socket.inet_ntoa(ip.src) #grab source ip
        dest = socket.inet_ntoa(ip.dst) #grab destination ip
        tcp = ip.data
        http = dpkt.http.Request(tcp.data)
        if http.method == "GET":
            url = http.uri.lower()
            if ".zip" in uri and "loic" in uri: #loic is low orbit ion cannon
            print ("[!]" + src + "loic has been downloaded")
    except:
        pass
 
 def findhive(pcap):
    for ts,buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src) #grab source ip
            dest = socket.inet_ntoa(ip.dst) #grab destination ip
            tcp = ip.data
            dport = tcp.dport #grab tcp destination port
            sport = tcp.sport #grab tcp source port
            if dport == 6677:
                if "!lazor" in tcp.data.lower().decode('utf-8):
                print("[!] ddos hivemind issued by" + src)
                print("Target command:" + tcp.data.decode("utf-8"))
            if sport == 6677:
                if "!lazor" in tcp.data.lower():
                    print("[!] DDoS hivemind issues by" + src)
                    print("target command:" + tcp.data)
                    
            except Exception as e:
                pass

# check for port 80 traffic                
def findattack(pcap):
    pktcount={}
    for ts,buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dest = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            if dport == 80:
                stream = src ":" + dest
                if stream in pktcount:
                    pktcount[stream]=pktcount[stream]+1
                else
                    pktcount[stream]=1
    except:
        pass
        
    for stream in pktcount:
        pktsent = pktcount[stream]
        if pktsent > THRES: # if more packets than 10k are sent then...
            srce= stream.split(":")[0]
            dst = stream.split(":")[1]
            print("[+] " + srce + " Attacked " + dst + " With " + str(pktsent) + " Packets")

def DOSmain(pcap):
    # parser=argparse.ArgumentParser(description="Detect D-DOS Attack")
    # parser.add_argument("-p" , required=True,dest="pcap", help="Add the pcap file location")
    
    # args = parser.parse_args()
    # pcap = args.pcap

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        detectLOIC(pcapf)
    
    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        findhive(pcapf)

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        findattack(pcapf)            
        


















