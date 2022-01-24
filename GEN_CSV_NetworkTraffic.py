# A script to generate network traffic with included attacks
# Based on an open source repository: https://github.com/CristianTuretta

import sys
import random
import random import getrandbits
from ipaddress import IPv4Address

def gen_src_pool(n_member):
    pool = set()
    for i in range (n_member):
        bits = getrandbits(32) # gens a int 32 random bits
        addr = IPv4Address(bits) # instances ipv4 add from bits
        pool.add(str(addr))
    return pool
    
    
    
def gen_src_pool_attack(n_member):
    pool = set()
    for i in range(n_member):
        bits = getrandbits(16) # gen 16 bit int
        addr = IPv4Address(bits) # instances addy with bits
        pool.add(str(addr))
    return pool
  

  
def forge_pkt(number, time, source, destination, protocol, length, info):
    pkt = list()
    pkt.append(str(number)) # number
    pkt.append(str(time)) # time
    pkt.append(random.choice(list(source))) # source
    pkt.append(destination) # destination
    pkt.append(random.choice(list(protocol))) # protocol
    pkt.append(str(length)) # 16 int len in bytes of UDP 
    pkt.append(info) # information
    return pkt
  

  
def attack(csv_file,time,target,atk_volume,atk_time_duration,attackers): #in mbs
    n_packets = atk_volume/pkt_size
    count = 1
    while count <= n_packets * atk_time_duration:
        atk_packet = forge_pkt("0",time,attackers,target,{"UDP"},pkt_size,"attack")
        append_to_csv(csv_file, CSV_FORMAT.join(atk_packet))
        time += (1.000000 / n_packets) + random.uniform(0.000001, 0.005)
        count += 1
 

 
def append_to_csv(file, line):
    file.write(str(line) + "\n")
DEFAULT_DESTINATION = "192.168.0.1"
CSV_FORMAT = ","
PROTOCOLS = {"UDP"}



def generate(file_path, n_members, records_length, n_attackers, atk_volume, atk_duration):
    csv_file = open(file_path, "a+")
    no = 1 
    normal_usr_pool = generate_source_pool(n_member=n_members)
    time = 0.0
    attack_pool = generate_source_pool_attackers(n_attackers_
    while no <= records_length:
        packet = forge_pkt(no, time, normal_usr_pool, DEFAULT_DESTINATION, PROTOCOLS, getrandbits(16),
        append_to_csv(csv_file, CSV_FORMAT.join(packet))
        no += 1
        time += random.uniform(0.000001, 0.3)
    if attack_pool:
        attack(csv_file, time, DEFAULT_DESTINATION, 1000, atk_volume,atk_duration,attack_pool) # 1kb
    csv_file.close()























