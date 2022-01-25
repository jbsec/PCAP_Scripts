# Github source reference: @kevingbrady
# PCAP Pre-processor for CSV data
#### imports ####
import os
import time
import logging
from src.ParallelSniffer import Sniffer
from src.PacketData import PacketData
from src import utils
import multiprocessing

if __name___ == '__main__':
    # start time and manager setup
    program_start = time.time()
    manager = multiprocessing.Manager()
    # logging
    logging.basicConfig(filename='PcapPreprocessor.log',filemode='w',level=logging.DEBUG,format='%(asctime)s %(message)s')
    # starting time record
    startTime = time.time()
    # parse cli args
    gl_args = utils.parse_command_line()
    # make pandas dataframe to hold pkt data
    data_frame = PacketData(gl_args.output_file, gl_args.enable_cicflowmeter)
    # init sniffer controller object
    sniffer_controller = Sniffer(manager, gl_args.keep_incomplete, gl_args.output_file, gl_args.enable_cicflowmeter)
    sniffer_controller.columns = data_frame.df.columns
    packet_data = []
    if gl_args.input_file:
        #start para sniff with pcap
        packet_data = sniffer_controller.start_sniffer(gl_args.input_file)
    elif gl_args.input_directory:
        logging.info('dir parsing starting @: ' + gl_args.input_directory + '/')
        print('Directory parsing starting at '+ gl_args.input_directory + '/')
        
       #loop that finds all pcap
       file_list = []
       for root, dirs, files in os.walk(gl_args.input_directory):
        for file in files:
            if file.endswith('.pcap' or '.pcapng'):
                file_list.append(root + '/' + file)
                
        # sort file list for largest files first
        file_list.sort(key=lambda x: os.stat(x).st_size, reverse=True)
        # start parssnif with list of pcap files
        packet_data = sniffer_controller.start_sniffer(file_list)
    
    #update pandas dataframe
    data_frame.df = data_frame.df.append(packet_data, ignore_index=True)
    program_end = time.time()
    print("Preprocessed"+str(sniffer_controller.total_packets.value)+"packets in: "+utils.pretty_time_delta(program_end - program_start))
    print("Program End")
    

