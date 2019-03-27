#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 30 20:40:09 2018

@author: shyamabs
"""
import dpkt
import codecs
from scapy.all import *
import csv
import numpy as np
import pandas as pd

def pcapToCsv(fname):
    #f = open('SynFlood_Sample.pcap')
    pkts=rdpcap(fname)
    #pcap = dpkt.pcap.Reader(f)
    outfile='/Users/shyamabs/Documents/DDoD_ML_MS/datasets/training_data_captured3.csv'
    with open(outfile, 'w', newline='') as csvfile:
        fieldnames = ['dst', 'src', 'type', 'IP version', 'IP ihl', 'IP tos','IP len', 'IP id', 'IP flags', 'IP frag', 'IP ttl',
                      'IP proto','IP chksum','IP src','IP dst','TCP sport','TCP dport', 'TCP seq', 'TCP ack', 'TCP dataofs', 
                      'TCP reserved', 'TCP flags','TCP window', 'TCP chksum','TCP urgptr','TCP options']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
        writer.writeheader()
    
        for pkt in pkts:
            #pkt.show()
            if pkt.haslayer(TCP):
                #print( "dst: " +  str(pkt.getlayer(IP).chksum))
                writer.writerow({'dst': str(pkt.dst), 'src': str(pkt.src), 'type' : str(pkt.type), 'IP version': str(pkt.getlayer(IP).version), 
                             'IP ihl': str(pkt.getlayer(IP).ihl), 'IP tos': str(pkt.getlayer(IP).tos),'IP len': str(pkt.getlayer(IP).len), 
                             'IP id': str(pkt.getlayer(IP).id),'IP flags': str(pkt.getlayer(IP).flags), 'IP frag': str(pkt.getlayer(IP).frag), 
                             'IP ttl': str(pkt.getlayer(IP).ttl), 'IP proto': str(pkt.getlayer(IP).proto),'IP chksum': str(pkt.getlayer(IP).chksum),
                             'IP src': str(pkt.getlayer(IP).src),'IP dst': str(pkt.getlayer(IP).dst),'TCP sport': str(pkt.getlayer(TCP).sport),
                          'TCP dport': str(pkt.getlayer(TCP).dport), 'TCP seq': str(pkt.getlayer(TCP).seq), 'TCP ack': str(pkt.getlayer(TCP).ack), 
                          'TCP dataofs': str(pkt.getlayer(TCP).dataofs), 'TCP reserved': str(pkt.getlayer(TCP).reserved), 
                          'TCP flags': str(pkt.getlayer(TCP).flags),'TCP window': str(pkt.getlayer(TCP).window), 'TCP chksum': str(pkt.getlayer(TCP).chksum),
                          'TCP urgptr': str(pkt.getlayer(TCP).urgptr),'TCP options': str(pkt.getlayer(TCP).options)})
    
    print("Done with conversion...")
    return outfile
        
def getFlagNumbers(train_data, batch_packets):
    number_of_ACK = []
    number_of_SYN = []
    number_of_RST = []
    number_of_PA = []
    number_of_FA = []
    number_of_SA = []
    number_of_FPA = []
    number_of_RA = []
    
    ratio_ack_syn = []
    ratio_ack_rst = []
    ratio_syn_rst = []
    
    #get the total number of rows in the dataset           
    total_packets=train_data.shape[0]  
    #total_packets=100
    print("Total packets= ",total_packets)  
        
    for i in range(batch_packets,total_packets,batch_packets):
        k=i-batch_packets
        train_data_subset=train_data[k:i]
        flags = train_data_subset['TCP flags'].value_counts()
        
        
        if 'A' in flags: 
            number_of_ACK.append(flags.get('A'))
        else: 
            number_of_ACK.append(0)
            
            
        if f'S' in flags: 
            number_of_SYN.append(flags.get('S'))
        else: 
            number_of_SYN.append(0)
            
            
        if 'R' in flags: 
            number_of_RST.append(flags.get('R'))
        else: 
            number_of_RST.append(0)
            
            
        if 'PA' in flags: 
            number_of_PA.append(flags.get('PA'))
        else: 
            number_of_PA.append(0)
            
            
        if 'FA' in flags: 
            number_of_FA.append(flags.get('FA'))
        else: 
            number_of_FA.append(0)
            
            
        if 'SA' in flags: 
            number_of_SA.append(flags.get('SA'))
        else: 
            number_of_SA.append(0)
            
            
        if 'FPA' in flags: 
            number_of_FPA.append(flags.get('FPA'))
        else: 
            number_of_FPA.append(0)
        
        
        if 'RA' in flags: 
            number_of_RA.append(flags.get('RA'))
        else: 
            number_of_RA.append(0)
            
        if 'A' in flags and 'S' in flags:
            ratio_ack_syn.append(flags.get('A')/flags.get('S'))
        else:
            ratio_ack_syn.append(-1)
        
        if 'A' in flags and 'R' in flags:    
            ratio_ack_rst.append(flags.get('A')/flags.get('R'))
        else:
            ratio_ack_rst.append(-1)
            
        if 'S' in flags and 'R' in flags:
            ratio_syn_rst.append(flags.get('S')/flags.get('R'))
        else:
            ratio_syn_rst.append(-1)
            
        #for j in range(k,i,1):
            #print(j)
            #print("K and I = ",k,i)
            
    train_data_subset=train_data[i:total_packets]
    flags = train_data_subset['TCP flags'].value_counts()
    
    if 'A' in flags: 
        number_of_ACK.append(flags.get('A')) 
    else: 
        number_of_ACK.append(0)
            
        
    if 'S' in flags: 
        number_of_SYN.append(flags.get('S'))
    else: 
        number_of_SYN.append(0)
            
        
    if 'R' in flags: 
       number_of_RST.append(flags.get('R')) 
    else: 
       number_of_RST.append(0)
       

    if 'PA' in flags: 
        number_of_PA.append(flags.get('PA'))
    else: 
        number_of_PA.append(0)
        
        
    if 'FA' in flags: 
        number_of_FA.append(flags.get('FA'))
    else: 
        number_of_FA.append(0)
            
            
    if 'SA' in flags: 
        number_of_SA.append(flags.get('SA'))
    else: 
        number_of_SA.append(0)
            
            
    if 'FPA' in flags: 
        number_of_FPA.append(flags.get('FPA'))
    else: 
        number_of_FPA.append(0)
        
        
    if 'RA' in flags: 
        number_of_RA.append(flags.get('RA'))
    else: 
        number_of_RA.append(0)       
    #while i<total_packets:
        #print("i= ",i)
        #i=i+1
    
    if 'A' in flags and 'S' in flags:
        ratio_ack_syn.append(flags.get('A')/flags.get('S'))
    else:
        ratio_ack_syn.append(-1)
    
    if 'A' in flags and 'R' in flags:    
        ratio_ack_rst.append(flags.get('A')/flags.get('R'))
    else:
        ratio_ack_rst.append(-1)
        
    if 'S' in flags and 'R' in flags:
        ratio_syn_rst.append(flags.get('S')/flags.get('R'))
    else:
        ratio_syn_rst.append(-1)

    return ratio_ack_syn, ratio_ack_rst, ratio_syn_rst, number_of_ACK, number_of_SYN, number_of_RST, number_of_PA, number_of_FA, number_of_SA, number_of_FPA, number_of_RA


def tcp_dport_sport_numbers(train_data, batch_packets):
    #get the total number of rows in the dataset           
    total_packets=train_data.shape[0]  
    #total_packets=100
    print("Total packets= ",total_packets) 
    
    number_sport_20percent = []
    number_sport_35percent = []
    number_sport_50percent = []
    number_sport_75percent = []
    number_dport_20percent = []
    number_dport_35percent = []
    number_dport_50percent = []
    number_dport_75percent = []
        
    for i in range(batch_packets,total_packets,batch_packets):
        k=i-batch_packets
        train_data_subset=train_data[k:i]
        sport = train_data_subset['TCP sport'].value_counts()
        dport = train_data_subset['TCP dport'].value_counts()
        
        sport_20percent = 0
        sport_35percent = 0
        sport_50percent = 0
        sport_75percent = 0
        
        dport_20percent = 0
        dport_35percent = 0
        dport_50percent = 0
        dport_75percent = 0
        
        for key in sport.keys():
            count_percent = (sport.get(key) / batch_packets)*100
            #print("sport.get(key)= ", sport.get(key))
            #print("batch_packets= ", batch_packets)
            #print("count_percent= ", count_percent)
            if count_percent >= 20:
                sport_20percent = sport_20percent + 1
            if count_percent >= 35:
                sport_35percent = sport_35percent + 1
            if count_percent >= 50:
                sport_50percent = sport_50percent + 1
            if count_percent >= 75:
                sport_75percent = sport_75percent + 1
                
        for key in dport.keys():
            count_percent = (dport.get(key) / batch_packets)*100
            if count_percent >= 20:
                dport_20percent = dport_20percent + 1
            if count_percent >= 35:
                dport_35percent = dport_35percent + 1
            if count_percent >= 50:
                dport_50percent = dport_50percent + 1
            if count_percent >= 75:
                dport_75percent = dport_75percent + 1
                
        number_sport_20percent.append(sport_20percent)
        number_sport_35percent.append(sport_35percent)
        number_sport_50percent.append(sport_50percent)
        number_sport_75percent.append(sport_75percent)
        number_dport_20percent.append(dport_20percent)
        number_dport_35percent.append(dport_35percent)
        number_dport_50percent.append(dport_50percent)
        number_dport_75percent.append(dport_75percent)
    
    train_data_subset=train_data[i:total_packets]
    sport = train_data_subset['TCP sport'].value_counts()
    dport = train_data_subset['TCP dport'].value_counts()
    
    sport_20percent = 0
    sport_35percent = 0
    sport_50percent = 0
    sport_75percent = 0
        
    dport_20percent = 0
    dport_35percent = 0
    dport_50percent = 0
    dport_75percent = 0
        
    for key in sport.keys():
        count_percent = (sport.get(key) / batch_packets)*100
        if count_percent >= 20:
            sport_20percent = sport_20percent + 1
        if count_percent >= 35:
            sport_35percent = sport_35percent + 1
        if count_percent >= 50:
            sport_50percent = sport_50percent + 1
        if count_percent >= 75:
            sport_75percent = sport_75percent + 1
                
    for key in dport.keys():
        count_percent = (dport.get(key) / batch_packets)*100
        if count_percent >= 20:
            dport_20percent = dport_20percent + 1
        if count_percent >= 35:
            dport_35percent = dport_35percent + 1
        if count_percent >= 50:
            dport_50percent = dport_50percent + 1
        if count_percent >= 75:
            dport_75percent = dport_75percent + 1
    number_sport_20percent.append(sport_20percent)
    number_sport_35percent.append(sport_35percent)
    number_sport_50percent.append(sport_50percent)
    number_sport_75percent.append(sport_75percent)
    number_dport_20percent.append(dport_20percent)
    number_dport_35percent.append(dport_35percent)
    number_dport_50percent.append(dport_50percent)
    number_dport_75percent.append(dport_75percent)
            
    return number_sport_20percent, number_sport_35percent, number_sport_50percent, number_sport_75percent, number_dport_20percent, number_dport_35percent, number_dport_50percent, number_dport_75percent
    


def ip_src_dst_numbers(train_data, batch_packets):
    #get the total number of rows in the dataset           
    total_packets=train_data.shape[0]  
    #total_packets=100
    print("Total packets= ",total_packets) 
    
    number_src_20percent = []
    number_src_35percent = []
    number_src_50percent = []
    number_src_75percent = []
    number_dst_20percent = []
    number_dst_35percent = []
    number_dst_50percent = []
    number_dst_75percent = []
        
    for i in range(batch_packets,total_packets,batch_packets):
        k=i-batch_packets
        train_data_subset=train_data[k:i]
        src = train_data_subset['IP src'].value_counts()
        dst = train_data_subset['IP dst'].value_counts()
        
        src_20percent = 0
        src_35percent = 0
        src_50percent = 0
        src_75percent = 0
        
        dst_20percent = 0
        dst_35percent = 0
        dst_50percent = 0
        dst_75percent = 0
        
        for key in src.keys():
            count_percent = (src.get(key) / batch_packets)*100
            #print("sport.get(key)= ", sport.get(key))
            #print("batch_packets= ", batch_packets)
            #print("count_percent= ", count_percent)
            if count_percent >= 20:
                src_20percent = src_20percent + 1
            if count_percent >= 35:
                src_35percent = src_35percent + 1
            if count_percent >= 50:
                src_50percent = src_50percent + 1
            if count_percent >= 75:
                src_75percent = src_75percent + 1
                
        for key in dst.keys():
            count_percent = (dst.get(key) / batch_packets)*100
            if count_percent >= 20:
                dst_20percent = dst_20percent + 1
            if count_percent >= 35:
                dst_35percent = dst_35percent + 1
            if count_percent >= 50:
                dst_50percent = dst_50percent + 1
            if count_percent >= 75:
                dst_75percent = dst_75percent + 1
                
        number_src_20percent.append(src_20percent)
        number_src_35percent.append(src_35percent)
        number_src_50percent.append(src_50percent)
        number_src_75percent.append(src_75percent)
        number_dst_20percent.append(dst_20percent)
        number_dst_35percent.append(dst_35percent)
        number_dst_50percent.append(dst_50percent)
        number_dst_75percent.append(dst_75percent)
    
    train_data_subset=train_data[i:total_packets]
    src = train_data_subset['IP src'].value_counts()
    dst = train_data_subset['IP dst'].value_counts()
    
    src_20percent = 0
    src_35percent = 0
    src_50percent = 0
    src_75percent = 0
        
    dst_20percent = 0
    dst_35percent = 0
    dst_50percent = 0
    dst_75percent = 0
        
    for key in src.keys():
        count_percent = (src.get(key) / batch_packets)*100
        if count_percent >= 20:
            src_20percent = src_20percent + 1
        if count_percent >= 35:
            src_35percent = src_35percent + 1
        if count_percent >= 50:
            src_50percent = src_50percent + 1
        if count_percent >= 75:
            src_75percent = src_75percent + 1
                
    for key in dst.keys():
        count_percent = (dst.get(key) / batch_packets)*100
        if count_percent >= 20:
            dst_20percent = dst_20percent + 1
        if count_percent >= 35:
            dst_35percent = dst_35percent + 1
        if count_percent >= 50:
            dst_50percent = dst_50percent + 1
        if count_percent >= 75:
            dst_75percent = dst_75percent + 1  
                
    number_src_20percent.append(src_20percent)
    number_src_35percent.append(src_35percent)
    number_src_50percent.append(src_50percent)
    number_src_75percent.append(src_75percent)
    number_dst_20percent.append(dst_20percent)
    number_dst_35percent.append(dst_35percent)
    number_dst_50percent.append(dst_50percent)
    number_dst_75percent.append(dst_75percent)
            
    return number_src_20percent, number_src_35percent, number_src_50percent, number_src_75percent, number_dst_20percent, number_dst_35percent, number_dst_50percent, number_dst_75percent


def get_average_IP_bytes(train_data, batch_packets):
    #get the total number of rows in the dataset           
    total_packets=train_data.shape[0]  
    #total_packets=100
    print("Total packets= ",total_packets) 
    average_IP_bytes = []
    for i in range(batch_packets,total_packets,batch_packets):
        k=i-batch_packets
        train_data_subset=train_data[k:i]
        total_IPbytes=0
        for index, row in train_data_subset.iterrows():
            total_IPbytes = total_IPbytes + row['IP len']
        average_IP_bytes.append(total_IPbytes/batch_packets)
        
    train_data_subset=train_data[i:total_packets]
    total_IPbytes=0
    for index, row in train_data_subset.iterrows():
        total_IPbytes = total_IPbytes + row['IP len']
    average_IP_bytes.append(total_IPbytes/batch_packets)
    return average_IP_bytes



def get_attack_aggregate(train_data, batch_packets):
    total_packets=train_data.shape[0]  
    #total_packets=100
    print("Total packets= ",total_packets) 
    attack_aggregate_list = []
    for i in range(batch_packets,total_packets,batch_packets):
        k=i-batch_packets
        train_data_subset=train_data[k:i]
        attack_aggregate = 0
        for index, row in train_data_subset.iterrows():
            attack_aggregate = attack_aggregate + row['Attack']
        attack_aggregate_list.append(attack_aggregate/batch_packets)
    train_data_subset=train_data[i:total_packets]
    attack_aggregate=0
    for index, row in train_data_subset.iterrows():
        attack_aggregate = attack_aggregate + row['Attack']
    attack_aggregate_list.append(attack_aggregate/batch_packets)
    return attack_aggregate_list
   

def extract_features(train_data, batch_packets, total_packets):
    print("Total packets= ",total_packets)
    number_of_ACK = []
    number_of_SYN = []
    number_of_RST = []
    number_of_PA = []
    number_of_FA = []
    number_of_SA = []
    number_of_FPA = []
    number_of_RA = []
    
    ratio_syn_ack = []
    ratio_ack_rst = []
    ratio_syn_rst = []
    
    number_sport_20percent = []
    number_sport_35percent = []
    number_sport_50percent = []
    number_sport_75percent = []
    number_dport_20percent = []
    number_dport_35percent = []
    number_dport_50percent = []
    number_dport_75percent = []
    
    number_src_20percent = []
    number_src_35percent = []
    number_src_50percent = []
    number_src_75percent = []
    number_dst_20percent = []
    number_dst_35percent = []
    number_dst_50percent = []
    number_dst_75percent = []
    
    average_IP_bytes = []
    
    attack_aggregate_list = []
    
    ratio_incom_to_outgo=[]
    
    number_uniq_incom_ips = []
    
    
    for i in range(batch_packets,total_packets,batch_packets):
        k=i-batch_packets
        train_data_subset=train_data[k:i]
        flags = train_data_subset['TCP flags'].value_counts()
        
        
        if 'A' in flags: 
            number_of_ACK.append(flags.get('A'))
        else: 
            number_of_ACK.append(0)
            
            
        if f'S' in flags: 
            number_of_SYN.append(flags.get('S'))
        else: 
            number_of_SYN.append(0)
            
            
        if 'R' in flags: 
            number_of_RST.append(flags.get('R'))
        else: 
            number_of_RST.append(0)
            
            
        if 'PA' in flags: 
            number_of_PA.append(flags.get('PA'))
        else: 
            number_of_PA.append(0)
            
            
        if 'FA' in flags: 
            number_of_FA.append(flags.get('FA'))
        else: 
            number_of_FA.append(0)
            
            
        if 'SA' in flags: 
            number_of_SA.append(flags.get('SA'))
        else: 
            number_of_SA.append(0)
            
            
        if 'FPA' in flags: 
            number_of_FPA.append(flags.get('FPA'))
        else: 
            number_of_FPA.append(0)
        
        
        if 'RA' in flags: 
            number_of_RA.append(flags.get('RA'))
        else: 
            number_of_RA.append(0)
            
        if 'A' in flags and 'S' in flags:
            ratio_syn_ack.append(flags.get('S')/flags.get('A'))
        elif 'A' not in flags and 'S' not in flags:
            ratio_syn_ack.append(0)
        elif 'A' not in flags:
            ratio_syn_ack.append(flags.get('S'))
        elif 'S' not in flags:
            ratio_syn_ack.append(1/flags.get('A'))
        
        
        if 'A' in flags and 'R' in flags:    
            ratio_ack_rst.append(flags.get('A')/flags.get('R'))
        elif 'A' not in flags and 'R' not in flags:
            ratio_ack_rst.append(0)
        elif 'A' not in flags:
            ratio_ack_rst.append(1/flags.get('R'))
        elif 'R' not in flags:
            ratio_ack_rst.append(flags.get('A'))
    
            
        if 'S' in flags and 'R' in flags:
            ratio_syn_rst.append(flags.get('S')/flags.get('R'))
        elif 'S' not in flags and 'R' not in flags:
            ratio_syn_rst.append(0)
        elif 'R' not in flags:
            ratio_syn_rst.append(flags.get('S'))
        elif 'S' not in flags:
            ratio_syn_rst.append(1/flags.get('R'))
        
            
        #for j in range(k,i,1):
            #print(j)
            #print("K and I = ",k,i)
            
        sport = train_data_subset['TCP sport'].value_counts()
        dport = train_data_subset['TCP dport'].value_counts()
        
        sport_20percent = 0
        sport_35percent = 0
        sport_50percent = 0
        sport_75percent = 0
        
        dport_20percent = 0
        dport_35percent = 0
        dport_50percent = 0
        dport_75percent = 0
        
        for key in sport.keys():
            count_percent = (sport.get(key) / batch_packets)*100
            #print("sport.get(key)= ", sport.get(key))
            #print("batch_packets= ", batch_packets)
            #print("count_percent= ", count_percent)
            if count_percent >= 20:
                sport_20percent = sport_20percent + 1
            if count_percent >= 35:
                sport_35percent = sport_35percent + 1
            if count_percent >= 50:
                sport_50percent = sport_50percent + 1
            if count_percent >= 75:
                sport_75percent = sport_75percent + 1
                
        for key in dport.keys():
            count_percent = (dport.get(key) / batch_packets)*100
            if count_percent >= 20:
                dport_20percent = dport_20percent + 1
            if count_percent >= 35:
                dport_35percent = dport_35percent + 1
            if count_percent >= 50:
                dport_50percent = dport_50percent + 1
            if count_percent >= 75:
                dport_75percent = dport_75percent + 1
                
        number_sport_20percent.append(sport_20percent)
        number_sport_35percent.append(sport_35percent)
        number_sport_50percent.append(sport_50percent)
        number_sport_75percent.append(sport_75percent)
        number_dport_20percent.append(dport_20percent)
        number_dport_35percent.append(dport_35percent)
        number_dport_50percent.append(dport_50percent)
        number_dport_75percent.append(dport_75percent)
        
        src = train_data_subset['IP src'].value_counts()
        dst = train_data_subset['IP dst'].value_counts()
        
        src_20percent = 0
        src_35percent = 0
        src_50percent = 0
        src_75percent = 0
        
        dst_20percent = 0
        dst_35percent = 0
        dst_50percent = 0
        dst_75percent = 0
        
        for key in src.keys():
            count_percent = (src.get(key) / batch_packets)*100
            #print("sport.get(key)= ", sport.get(key))
            #print("batch_packets= ", batch_packets)
            #print("count_percent= ", count_percent)
            if count_percent >= 20:
                src_20percent = src_20percent + 1
            if count_percent >= 35:
                src_35percent = src_35percent + 1
            if count_percent >= 50:
                src_50percent = src_50percent + 1
            if count_percent >= 75:
                src_75percent = src_75percent + 1
                
        for key in dst.keys():
            count_percent = (dst.get(key) / batch_packets)*100
            if count_percent >= 20:
                dst_20percent = dst_20percent + 1
            if count_percent >= 35:
                dst_35percent = dst_35percent + 1
            if count_percent >= 50:
                dst_50percent = dst_50percent + 1
            if count_percent >= 75:
                dst_75percent = dst_75percent + 1
                
        number_src_20percent.append(src_20percent)
        number_src_35percent.append(src_35percent)
        number_src_50percent.append(src_50percent)
        number_src_75percent.append(src_75percent)
        number_dst_20percent.append(dst_20percent)
        number_dst_35percent.append(dst_35percent)
        number_dst_50percent.append(dst_50percent)
        number_dst_75percent.append(dst_75percent)
        
        total_IPbytes=0
        for index, row in train_data_subset.iterrows():
            total_IPbytes = total_IPbytes + row['IP len']
        average_IP_bytes.append(total_IPbytes/batch_packets)
        
        attack_aggregate = 0
        for index, row in train_data_subset.iterrows():
            attack_aggregate = attack_aggregate + row['Attack']
        attack_aggregate_list.append(attack_aggregate/batch_packets)
        
        incoming_ips = train_data_subset['IP dst'].value_counts()
        outgoing_ips = train_data_subset['IP src'].value_counts()
        if '10.0.0.5' in incoming_ips:
            incom_pkts = incoming_ips.get('10.0.0.5')
        else:
            incom_pkts = 1
            
        if '10.0.0.5' in outgoing_ips:
            outgo_pkts = outgoing_ips.get('10.0.0.5')
        else:
            outgo_pkts = 1
        

        ratio_incom_to_outgo.append(incom_pkts/outgo_pkts)
        if '10.0.0.5' in train_data_subset['IP src'].value_counts():
            number_uniq_incom_ips.append(train_data_subset['IP src'].value_counts().size-1)
        else:
            number_uniq_incom_ips.append(train_data_subset['IP src'].value_counts().size)
        
            
    train_data_subset=train_data[i:total_packets]
    flags = train_data_subset['TCP flags'].value_counts()
    
    if 'A' in flags: 
        number_of_ACK.append(flags.get('A')) 
    else: 
        number_of_ACK.append(0)
            
        
    if 'S' in flags: 
        number_of_SYN.append(flags.get('S'))
    else: 
        number_of_SYN.append(0)
            
        
    if 'R' in flags: 
       number_of_RST.append(flags.get('R')) 
    else: 
       number_of_RST.append(0)
       

    if 'PA' in flags: 
        number_of_PA.append(flags.get('PA'))
    else: 
        number_of_PA.append(0)
        
        
    if 'FA' in flags: 
        number_of_FA.append(flags.get('FA'))
    else: 
        number_of_FA.append(0)
            
            
    if 'SA' in flags: 
        number_of_SA.append(flags.get('SA'))
    else: 
        number_of_SA.append(0)
            
            
    if 'FPA' in flags: 
        number_of_FPA.append(flags.get('FPA'))
    else: 
        number_of_FPA.append(0)
        
        
    if 'RA' in flags: 
        number_of_RA.append(flags.get('RA'))
    else: 
        number_of_RA.append(0)       
    #while i<total_packets:
        #print("i= ",i)
        #i=i+1
    if 'A' in flags and 'S' in flags:
        ratio_syn_ack.append(flags.get('S')/flags.get('A'))
    elif 'A' not in flags and 'S' not in flags:
        ratio_syn_ack.append(0)
    elif 'A' not in flags:
        ratio_syn_ack.append(flags.get('S'))
    elif 'S' not in flags:
        ratio_syn_ack.append(1/flags.get('A'))
        
        
    if 'A' in flags and 'R' in flags:    
        ratio_ack_rst.append(flags.get('A')/flags.get('R'))
    elif 'A' not in flags and 'R' not in flags:
        ratio_ack_rst.append(0)
    elif 'A' not in flags:
        ratio_ack_rst.append(1/flags.get('R'))
    elif 'R' not in flags:
        ratio_ack_rst.append(flags.get('A'))
    
            
    if 'S' in flags and 'R' in flags:
        ratio_syn_rst.append(flags.get('S')/flags.get('R'))
    elif 'S' not in flags and 'R' not in flags:
        ratio_syn_rst.append(0)
    elif 'R' not in flags:
        ratio_syn_rst.append(flags.get('S'))
    elif 'S' not in flags:
        ratio_syn_rst.append(1/flags.get('R'))
   
        
    sport = train_data_subset['TCP sport'].value_counts()
    dport = train_data_subset['TCP dport'].value_counts()
    
    sport_20percent = 0
    sport_35percent = 0
    sport_50percent = 0
    sport_75percent = 0
        
    dport_20percent = 0
    dport_35percent = 0
    dport_50percent = 0
    dport_75percent = 0
        
    for key in sport.keys():
        count_percent = (sport.get(key) / batch_packets)*100
        if count_percent >= 20:
            sport_20percent = sport_20percent + 1
        if count_percent >= 35:
            sport_35percent = sport_35percent + 1
        if count_percent >= 50:
            sport_50percent = sport_50percent + 1
        if count_percent >= 75:
            sport_75percent = sport_75percent + 1
                
    for key in dport.keys():
        count_percent = (dport.get(key) / batch_packets)*100
        if count_percent >= 20:
            dport_20percent = dport_20percent + 1
        if count_percent >= 35:
            dport_35percent = dport_35percent + 1
        if count_percent >= 50:
            dport_50percent = dport_50percent + 1
        if count_percent >= 75:
            dport_75percent = dport_75percent + 1
            
    number_sport_20percent.append(sport_20percent)
    number_sport_35percent.append(sport_35percent)
    number_sport_50percent.append(sport_50percent)
    number_sport_75percent.append(sport_75percent)
    number_dport_20percent.append(dport_20percent)
    number_dport_35percent.append(dport_35percent)
    number_dport_50percent.append(dport_50percent)
    number_dport_75percent.append(dport_75percent)
    
    src = train_data_subset['IP src'].value_counts()
    dst = train_data_subset['IP dst'].value_counts()
    
    src_20percent = 0
    src_35percent = 0
    src_50percent = 0
    src_75percent = 0
        
    dst_20percent = 0
    dst_35percent = 0
    dst_50percent = 0
    dst_75percent = 0
        
    for key in src.keys():
        count_percent = (src.get(key) / batch_packets)*100
        if count_percent >= 20:
            src_20percent = src_20percent + 1
        if count_percent >= 35:
            src_35percent = src_35percent + 1
        if count_percent >= 50:
            src_50percent = src_50percent + 1
        if count_percent >= 75:
            src_75percent = src_75percent + 1
                
    for key in dst.keys():
        count_percent = (dst.get(key) / batch_packets)*100
        if count_percent >= 20:
            dst_20percent = dst_20percent + 1
        if count_percent >= 35:
            dst_35percent = dst_35percent + 1
        if count_percent >= 50:
            dst_50percent = dst_50percent + 1
        if count_percent >= 75:
            dst_75percent = dst_75percent + 1  
                
    number_src_20percent.append(src_20percent)
    number_src_35percent.append(src_35percent)
    number_src_50percent.append(src_50percent)
    number_src_75percent.append(src_75percent)
    number_dst_20percent.append(dst_20percent)
    number_dst_35percent.append(dst_35percent)
    number_dst_50percent.append(dst_50percent)
    number_dst_75percent.append(dst_75percent)
    
    total_IPbytes=0
    for index, row in train_data_subset.iterrows():
        total_IPbytes = total_IPbytes + row['IP len']
    average_IP_bytes.append(total_IPbytes/batch_packets)
    
    attack_aggregate=0
    for index, row in train_data_subset.iterrows():
        attack_aggregate = attack_aggregate + row['Attack']
    attack_aggregate_list.append(attack_aggregate/batch_packets)
    
    incoming_ips = train_data_subset['IP dst'].value_counts()
    outgoing_ips = train_data_subset['IP src'].value_counts()
    if '10.0.0.5' in incoming_ips:
        incom_pkts = incoming_ips.get('10.0.0.5')
    else:
        incom_pkts = 1
            
    if '10.0.0.5' in outgoing_ips:
        outgo_pkts = outgoing_ips.get('10.0.0.5')
    else:
        outgo_pkts = 1
            
    ratio_incom_to_outgo.append(incom_pkts/outgo_pkts)
    number_uniq_incom_ips.append(incoming_ips.size)
    
    extracted_data= pd.DataFrame()
    extracted_data['number_of_ACK']=number_of_ACK
    extracted_data['number_of_SYN']=number_of_SYN
    extracted_data['number_of_RST']=number_of_RST
    extracted_data['number_of_PA']=number_of_PA
    extracted_data['number_of_FA']=number_of_FA
    extracted_data['number_of_SA']=number_of_SA
    extracted_data['number_of_FPA']=number_of_FPA
    extracted_data['number_of_RA']=number_of_RA

    extracted_data['ratio_syn_ack']=ratio_syn_ack
    extracted_data['ratio_ack_rst']=ratio_ack_rst
    extracted_data['ratio_syn_rst']=ratio_syn_rst

    extracted_data['number_sport_20percent']=number_sport_20percent
    extracted_data['number_sport_35percent']=number_sport_35percent
    extracted_data['number_sport_50percent']=number_sport_50percent
    extracted_data['number_sport_75percent']=number_sport_75percent
    extracted_data['number_dport_20percent']=number_dport_20percent
    extracted_data['number_dport_35percent']=number_dport_35percent
    extracted_data['number_dport_50percent']=number_dport_50percent
    extracted_data['number_dport_75percent']=number_dport_75percent

    extracted_data['number_src_20percent']=number_src_20percent
    extracted_data['number_src_35percent']=number_src_35percent
    extracted_data['number_src_50percent']=number_src_50percent
    extracted_data['number_src_75percent']=number_src_75percent
    extracted_data['number_dst_20percent']=number_dst_20percent
    extracted_data['number_dst_35percent']=number_dst_35percent
    extracted_data['number_dst_50percent']=number_dst_50percent
    extracted_data['number_dst_75percent']=number_dst_75percent

    extracted_data['average_IP_bytes']=average_IP_bytes
    extracted_data['ratio_incom_to_outgo']=ratio_incom_to_outgo
    extracted_data['number_uniq_ips']=number_uniq_incom_ips
    extracted_data['attack_aggregate']=attack_aggregate_list
    
    
    return extracted_data


import matplotlib.pyplot as plt 
from sklearn.model_selection import learning_curve
def plot_learning_curve(estimator, title, X, y, ylim=None, cv=None,
                        n_jobs=-1, train_sizes=np.linspace(.1, 1.0, 5)):
    """Generate a simple plot of the test and training learning curve"""
    plt.figure()
    plt.title(title)
    if ylim is not None:
        plt.ylim(*ylim)
    plt.xlabel("Training examples")
    plt.ylabel("Score")
    train_sizes, train_scores, test_scores = learning_curve(
        estimator, X, y, cv=cv, n_jobs=n_jobs, train_sizes=train_sizes)
    train_scores_mean = np.mean(train_scores, axis=1)
    train_scores_std = np.std(train_scores, axis=1)
    test_scores_mean = np.mean(test_scores, axis=1)
    test_scores_std = np.std(test_scores, axis=1)
    plt.grid()

    plt.fill_between(train_sizes, train_scores_mean - train_scores_std,
                     train_scores_mean + train_scores_std, alpha=0.1,
                     color="r")
    plt.fill_between(train_sizes, test_scores_mean - test_scores_std,
                     test_scores_mean + test_scores_std, alpha=0.1, color="g")
    plt.plot(train_sizes, train_scores_mean, 'o-', color="r",
             label="Training score")
    plt.plot(train_sizes, test_scores_mean, 'o-', color="g",
             label="Cross-validation score")

    plt.legend(loc="best")
    return plt

    
print("Starting pcap to csv conversion...")
fname = '/Users/shyamabs/Documents/DDoD_ML_MS/datasets/data_3.pcap'
#csvfile=pcapToCsv(fname)
csvfile='/Users/shyamabs/Documents/DDoD_ML_MS/datasets/training_data_captured3.csv'
print("Output csv file name "+csvfile )

data = pd.read_csv(csvfile)
#print(train_data.head())

print("Pcap to CSV conversion completed!")
print("")

batch_packets = 100

# =============================================================================
# ratio_ack_syn, ratio_ack_rst, ratio_syn_rst, number_of_ACK, number_of_SYN, number_of_RST, number_of_PA, number_of_FA, number_of_SA, number_of_FPA, number_of_RA = getFlagNumbers(train_data, batch_packets)
# number_sport_20percent, number_sport_35percent, number_sport_50percent, number_sport_75percent, number_dport_20percent, number_dport_35percent, number_dport_50percent, number_dport_75percent = tcp_dport_sport_numbers(train_data, batch_packets)
# number_src_20percent, number_src_35percent, number_src_50percent, number_src_75percent, number_dst_20percent, number_dst_35percent, number_dst_50percent, number_dst_75percent = ip_src_dst_numbers(train_data, batch_packets)
# average_IP_bytes = get_average_IP_bytes(train_data, batch_packets)
# attack_aggregate_list = get_attack_aggregate(train_data, batch_packets)
# #print("number_of_ACK: ",number_of_ACK)
# #print("number_of_SYN: ",number_of_SYN)
# #print("number_of_RST: ",number_of_RST)
# 
# extracted_data= pd.DataFrame()
# extracted_data['number_of_ACK']=number_of_ACK
# extracted_data['number_of_SYN']=number_of_SYN
# extracted_data['number_of_RST']=number_of_RST
# extracted_data['number_of_PA']=number_of_PA
# extracted_data['number_of_FA']=number_of_FA
# extracted_data['number_of_SA']=number_of_SA
# extracted_data['number_of_FPA']=number_of_FPA
# extracted_data['number_of_RA']=number_of_RA
# 
# extracted_data['ratio_ack_syn']=ratio_ack_syn
# extracted_data['ratio_ack_rst']=ratio_ack_rst
# extracted_data['ratio_syn_rst']=ratio_syn_rst
# 
# extracted_data['number_sport_20percent']=number_sport_20percent
# extracted_data['number_sport_35percent']=number_sport_35percent
# extracted_data['number_sport_50percent']=number_sport_50percent
# extracted_data['number_sport_75percent']=number_sport_75percent
# extracted_data['number_dport_20percent']=number_dport_20percent
# extracted_data['number_dport_35percent']=number_dport_35percent
# extracted_data['number_dport_50percent']=number_dport_50percent
# extracted_data['number_dport_75percent']=number_dport_75percent
# 
# extracted_data['number_src_20percent']=number_src_20percent
# extracted_data['number_src_35percent']=number_src_35percent
# extracted_data['number_src_50percent']=number_src_50percent
# extracted_data['number_src_75percent']=number_src_75percent
# extracted_data['number_dst_20percent']=number_dst_20percent
# extracted_data['number_dst_35percent']=number_dst_35percent
# extracted_data['number_dst_50percent']=number_dst_50percent
# extracted_data['number_dst_75percent']=number_dst_75percent
# 
# extracted_data['average_IP_bytes']=average_IP_bytes
# extracted_data['attack_aggregate']=attack_aggregate_list
# =============================================================================


total_packets=data.shape[0] 
print("Starting Feature Extraction...")

extracted_data = extract_features(data, batch_packets, total_packets)

print("Feature Extraction Completed!")
print()

#extracted_data  = pd.read_csv('/Users/shyamabs/Documents/DDoD_ML_MS/training_data_extracted2.csv', index_col=0)
#print("extracted_data: ")
#print(extracted_data.head())

extracted_data.to_csv('/Users/shyamabs/Documents/DDoD_ML_MS/datasets/training_data_extracted_3.csv')

print("Starting Preprocessing...")

from sklearn.model_selection import train_test_split
y = extracted_data ['attack_aggregate']
x = extracted_data.loc[:, extracted_data.columns != 'attack_aggregate']
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=0)

train_data = pd.concat([x_train, y_train], axis=1)
test_data = pd.concat([x_test, y_test], axis=1)

print(x_train.shape)
print(x_test.shape)
print(y_train.shape)
print(y_test.shape)
print(train_data.head())

import seaborn as sns
from scipy.stats import norm, skew
#sns.distplot(train_data['attack_aggregate'], fit=norm)
#train_data["attack_aggregate"] = np.log1p(train_data["attack_aggregate"])

# =============================================================================
# bins = [-1, 0.4, 0.7, 1]
# labels = [1,2, 3]
# =============================================================================

bins = [-1, 0.4, 1]
labels = [1,2]

train_data['attack_aggregate'] = pd.cut(train_data['attack_aggregate'],bins=bins, labels=labels)
test_data['attack_aggregate'] = pd.cut(test_data['attack_aggregate'],bins=bins, labels=labels)

#Computing correlation
corrmat = train_data.corr()

#Dropping the below features after computing correlation

poor_corr_cols = ["number_of_PA", "number_sport_35percent", "number_sport_75percent", "number_dport_20percent", "number_dport_35percent", "number_of_RA", "number_src_35percent", "number_dst_35percent"]
#poor_corr_cols = ["number_of_PA", "number_sport_35percent", "number_sport_75percent", "number_dport_20percent", "number_dport_35percent", "number_of_RA", "number_src_35percent"]
train_data =train_data.drop(poor_corr_cols, axis=1)
test_data = test_data.drop(poor_corr_cols, axis=1)

# =============================================================================
# #features heavily skewed. (skew greater than 0.5)
# skewness = train_data.apply(lambda x: skew(x))
# skewness = skewness[abs(skewness) > 0.5]
# 
# #applying log tranform on the skewed features
# skewed_features = skewness.index
# for feat in skewed_features:
#     train_data[feat] = train_data[feat].map(lambda i: np.log(i) if i > 0 else 0)
# =============================================================================


# from scipy.special import boxcox1p
# skewed_features = skewness.index
# lam = 0.15
# for feat in skewed_features:
#     train_data[feat] = boxcox1p(train_data[feat], lam)

#Starting with modelling
x_train = train_data.drop(labels = ["attack_aggregate"],axis = 1)
x_test = test_data.drop(labels = ["attack_aggregate"],axis = 1)

y_train = train_data["attack_aggregate"]
y_test = test_data["attack_aggregate"]

#Using standard scaler to scale the features:
# =============================================================================
# from sklearn.preprocessing import StandardScaler
# stdSc = StandardScaler()
# x_train_std = stdSc.fit_transform(x_train)
# x_test_std = stdSc.transform(x_test)
# =============================================================================

from sklearn.model_selection import StratifiedKFold, cross_val_score, GridSearchCV
kfold = StratifiedKFold(n_splits=10)


# Testing certain algorithms 
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier

classifiers = []
classifiers.append(SVC(random_state=2))
classifiers.append(LogisticRegression(random_state=2))
classifiers.append(KNeighborsClassifier())
classifiers.append(DecisionTreeClassifier(random_state=2))
classifiers.append(RandomForestClassifier(random_state=2))
classifiers.append(GradientBoostingClassifier(random_state=2))
classifiers.append(AdaBoostClassifier(DecisionTreeClassifier(random_state=2),random_state=2,learning_rate=0.1))
classifiers.append(MLPClassifier(random_state=2))
classifiers.append(ExtraTreesClassifier(random_state=2))


CV_results = []
CV_means = []
CV_std = []

for classifier in classifiers :
    CV_results.append(cross_val_score(classifier, x_train, y_train, scoring = "accuracy", cv = kfold, n_jobs=1))

for CV_result in CV_results:
    CV_means.append(CV_result.mean())
    CV_std.append(CV_result.std())

CV_res_data = pd.DataFrame({"CVmeans":CV_means,"CVerrors": CV_std,"Algorithm":["SVC","LogisticRegression", "KNeighboors", "DecisionTree","RandomForest","GradientBoosting",
                                                                               "AdaBoostClassifier", "MultipleLayerPerceptron", "ExtraTreesClassifier"]})
from matplotlib import pyplot
a4_dims = (12, 9)
fig, ax = pyplot.subplots(figsize=a4_dims)

graph = sns.barplot("CVmeans","Algorithm",ax=ax, data = CV_res_data.sort_values(by=['CVmeans'], ascending=False),orient = "h",**{'xerr':CV_std})
graph.set_xlabel("Mean Accuracy")
graph = graph.set_title("Cross validation scores")

CV_res_data.sort_values(by=['CVmeans'], ascending=False)


## *******************REWRITE THE CODE BELOW*******************************



### META MODELING  WITH ADABOOST, RF, EXTRATREES and GRADIENTBOOSTING

# Adaboost
DTC = DecisionTreeClassifier()
adaDTC = AdaBoostClassifier(DTC, random_state=1)
ada_param_grid = {"base_estimator__criterion" : ["gini", "entropy"],
              "base_estimator__splitter" :   ["best", "random"],
              "algorithm" : ["SAMME","SAMME.R"],
              "n_estimators" :[1,2],
              "learning_rate":  [0.0001, 0.001, 0.01, 0.1, 0.2, 0.3,1.5]}
gsadaDTC = GridSearchCV(adaDTC,param_grid = ada_param_grid, cv=kfold, scoring="accuracy", n_jobs= 4, verbose = 1)
gsadaDTC.fit(x_train,y_train)
ada_best = gsadaDTC.best_estimator_

g = plot_learning_curve(gsadaDTC.best_estimator_,"AdaBoost learning curves",x_train,y_train,cv=kfold)


#ExtraTrees 
ExtC = ExtraTreesClassifier()
## Search grid for optimal parameters
ex_param_grid = {"max_depth": [None],
              "max_features": [1, 3, 10],
              "min_samples_split": [2, 3, 10],
              "min_samples_leaf": [1, 3, 10],
              "bootstrap": [False],
              "n_estimators" :[100,300],
              "criterion": ["gini"]}
gsExtC = GridSearchCV(ExtC,param_grid = ex_param_grid, cv=kfold, scoring="accuracy", n_jobs= 4, verbose = 1)
gsExtC.fit(x_train,y_train)
ExtC_best = gsExtC.best_estimator_
gsExtC.best_score_

g = plot_learning_curve(gsExtC.best_estimator_,"ExtraTrees learning curves",x_train,y_train,cv=kfold)



# RFC Parameters tunning 
RFC = RandomForestClassifier()
## Search grid for optimal parameters
rf_param_grid = {"max_depth": [None],
              "max_features": [1, 3, 10],
              "min_samples_split": [2, 3, 10],
              "min_samples_leaf": [1, 3, 10],
              "bootstrap": [False],
              "n_estimators" :[100,300],
              "criterion": ["gini"]}
gsRFC = GridSearchCV(RFC,param_grid = rf_param_grid, cv=kfold, scoring="accuracy", n_jobs= 4, verbose = 1)
gsRFC.fit(x_train,y_train)
RFC_best = gsRFC.best_estimator_
# Best score
gsRFC.best_score_

g = plot_learning_curve(gsRFC.best_estimator_,"RF mearning curves",x_train,y_train,cv=kfold)



# Gradient boosting tunning
GBC = GradientBoostingClassifier()
gb_param_grid = {'loss' : ["deviance"],
              'n_estimators' : [100,200,300],
              'learning_rate': [0.1, 0.05, 0.01],
              'max_depth': [4, 8],
              'min_samples_leaf': [100,150],
              'max_features': [0.3, 0.1] 
              }

gsGBC = GridSearchCV(GBC,param_grid = gb_param_grid, cv=kfold, scoring="accuracy", n_jobs= 4, verbose = 1)
gsGBC.fit(x_train,y_train)
GBC_best = gsGBC.best_estimator_
gsGBC.best_score_

g = plot_learning_curve(gsGBC.best_estimator_,"GradientBoosting learning curves",x_train,y_train,cv=kfold)


### SVC classifier
SVMC = SVC(probability=True)
svc_param_grid = {'kernel': ['rbf'], 
                  'gamma': [ 0.001, 0.01, 0.1, 1],
                  'C': [1, 10, 50, 100,200,300, 1000]}

gsSVMC = GridSearchCV(SVMC,param_grid = svc_param_grid, cv=kfold, scoring="accuracy", n_jobs= 4, verbose = 1)
gsSVMC.fit(x_train,y_train)
SVMC_best = gsSVMC.best_estimator_
# Best score
gsSVMC.best_score_

g = plot_learning_curve(gsSVMC.best_estimator_,"SVC learning curves",x_train,y_train,cv=kfold)


#Feature importance of the tree based classifiers
nrows = ncols = 2
fig, axes = plt.subplots(nrows = nrows, ncols = ncols, sharex="all", figsize=(25,25))

names_classifiers = [("AdaBoosting", ada_best),("ExtraTrees",ExtC_best),("RandomForest",RFC_best),("GradientBoosting",GBC_best)]

nclassifier = 0
for row in range(nrows):
    for col in range(ncols):
        name = names_classifiers[nclassifier][0]
        classifier = names_classifiers[nclassifier][1]
        indices = np.argsort(classifier.feature_importances_)[::-1][:40]
        g = sns.barplot(y=x_train.columns[indices][:40],x = classifier.feature_importances_[indices][:40] , orient='h',ax=axes[row][col])
        g.set_xlabel("Relative importance",fontsize=12)
        g.set_ylabel("Features",fontsize=12)
        g.tick_params(labelsize=9)
        g.set_title(name + " feature importance")
        nclassifier += 1


#Combining Classifiers
votingC = VotingClassifier(estimators=[('rfc', RFC_best), ('extc', ExtC_best),
('svc', SVMC_best), ('adac',ada_best),('gbc',GBC_best)], voting='soft', n_jobs=4)
votingC = votingC.fit(x_train, y_train)

#removing adaboost
votingC_withoutada = VotingClassifier(estimators=[('rfc', RFC_best), ('extc', ExtC_best),
('svc', SVMC_best),('gbc',GBC_best)], voting='soft', n_jobs=4)
votingC_withoutada = votingC_withoutada.fit(x_train, y_train)



import pickle
pickle.dump(votingC, open('ensemble_model_nonSpoof.sav', 'wb'))
#pickle.dump(votingC, open('ensemble_model_10batch.sav', 'wb'))
pickle.dump(votingC_withoutada, open('ensemble_model_nonSpoof_withoutada.sav', 'wb'))


loaded_model = pickle.load(open('ensemble_model_nonSpoof.sav', 'rb'))
y_pred = loaded_model.predict(x_test)

IDtest = x_test.index.values
y_pred_df = pd.DataFrame(y_pred, index = IDtest)


loaded_model_withoutada = pickle.load(open('ensemble_model_nonSpoof_withoutada.sav', 'rb'))
y_pred_withoutada = loaded_model_withoutada.predict(x_test)

IDtest = x_test.index.values
y_pred_df_withoutada = pd.DataFrame(y_pred_withoutada, index = IDtest)


block_ips = []
block_indices = y_pred_df.index[y_pred_df[0] == 2]
for i in block_indices:
    if x_test.loc[i]['number_src_50percent']>0:
        index_from = i*batch_packets
        index_to = index_from + batch_packets
        #src_ips_df = pd.DataFrame(data.iloc[index_from:index_to]['IP src'])
        packet_list = data.iloc[index_from:index_to]
        src_ips = packet_list['IP src'].value_counts()
        for key in src_ips.keys():
            if src_ips.get(key)>=batch_packets/2 and key!='10.0.0.5':
                block_ips.append(key)
block_ips_series = pd.Series(block_ips)
block_ip_toSave= pd.Series(block_ips_series.value_counts().keys().values)

print("The below Ips need to be blocked!")
print(block_ip_toSave)


safe_ips = []
safe_indices = y_pred_df.index[y_pred_df[0] == 1]
for i in safe_indices:
    if x_test.loc[i]['number_src_50percent']==0:
        index_from = i*batch_packets
        index_to = index_from + batch_packets
        #src_ips_df = pd.DataFrame(data.iloc[index_from:index_to]['IP src'])
        packet_list = data.iloc[index_from:index_to]
        src_ips = packet_list['IP src'].value_counts()
        for key in src_ips.keys():
            if src_ips.get(key)<=batch_packets/2:
                safe_ips.append(key)
safe_ips_series = pd.Series(safe_ips)
safe_ips_toSave= pd.Series(safe_ips_series.value_counts().keys().values)

print("The below Ips need to be whitelisted!")
print(safe_ips_toSave)






spoof_model = pickle.load(open('ensemble_model_spoof.sav', 'rb'))
non_spoof_model = pickle.load(open('ensemble_model_nonSpoof.sav', 'rb'))
votingC_combined = VotingClassifier(estimators=[('spoofmodel', spoof_model), ('nonspoofmodel', non_spoof_model)], voting='soft', n_jobs=4)
votingC_combined = votingC_combined.fit(x_train, y_train)

pickle.dump(votingC_combined, open('ensemble_model_combined.sav', 'wb'))

loaded_combined_model = pickle.load(open('ensemble_model_combined.sav', 'rb'))
y_pred_combined = loaded_combined_model.predict(x_test)
IDtest = x_test.index.values
y_pred_combined_df = pd.DataFrame(y_pred_combined, index = IDtest)


from sklearn.metrics import accuracy_score
acc_nonspoof_combined = accuracy_score (y_pred_combined_df, y_test)
acc_nonspoof_combined

acc_spoof = accuracy_score (y_pred, y_test)
acc_spoof

y_pred_nonspoof_nonspoofmodel = non_spoof_model.predict(x_test)
acc_nonspoof_nonspoofmodel = accuracy_score (y_pred_nonspoof_nonspoofmodel, y_test)
acc_nonspoof_nonspoofmodel

y_pred_nonspoof_spoofmodel = spoof_model.predict(x_test)
acc_nonspoof_spoofmodel = accuracy_score (y_pred_nonspoof_spoofmodel, y_test)
acc_nonspoof_spoofmodel





spoof_model = pickle.load(open('ensemble_model_spoof.sav', 'rb'))
non_spoof_model_withoutada = pickle.load(open('ensemble_model_nonSpoof_withoutada.sav', 'rb'))
votingC_combined_withoutada = VotingClassifier(estimators=[('spoofmodel', spoof_model), ('nonspoofmodel', non_spoof_model_withoutada)], voting='soft', n_jobs=4)
votingC_combined_withoutada = votingC_combined_withoutada.fit(x_train, y_train)

#pickle.dump(votingC_combined, open('ensemble_model_combined.sav', 'wb'))

loaded_combined_model = pickle.load(open('ensemble_model_combined.sav', 'rb'))
y_pred_combined = loaded_combined_model.predict(x_test)
IDtest = x_test.index.values
y_pred_combined_df = pd.DataFrame(y_pred_combined, index = IDtest)


from sklearn.metrics import accuracy_score
acc_nonspoof_combined = accuracy_score (y_pred_combined_df, y_test)
acc_nonspoof_combined

acc_spoof = accuracy_score (y_pred, y_test)
acc_spoof

y_pred_nonspoof_nonspoofmodel_withoutada = non_spoof_model_withoutada.predict(x_test)
acc_nonspoof_nonspoofmodel_withoutada = accuracy_score (y_pred_nonspoof_nonspoofmodel_withoutada, y_test)
acc_nonspoof_nonspoofmodel_withoutada

y_pred_nonspoof_spoofmodel = spoof_model.predict(x_test)
acc_nonspoof_spoofmodel = accuracy_score (y_pred_nonspoof_spoofmodel, y_test)
acc_nonspoof_spoofmodel


# =============================================================================
#Predicting Test Data
# test_Survived = pd.Series(votingC.predict(test), name="Survived")
# results = pd.concat([IDtest,test_Survived],axis=1)
# results.to_csv("ensemble_python_voting.csv",index=False)
# =============================================================================

#map_dict = {0: "N", 1: "Y"}
#train_data["attack_aggregate"]=train_data["attack_aggregate"].map(map_dict)
#test_data["attack_aggregate"]=test_data["attack_aggregate"].map(map_dict)

# =============================================================================
# import matplotlib.pyplot as plt 
# fig, ax = plt.subplots()
# ax.scatter(x = train_data['number_of_ACK'], y = train_data['attack_aggregate'])
# 
# corrmat = train_data.corr()
# plt.subplots(figsize=(12,9))
# sns.heatmap(corrmat, vmax=0.9, square=True)
# 
# numeric_feats = train_data.dtypes[train_data.dtypes != "object"].index
# # Check the skew of all numerical features
# skewed_feats = train_data[numeric_feats].apply(lambda x: skew(x.dropna())).sort_values(ascending=False)
# print("\nSkew in numerical features: \n")
# skewness = pd.DataFrame({'Skew' :skewed_feats})
# skewness.head(10)
# skewness = skewness[abs(skewness) > 0.75]
# print("There are {} skewed numerical features to Box Cox transform".format(skewness.shape[0]))
# 
# 
# from scipy.special import boxcox1p
# skewed_features = skewness.index
# lam = 0.15
# for feat in skewed_features:
#     #all_data[feat] += 1
#     train_data[feat] = boxcox1p(train_data[feat], lam)
#     
# print("Find most important features relative to target")
# corr = train_data.corr()
# corr.sort_values(["attack_aggregate"], ascending = False, inplace = True)
# print(corr.attack_aggregate)
# 
# train_no_target = train_data.drop('attack_aggregate', axis=1)
# 
# skewness = train_no_target.apply(lambda x: skew(x))
# skewness = skewness[abs(skewness) > 0.5]
# print(str(skewness.shape[0]) + " skewed numerical features to log transform")
# skewed_features = skewness.index
# train_no_target[skewed_features] = np.log1p(train_no_target[skewed_features])
# 
# from sklearn.preprocessing import StandardScaler
# stdSc = StandardScaler()
# x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=1)
# x_train.loc[:, numerical_features] = stdSc.fit_transform(X_train.loc[:, numerical_features])
# x_test.loc[:, numerical_features] = stdSc.transform(X_test.loc[:, numerical_features])
# =============================================================================

# =============================================================================
# from sklearn.preprocessing import StandardScaler
# sc = StandardScaler()
# x_train = sc.fit_transform(x_train)
# x_test = sc.fit_transform(x_test)
# =============================================================================



# =============================================================================
# fig = plt.figure(figsize=(15,10))
# sns.heatmap(df.corr(),annot=True,cmap='coolwarm',linewidths=0.2)
# plt.show()
# =============================================================================
