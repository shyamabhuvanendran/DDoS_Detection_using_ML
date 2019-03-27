#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 30 20:40:09 2018

@author: shyamabs
"""
#import dpkt
import codecs
from scapy.all import *
import csv
import numpy as np
import pandas as pd
import subprocess

def pcapToCsv(fname):
    #f = open('SynFlood_Sample.pcap')
    pkts=rdpcap(fname)
    #pcap = dpkt.pcap.Reader(f)
    outfile='/home/mininet/data1.csv'
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
    
    #print("Done with conversion...")
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
    #print("Total packets= ",total_packets)
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
    i=0    
    
    for i in range(batch_packets,total_packets,batch_packets):
        k=i-batch_packets
        train_data_subset=train_data[k:i]
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
    
    
    return extracted_data


    
#print("Starting pcap to csv conversion...")
fname = '/home/mininet/data1.pcap'
csvfile=pcapToCsv(fname)
#csvfile='/home/mininet/data1.csv'
#print("Output csv file name "+csvfile )

data = pd.read_csv(csvfile)
#print(data.head())

#print("Pcap to CSV conversion completed!")
#print("")

batch_packets = 100

total_packets=data.shape[0] 
#print("Starting Feature Extraction...")

extracted_data = extract_features(data, batch_packets, total_packets)

#print("Feature Extraction Completed!")
#print()

#extracted_data.to_csv('/home/mininet/data_extracted.csv')
poor_corr_cols = ["number_of_PA", "number_sport_35percent", "number_sport_75percent", "number_dport_20percent", "number_dport_35percent", "number_of_RA", "number_src_35percent", "number_dst_35percent"]
#poor_corr_cols = ["number_of_PA", "number_sport_35percent", "number_sport_75percent", "number_dport_20percent", "number_dport_35percent", "number_of_RA", "number_src_35percent"]
test_data = extracted_data.drop(poor_corr_cols, axis=1)

import pickle
loaded_model = pickle.load(open('ensemble_model.sav', 'rb'))
y_pred = loaded_model.predict(test_data)

IDtest = test_data.index.values
y_pred_df = pd.DataFrame(y_pred, index = IDtest)

ip_spoofing = 0

#Getting the IPs to block
block_ips = []
block_indices = y_pred_df.index[y_pred_df[0] == 2]
for i in block_indices:
  if test_data.loc[i]['ratio_ack_rst']<=26 or test_data.loc[i]['number_src_50percent']>0:
    index_from = i*batch_packets
    index_to = index_from + batch_packets
    #src_ips_df = pd.DataFrame(data.iloc[index_from:index_to]['IP src'])
    packet_list = data.iloc[index_from:index_to]
    src_ips = packet_list['IP src'].value_counts()
    for key in src_ips.keys():
      if src_ips.get(key)>=batch_packets/2 and key!='10.0.0.5':
        block_ips.append(key)
  
  if test_data.loc[i]['number_uniq_ips']>=50:
    #print("IP Spoofing Detected !!!")
    ip_spoofing=1

block_ips_series = pd.Series(block_ips)
block_ip_toSave= pd.Series(block_ips_series.value_counts().keys().values)
if block_ips_series.size>0:
  print("The below Ips need to be blocked!")
  block_ip_toSave.to_csv('Block_Ips.csv')
  print(block_ips_series.value_counts().keys().values)
  subprocess.call(['./blockIPs.sh'])
    

safe_ips = []


if(ip_spoofing == 1):
  #print()
  #print("IP Spoofing Detected!!!");
  #print()
  safe_indices = y_pred_df.index[y_pred_df[0] == 1]
  for i in safe_indices:
    if test_data.loc[i]['number_of_SYN']<=30:#  and test_data.loc[i]['number_src_50percent']==0: #and test_data.loc[i]['ratio_ack_rst']>26:
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
  safe_ips_toSave.to_csv('Safe_Ips.csv')
  #print()
  #print("The below safe Ips need to be whitelisted!")
  #print()
  #print(safe_ips_series.value_counts().keys().values)
  #print()
  #subprocess.call(['./blockIPspoofing.py'])

#print("Completed Prediction");
#print()
#print()
