#!/bin/bash
#echo "Starting Floodlight Firewall - All Allow Mode"
#./startFirewall.sh
#sshpass -p "mininet" ssh 10.0.0.5
while true;
do
	#printf "\ntcpdump capture started.\n"
	sudo timeout 1 tcpdump -w data1.pcap -i h5-eth0 tcp
	#printf "\n\ntcpdump capture stopped. Starting prediction for the captured packets\n"  	
	#if [[ $(tcpdump -r data1.pcap | wc -l) >0 ]];
	#then
	#if [[ -f "data1.pcap" && -s "data1.pcap" ]];
	#then	
	python3 -W ignore AttackPrediction.py
		#printf "\n"
	sudo rm data1.pcap
	#fi
done

