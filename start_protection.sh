#!/bin/bash
#echo "Starting Floodlight Firewall - All Allow Mode"
./startFirewall.sh
sshpass -p "mininet" ssh 10.0.0.5 < ddos_protection.sh &
