#!/bin/bash
echo "starting floodlight controller in the background...."
cd /home/mininet/floodlight/
nohup sudo java -jar /home/mininet/floodlight/target/floodlight.jar
echo "starting mininet 5 host 5 switch topology...."
nohup sudo /home/mininet/src/myTopo.py
