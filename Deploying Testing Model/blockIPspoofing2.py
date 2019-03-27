#!/usr/bin/env python3
import json
import urllib.request
import requests
import os

req = urllib.request.Request("http://localhost:8080/wm/firewall/rules/json")
res = urllib.request.urlopen(req)
json_string = res.read().decode('utf-8')
json_data = json.loads(json_string)
#print(json_string)
for rule in json_data:
	if(rule['dpid'] == "00:00:00:00:00:00:00:04"):
		ruleid = rule['ruleid']
		print()
		print("Changing Firewall Rules to Whitelist IPs...")
		data = '{"ruleid":"'+str(ruleid)+'"}'
		url = 'http://localhost:8080/wm/firewall/rules/json'
		res = requests.delete(url, data=data)
		print()
		print("Whitelisting done.");
		break

os.system("rm Safe_Ips.csv")
