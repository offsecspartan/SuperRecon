#!/usr/bin/bash

import sys,os,subprocess


def webEnum(target,port,protocol):
	print ""
	print "++++++++++++++++++++"
	print "Web"
	print "++++++++++++++++++++"
	print ""

	gobuster(target, port, protocol)

def gobuster(target, port, protocol):
	
	print ""
	print "++++++++++"
	print "GoBuster!"
	print "++++++++++"
	print ""

	url = ""
	if protocol == "http":
		url = "http://%s:%s" % (target, port)
	else:
		url = "https://%s:%s" % (target, port)

	gobusterCmd = "gobuster -w /usr/share/wordlists/dirb/common.txt -u %s" % url
	try:
		gobusterCmdResults = subprocess.check_output(gobusterCmd, shell=True)
		gobusterResults = gobusterCmdResults.split("\n")
		
		print ""
		print "Interesting results for %s" % url
		print ""
		
		for gobusterResult in gobusterResults:
			if ("/" in gobusterResult) and ("(" in gobusterResult):
				gobusterResult = ' '.join(gobusterResult.split())
				print gobusterResult
	except:
		print "Ran into some kind of error..."
		e = sys.exc_info()[0]
		print e

target = sys.argv[1]

print ""
print """\
  ______                         ______                         
 / _____)                       (_____ \                        
( (____  _   _ ____  _____  ____ _____) )_____  ____ ___  ____  
 \____ \| | | |  _ \| ___ |/ ___)  __  /| ___ |/ ___) _ \|  _ \ 
 _____) ) |_| | |_| | ____| |   | |  \ \| ____( (__| |_| | | | |
(______/|____/|  __/|_____)_|   |_|   |_|_____)\____)___/|_| |_|
              |_|                                               
"""

print ""
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "Performing initial scan of target %s" % target
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print ""

initialNmap = "nmap -Pn -T4 -sS -O %s -oA %s" % (target, target)

try:
	initialNmapResults = subprocess.check_output(initialNmap, shell=True)
except:
	print "Ran into some kind of error..."

initialNmap = "nmap -T 4 -sU %s --top-ports 100 -oA %s" % (target, target + "UDP")

try:
	nmapUdpResults = subprocess.check_output(initialNmap, shell=True)
	initialNmapResults += nmapUdpResults
except:
	print "Ran into some kind of error..."

tcpPorts = []
udpPorts = []

results = initialNmapResults.split("\n")
for result in results:
	if ("/" in result) and ("open " in result):
		result = ' '.join(result.split())
		split = result.split(" ")
		protocol = split[0].split("/")[1]
                port = split[0].split("/")[0]
		print "Open port:\t %s %s %s" % (protocol, port, split[2])
		if protocol == "tcp":
			tcpPorts.append(port)
		else:
			udpPorts.append(port)

print ""
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "Performing service versioning."
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print ""


serviceInput = ""
for tcpPort in tcpPorts:
	serviceInput += tcpPort + ","
serviceInput = serviceInput[:-1]
serviceScan = "nmap -sV -p %s %s -oA %s" % (serviceInput, target, target + "services")

try:
        serviceScanResults = subprocess.check_output(serviceScan, shell=True)
	serviceResults = serviceScanResults.split("\n")
	for serviceResult in serviceResults:
		if ("/" in serviceResult) and ("open" in serviceResult):
			print serviceResult
except:
        print "Ran into some kind of error..."

print ""
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "Performing service-specific enumeration."
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print ""

serviceResults = serviceScanResults.split("\n")
for serviceResult in serviceResults:
	if ("/" in serviceResult) and ("open " in serviceResult):
		serviceResult = ' '.join(serviceResult.split())
		serviceSplit = serviceResult.split(" ")
		service = serviceSplit[2]
		servicePort = serviceSplit[0]

		if "http" in service:
			if "ssl" in service:
				webEnum(target, servicePort.split("/")[0],"https")
			else:
				webEnum(target, servicePort.split("/")[0],"http")
