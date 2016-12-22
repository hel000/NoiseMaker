#!/usr/bin/env python
# Test file for scanning and listing possible targets

import sys
from scapy.all import *

intface = "wlan0mon"
amount = 50 #amount of packages that will be listened to before 
target = {}

#sniff(iface=intface, prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%:%Dot11Beacon.info%}"), count=1) #Returns the following: FF:FF:FF:FF:FF:FF <ESSID>
a = sniff(iface=intface, count=amount) # Stores all the captured information in a. a.addrx for dest and source
# use a[9].payload.payload.info for the SSID

for b in a:
    if str(b.summary()).find("Dot11Beacon"):
        print b.addr2
        target[b.addr2] = b.payload.payload.info

print "Choose from these targets:"
print target
for c, value in target:
    print c + ":" + value
    
