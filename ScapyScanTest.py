#!/usr/bin/env python
# Test file for scanning and listing possible targets

import sys
from scapy.all import *

conf.iface = "wlan0mon"
amount = 50 #amount of packages that will be listened to before 

sniff(iface="wlan0mon", prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%}"), count=amount) #Returns the following: FF:FF:FF:FF:FF:FF <ESSID>

