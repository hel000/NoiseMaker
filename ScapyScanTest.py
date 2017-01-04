#!/usr/bin/env python
# Test file for scanning and listing possible targets

import sys
from scapy.all import *
from dns.rdatatype import NULL

def main():
    intface = "wlan0mon"
    amount = 50 #amount of packages that will be listened to before 
    target = {}
    
    #sniff(iface=intface, prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%:%Dot11Beacon.info%}"), count=1) #Returns the following: FF:FF:FF:FF:FF:FF <ESSID>
    try:
        print "Scanning..."
        a = sniff(iface=intface, count=amount) # Stores all the captured information in a. a.addrx for dest and source
    except socket.error, e:
        print "Error, interface does not exist. " + str(e)
        return 1
    # use a[9].payload.payload.info for the SSID
    
    for b in a:
        if str(b.summary()).find("Dot11Beacon") and not str(b.addr2) == "None": #Only process the current package if it is a beacon. Also, apparently find tends to just fail at its job.
            #print b.addr2
            try:
                if str(b.payload.payload.info) is not "":
                    target[b.addr2] = b.payload.payload.info
                #else:
                    #print "Possible hidden AP found. Functionality not supported."
                    #target[b.addr2] = "<Hidden access point>"
                    #print "Caught hidden AP(?). Details: " + str(b.summary())
            except AttributeError, e: #Package was incorrect or no beacon. Removing item from dictionary.
                print "Corrupt package caught. Skipping."
    print "Choose from these targets:" 
    print target
    for c in target:
        print c + ":" + target[c]
    return target
    
if __name__ == '__main__':
    print main()