#!/usr/bin/env python
# Test file for scanning and listing possible targets

import sys
from scapy.all import *
from dns.rdatatype import NULL

def main(x, y): #Input is count (amount of packets to listen to and the interface to listen on
    intface = y
    amount = x #amount of packages that will be listened to before 
    target = {}
    
    try:
        print "Scanning..."
        a = sniff(iface=intface, count=amount) # Stores all the captured information in a. a.addrx for dest and source
    except socket.error, e:
        print "Error, interface does not exist. " + str(e)
        return 1
    
    for b in a:
        if str(b.summary()).find("Dot11Beacon") and not str(b.addr2) == "None": #Only process the current package if it is a beacon. Also, apparently find tends to just fail at its job.
            #print b.addr2
            try:
                if str(b.payload.payload.info) is not "":
                    target[b.addr2] = b.payload.payload.info
            except AttributeError, e: #Package was incorrect or no beacon. Removing item from dictionary.
                print "Corrupt package caught. Skipping."
    print "Choose from these targets:" 
    return target
    
if __name__ == '__main__':
    print main(500, "wlan0mon")
    
    