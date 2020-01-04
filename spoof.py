#!/usr/bin/env python3

from scapy.all import *
from colorama import Fore, init
import argparse
import sys

parse = argparse.ArgumentParser()
parse.add_argument("-r","--range",help="Range to scan or spoof")
parse.add_argument("-g","--gateway",help="Gatewat")
parse = parse.parse_args()

def get_mac(gateway):
    arp_layer = ARP(pdst=gateway)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast/arp_layer

    mac = srp(final_packet, timeout=2, verbose=False)[0]
    mac = mac[0][1].hwsrc
    return mac

def scanner(_range,gateway):
    list_hosts = dict()
    arp_layer = ARP(pdst=_range)
    broadcast = Eter(dst="ff:ff:ff:ff:ff:ff:")
    final_packet = brodcast/arp_layer

    answers = srp(final_packet, timeout=2, verbose=False)[0]
    
    print("\n")
    
    for a in ansers:
        print(a)

    
def restore_arp(destip,sourceip,hwsrc,hwdst):
    pass

def arp_spoof(hwdst, pdst,spsrc):
    pass

def main():
    if parse.range and parse.gateway:
        mac_gateway = get_mac(parse.gateway)
        print(mac_gateway)
        scanner(parse.range, parese.gateway)
    else:
        print("shit")

if __name__ == '__main__':
    main()
