#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    arp_request_broadcast.show()

scan("192.168.117.0/24")