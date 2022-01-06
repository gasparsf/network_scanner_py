#!/usr/bin/env python

import scapy.all as scapy   # Module not pre-installed by default in Python 3
# import optparse           # Module that allows parse parameters called through the terminal
import argparse

def get_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip_range", help="IP Range to be scanned")
    options = parser.parse_args()
    if not options.ip_range:
        parser.error("[-] Please specify the IP Range, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #The srp function allows to send packets with custom ether part

    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.ip_range)
print_result(scan_result)