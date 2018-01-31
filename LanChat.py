from threading import Thread

from scapy.all import *

found_ips = []

def arp_found(packet):
    found_ip = packet[0][ARP].psrc
    if found_ip not in found_ips:
        found_ips.append(found_ip)

def run_sniff():
    sniff(filter="arp",prn=arp_found)

sniff_thread = Thread(target=run_sniff)
sniff_thread.start()