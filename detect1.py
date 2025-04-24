#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

null_ip = {}
fin_ip = {}
xmas_ip = {}
count = 0

def parsePacket(packet):    
    global count

    if not packet.haslayer("TCP"): return

    if IP in packet and TCP in packet:

        if packet[TCP].flags == 0:
            if packet[IP].src not in null_ip:
                null_ip[packet[IP].src] = 1
            else:
                null_ip[packet[IP].src] += 1
        
        if packet[TCP].flags == 'F':
            if packet[IP].src not in fin_ip:
                fin_ip[packet[IP].src] = 1
            else: 
                fin_ip[packet[IP].src] += 1

        if packet[TCP].flags.F and packet[TCP].flags.P and packet[TCP].flags.U:
            if packet[IP].src not in xmas_ip:
                xmas_ip[packet[IP].src] = 1
            else:
                xmas_ip[packet[IP].src] += 1
 


    return

if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]): 
        parsePacket(packet)


    # Print NULL scans
    for ip, count in null_ip.items():
        print(f"NULLScan, IP:{ip}, COUNT:{count}")

    # Print FIN scans
    for ip, count in fin_ip.items():
        print(f"FINScan, IP:{ip}, COUNT:{count}")

    # Print XMAS scans
    for ip, count in xmas_ip.items():
        print(f"XMASScan, IP:{ip}, COUNT:{count}")


