#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

ftp_logins = {}

def parsePacket(packet):    

    if not packet.haslayer("TCP"): return

    if IP in packet and TCP in packet:

        ## Checks if a packet's source or destination is on port 21 (FTP)
        if packet["TCP"].dport == 21 or packet["TCP"].sport == 21:

            ## Creates a new dictionary for IP
            if packet[IP].src not in ftp_logins:
                if packet[TCP].flags == 'S':
                    ftp_logins[packet[IP].src] = {
                        "login_attempts" : 0,
                        "login_failures" : 0
                        }

            ## Gets packet data and decodes it
            data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')

            if 'USER' in data:
                ftp_logins[packet[IP].src]["login_attempts"] += 1

            if '530' in data:
                ftp_logins[packet[IP].dst]["login_failures"] += 1

    return

if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]): 
        parsePacket(packet)

    for ip, data in ftp_logins.items():
        print("IP:{ip}, REQS:{requests}, FAILS:{failures}".format(ip = ip, requests = data["login_attempts"], failures = data["login_failures"]))

