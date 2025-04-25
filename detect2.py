#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

SYN_senders = {}

def parsePacket(packet):    
    if not packet.haslayer("TCP"): return

    if IP in packet and TCP in packet:
        if packet[TCP].flags.S and not packet[TCP].flags.SA:
            if packet[IP].src not in SYN_senders:

                # Collect the SYNACK source IP
                SYN_senders[packet[IP].src] = {
                        "syn" : 1,
                        "synack" : 0
                    }
            else:
                # Collect the SYNACK source IP
                SYN_senders[packet[IP].src]["syn"] += 1

        if packet[TCP].flags.SA:
            # Collect the SYNACK destination IP
            SYN_senders[packet[IP].dst]["synack"] += 1

    return

if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]): 
        parsePacket(packet)

    for ip, data in SYN_senders.items():
        # IP address that never received SYNACK packets and sent more than 3
        if data["synack"] == 0:
            if data["syn"] > 3:
                print(f"IP:{ip}, SYN:{data['syn']}, SYNACK:{data['synack']}")

        # IP addresses that issue 3 times more SYN than SYNACK packets
        elif data["syn"] / data["synack"] > 3:
            print(f"IP:{ip}, SYN:{data['syn']}, SYNACK:{data['synack']}")


