#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.show()

# ifaces = ['br-9ad767b9f85c', 'enp0s3']
def print_pkt(pkt):
    pkt.show()

# capture only icmp
pkt = sniff(iface='enp0s3', filter='icmp', prn=print_pkt)

#capture tcp packet from particular ip, capture packets from a particular subnet