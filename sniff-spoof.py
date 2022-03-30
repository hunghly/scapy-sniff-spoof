#!/usr/bin/env python3
from scapy.all import *

"""In this task, you will combine the sniffing and spoofing techniques to implement the following sniff-and- then-spoof program. 
You need two machines on the same LAN: the VM and the user container. From the user container, you ping an IP X. This will generate
an ICMP echo request packet. If X is alive, the ping program will receive an echo reply, and print out the response. Your sniff-and-then-spoof
program runs on the VM, which monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request, regardless of what the 
target IP address is, your program should immediately send out an echo reply using the packet spoofing technique. Therefore, regardless of 
whether machine X is alive or not, the ping program will always receive a reply, indicating that X is alive. You need to use Scapy to do this task. 
In your report, you need to provide evidence to demonstrate that your technique works."""

# Set up sniffer on network 
def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-9ad767b9f85c', filter='icmp', prn=print_pkt)

