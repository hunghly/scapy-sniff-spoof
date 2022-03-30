#!/usr/bin/python3
import sys
from scapy.all import *

num_args = sys.argv

if len(num_args) != 2:
    print("Usage: ./traceroute <ip_addr>")

destination = sys.argv[1]

a = IP() # create IP object from IP class
b = ICMP() # creates an ICMP object
p = a/b # adds the object b as a payload to the object a.
p.dst = Net(destination)
p.ttl = 1

MAX_TTL = 200

# p.show()

# Do some crazy fuzzing 
#send(IP(dst=destination)/fuzz(UDP()/NTP(version=4)),loop=1)

print(f"Your trace route to {destination} ({Net(destination)})")
while p.ttl < MAX_TTL:
    # p.summary()
    reply = sr1(p, verbose=0, timeout=2)

    if reply == None:
        print(str(p.ttl) + "\t No Reply")
        p.ttl += 1
        continue

    print(str(p.ttl) + "\t" + reply.src)
    # reply.show()

    if (reply.src == Net(destination)):
        print("Finished!")
        break
    p.ttl += 1

# p.show()
# reply.show()
# reply.summary()
