from scapy.all import *

a = IP() # create IP object from IP class
a.dst = 'google.com' # sets the destination IP address
a.ttl = 2
b = ICMP() # creates an ICMP object
p = a/b # adds the object b as a payload to the object a.

ls(a)
send(p)

p.show()
ls(a)