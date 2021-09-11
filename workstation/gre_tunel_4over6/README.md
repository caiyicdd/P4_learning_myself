Ref of tunnel : nsg-ethz/p4-learning/exercises/04-MPLS 

This is a gre tunnel example. Different with the last tunnel_6over4. We increase a new header --gre hdr. We regard the IPv4 ov IPv6 be the underlay network , which means different network can transfer packet throw the underlay network , with their own privay form .

We provide two example ipv6 over ipv4 and ipv4 over ipv6 . 
when ipv6 over ipv4 ,  ethernet --> ipv4 --> gre --> ipv6_gre
when ipv4 over ipv6 ,  ethernet --> ipv6 --> gre --> ipv4_gre
we can see the main difference in the parser .

each time when one packet should transmit across the network , they should add a gre header and then add a ipx_gre header , and the oringe header should be copied , so after the packet is transfered to the other side , switch could still use the oringe header as to transfer the packet to the destination.

The others are almost the same to tunnel example.

We implement 5 switches and 4 hosts , consist a linear topo (linear-topo/topology.json).
s1 s2 s4 s5 support ipv4 . s2 s3 s4 support ipv6.
So s2 and s4 are ingress/egress border switch. Comaparing with s1 ,s5 or s6 ,which just maintanence only one ipv4/ipv6 foward table ,s2 and s4 not only maintanence both ipv4 and ipv6 forward table , they also maintanence ingress/egress-border-table. These tables indicate which dstAddr is over tunnel.


4.run:    

$ make
mininet>xterm h1 h2 h3 h4

one direct:
in h4's xterm:
$ python3 receive.py

in h1's xterm:
(send IPv4 packet)
$ python3 send_v4.py 10.0.1.1 10.0.4.4 "Send a IPv4 packet"

the other direct:
in h43's xterm:
$ python3 receive.py

in h2's xterm:
(send IPv4 packet)
$ python3 send_v4.py 10.0.2.2 10.0.3.3 "Send a IPv4 packet"

5.exit

mininet> exit
$ make stop
$ make run 