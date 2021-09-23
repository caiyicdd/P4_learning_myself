Ref of tunnel : nsg-ethz/p4-learning/exercises/04-MPLS 

This is a tunnel example of ipv4 over ipv6 network. We implement 5 switches and 4 hosts , consist a linear topo (linear-topo/topology.json).
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