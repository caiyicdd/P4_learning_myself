Ref of tunnel : nsg-ethz/p4-learning/exercises/04-MPLS 

This is another gre-tunnel example. Different with the last gre-tunnel-4over6. This example we implement a 6over4 network. So we will give a conclusion to the tunnel exercise.

In these works ,we should carefully design the pipline of the switch. We reserve the IPv4 and IPv6 parser(parse_ipv6 & parse_ipv4), because we should keep line with the current network design. so we treat the former(or user)ipv4/ipv6 header as a gre_ipv4/ipv6 header. And then we add the gre header and the new ipv4/ipv6 network.
So when a ipv4/ipv6 packet conmes to the ingress border switch. It's header transform from : ipv4(or ipv6) header(oringe) --> ipv4(or ipv6) header(new) / gre header / gre_ipv4(or ipv6) header(same with oringe)

In the control plane , we should implement tables : ipv6_tbl, ipv4_tbl, ipv6_lpm
Table ipv6_tbl should match ipv6 dstAddr: 
	the formal forward , 				action : ipv6_forward                       formal ipv6 forward
	the ingress_border of tunnel , 		action : add_ipv6_gre_header				add a ipv4 header for the ipv6 packet, when the ipv6 packet 																						should transfer across the ipv4 tunnel.
	the egress_border of tunnel , 		action : mov_ipv6_gre_header				move away the ipv6 header when the packet transfer out of 																							the ipv6 tunnel 
Tabel ipv4_tbl should match ipv4 dstAddr:
	the formal forward , 				action : ipv4_forward                       formal ipv4 forward
	the ingress_border of tunnel , 		action : add_ipv4_gre_header				add a ipv6 header for the ipv4 packet, when the ipv4 packet 																						should transfer across the ipv6 tunnel.
	the egress_border of tunnel , 		action : mov_ipv4_gre_header				move away the ipv4 header when the packet transfer out of 																							the ipv4 tunnel 
Table ipv6_tbl should math ipv6 dstAddr:
	the formal forward , 				action : ipv6_forward                       formal ipv6 forward,this table apply,when a packet transfer out of 																					thethe ipv4 tunnel or ipv4 packet transfer into a ipv6 tunnel , 																					mainly relay on the apply{} logic design


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
(send IPv6 packet)
$ python3 send.py fe08::1 fe08::4 "Send a IPv6 packet"

the other direct:
in h1's xterm:
$ python3 receive.py

in h2's xterm:
(send IPv6 packet)
$ python3 send.py fe08::2 fe08::1 "Send a IPv6 packet"

5.exit

mininet> exit
$ make stop
$ make run 