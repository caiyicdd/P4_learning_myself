we implement a square network or two paths network . you can see the topo in p4app.jason
In the p4app.jason,we define the hosts , switches and links (include the link bw,delay,looss,weight,queue+length)
There are two ways from h1 to h2 : h1-s1-s2-s4-h2  or  h1-s1-s3-s4-h2.
The shortest_path algo we insert only one path to the foward table ipv4_tbl.
The host is defined in the linear/host.jason. If the host is IPv4 the controller will compute the IPv4 routing table ipv4_tbl . If the host is IPv6 the controller will compute the IPv6 routing table ipv6_tbl.
Ping in IPv4 network is allowed . But ping/ping6 in IPv6 network is not allowed . Because the controller doesn't insert the ND(neightbor discover) packet in the foward tbale... So we just use the send.py and receive.py to test the network.

The IPv6 is also effect in this implement.

routing-controller.py implement the shortest path computing . and insert the routing table (ipv4_tbl & ipv6_tbl).

when computing shortest paths . the bw and weight is useful. the loss and delay doesn't work. the algo just consider the bw and weight as a metric , the minimum sum of weight(bw or weight) is prior.

4.run:    

$ sudo p4run
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