Based on basic_ipv6 we implement basic_dualStack. The swich can forward ipv4 or ipv6 packet.

1.reference basic.
2.IPv6 & IPv4 forward.
3.modify the topo : open Makefile      TOPO = triangle-topo/topology.json  or  TOPO = single-topo/topology.json
we can see the topology.json asign ipv6 address to host h1 and h2. But I think it's useless.We can prove it by send_v4.py which send a ipv4 pakcet, but the topo still asign a ipv6 address to the host.  

4.run:    

$ make
mininet>xterm h1 h2

in h2's xterm:
$ python3 receive.py

in h1's xterm:
(send IPv4 packet)
$ python3 send_v4.py 10.0.1.1 10.0.2.2 "Send a IPv4 packet"

(send IPv6 packet)
$ python3 send.py fe08::1 fe08::2 "Send a IPv6 packet"

5.exit

mininet> exit
$ make stop
$ make run 