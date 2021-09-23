Based on basic_ipv6 and basic_dualStack .
We implement a linear topo with 4 switches(s1,s2,s3,s4) . Beside this we attach hosts: h1-s1 h2-s4 h3-s2 h4-s3.
h1,h3,s1,s3 consists of an ipv6 network.
h2,h4,s2,s4 consists of an ipv4 network.

We perform NAT64 at s2 and s3.
So at s2 , it contain the route of ipv6 ,it assign ipv6 address for the ipv4 host(s2 and s4). 
		s2:10.0.2.2(original)<-->fe08::2(new assign)
		s4:10.0.4.4(original)<-->fe08::4(new assign)
	beside this,s2 contain the route of ipv4, it assign ipv4 address for the ipv6 host(s1 and s3).													s1:fe08::1(original)<-->10.0.1.1(new assign)
		s3:fe08::3(original)<-->10.0.3.3(new assign)
The same implement on s3.								  	

test our model:

run:    

$ make
mininet>xterm h1 h2 h3 h4

in h2's and h3's xterm:
$ python3 receive.py

in h1's xterm:
(send IPv6 packet to the same network host s3)
$ python3 send.py fe08::1 fe08::3 "Send a IPv6 packet"

we can watch the packet send between s1 and s3.

(send IPv6 packet to the ipv4 network host s4)
$ python3 send.py fe08::1 fe08::4 "Send a IPv6 packet"

we can watch the packet send between s1 and s4.

in h2's xterm:
(send IPv4 packet to the same network host s4)
$ python3 send_v4.py 10.0.2.2 10.0.4.4 "Send a IPv4 packet"

we can watch the packet send between s2 and s4.

(send IPv4 packet to the ipv6 network host s3)
$ python3 send_v4.py 10.0.2.2 10.0.3.3 "Send a IPv4 packet"

we can watch the packet send between s2 and s3.


5.exit

mininet> exit
$ make stop
$ make run 