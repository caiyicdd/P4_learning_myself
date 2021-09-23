1.reference basic
2.IPv6 forward
3.modify the topo : open Makefile      TOPO = triangle-topo/topology.json  or  TOPO = single-topo/topology.json
4.run:    

make
xterm h1 h2

in h2's xterm:
$ python3 receive.py

in h1's xterm:
$ python3 send.py fe08::1 fe08::2 "P4 is cool"

5.exit

mininet> exit
$ make stop
$ make run 