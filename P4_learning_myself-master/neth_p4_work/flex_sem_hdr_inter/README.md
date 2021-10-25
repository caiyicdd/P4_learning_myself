
4.run:    

$ sudo p4run
mininet>xterm h1 


communicate throw Source Routing:
>first   send packets from h1 to h3:
python send.py fe80::1 fe80::3 "send a IPv6 test packet"

>second  receive packet at h3:
python receive.py
(receive.py will write a json to save the sender's route and packet struct)

>third  h3 reply packet to h1
python replay.py

>forth   h1 receive the reply packet
python receive_reply.py

communicate throw Tunnel:
>first send packets from h1 to h2
python send.py fe80::1 fe80::2 "send a IPv6 test packet throw tunnel"

>second  receive packet from h2
python receive_reply.py




communicate throw InterDomain Routing:
>first   send packets from h1 to h4:
python send.py fe80::1 fe80::4 "send a IPv6 test packet throw interDomain routing"

>second  receive packet at h4:
python receive_reply.py

