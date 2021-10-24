#!/usr/bin/env python
import sys
import struct
import os
import subprocess
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IPv6, TCP, UDP, Raw, Ether, IP
from scapy.layers.inet import _IPOption_HDR
from scapy.packet import bind_layers,Padding

import header

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

class src(Packet):
	name = "src"
	fields_desc = [
		BitField("nextHdr", 0, 16),
		BitField("s", 0, 1),
		BitField("len", 0, 6),
		BitField("index", 0, 6),
		BitField("exp", 0, 3)
		]

class srcList(Packet):
	name = "srcList"
	fields_desc = [
		BitField("swID", 0, 128),
		BitField("next_domainID", 0, 32),
		BitField("nextDomainType", 0, 16),
		BitField("s", 0, 1),
		BitField("exp", 0, 7)
	]

class pathHd(Packet):
	name = "pathHd"
	fields_desc = [
		BitField("nextHdr", 0, 16),
		BitField("s", 0, 1),
		BitField("len", 0, 6),
		BitField("index", 0, 6),
		BitField("exp", 0, 3)
		]

class backPath(Packet):
	name = "backPath"
	fields_desc = [
		BitField("swID", 0, 128),
		BitField("next_domainID", 0, 32),
		BitField("nextDomainType", 0, 16),
		BitField("s", 0, 1),
		BitField("exp", 0, 7)
	]


def handle_pkt(pkt, ic, receFile):
    print ("got a packet")
 
    pkt.show2()
    if pkt.payload.haslayer("backPath"):
        print("got it got it")
    else:
        print("cant find it")

    # pkt["backPath"].show2()
    

    sys.stdout.flush()
    print(" it's {}-th packets".format(ic[0]))
    ic[0] = ic[0] + 1

    

bind_layers(Ether, IPv6, type=0x86dd)
bind_layers(Ether, IP, type=0x800)
bind_layers(IP, srcList, proto = 0x65)
bind_layers(IP, backPath, proto = 0x66)
bind_layers(IPv6, srcList, nh = 0x65)
bind_layers(IPv6, backPath, nh = 0x66)
bind_layers(srcList, srcList, s=0)
bind_layers(srcList, src, s=1)
bind_layers(backPath, backPath, s=0)
bind_layers(backPath, pathHd, s=1)
bind_layers(src, backPath, nextHdr=0x66)
bind_layers(pathHd, UDP, nextHdr=0x11)
bind_layers(pathHd, TCP, nextHdr=0x6)
bind_layers(pathHd, IP, nextHdr=0x0800)
bind_layers(pathHd, IPv6, nextHdr=0x86dd)
bind_layers(IP, UDP, ptoto=0x11)
bind_layers(IP, TCP, proto=0x6)
bind_layers(IPv6, UDP, nh=0x11)
bind_layers(IPv6, TCP, nh=0x6)

def main():


    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    #iface = ifaces[0]
    iface = next(iter(ifaces))
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    ic = [1]
    # sniff(filter="udp and port 4321",iface = iface,
    #       prn = lambda x: handle_pkt(x, ic))
    # Rpacket = ResolvePacket()

    receFile = "linear-topo/"+iface+"_host_stack.json"
    # print(receFile)

    sniff(iface = iface,
          prn = lambda x: handle_pkt(x, ic,receFile))





if __name__ == '__main__':
    main()