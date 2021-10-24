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

    sys.stdout.flush()
    print(" it's {}-th packets".format(ic[0]))
    ic[0] = ic[0] + 1

    # repsponse a packet with the request's route

    dstAddrOfIPv6 = pkt[IPv6].src
    srcAddrOfIPv6 = pkt[IPv6].dst
    localDomainSW = "fe80::7"
    payload = "this is a repsponse packet!!!"

    # pktNew = Ether(src='11:11:11:11:11:11',dst='ff:ff:ff:ff:ff:ff',type=0x86dd)
    # pktNew = pktNew / IPv6(src=srcAddrOfIPv6,dst=localDomainSW,nh=0x65)
    length = pkt["pathHd"].len
    # for i in range(length):
    # 	swID = pkt["backPath"][i].swID
    # 	next_domainID = pkt["backPath"][i].next_domainID
    # 	nextDomainType = pkt["backPath"][i].nextDomainType
    # 	s = 0
    # 	if i == length - 1:
    # 		s = 1
    # 	pktNew = pktNew / srcList(swID=swID,next_domainID=next_domainID,nextDomainType=nextDomainType,s=s)
    # pktNew = pktNew / src(nextHdr=0x66,len=length,index=0)
    # pktNew = pktNew / backPath(swID=0,next_domainID=0,nextDomainType=0,s=1)
    # pktNew = pktNew / pathHd(nextHdr=0x86dd,len=0,index=0)
    # pktNew = pktNew / IPv6(src=srcAddrOfIPv6,dst=dstAddrOfIPv6,nh=0x11,plen=37) / UDP(dport=5432,sport=2345) /payload

    pkt_struct = {
	    "Ether":{"src":"11:11:11:11:11:11","dst":"ff:ff:ff:ff:ff:ff","type":34525},
	    "IPv6":{"src":srcAddrOfIPv6,"dst":localDomainSW,"nh":101},
	    "srcList":{
	    		"0":{"swID":pkt["backPath"][0].swID,"next_domainID":pkt["backPath"][0].next_domainID,"nextDomainType":pkt["backPath"][0].nextDomainType,"s":0},
	    		"1":{"swID":pkt["backPath"][1].swID,"next_domainID":pkt["backPath"][1].next_domainID,"nextDomainType":pkt["backPath"][1].nextDomainType,"s":0},	
	    		"2":{"swID":pkt["backPath"][2].swID,"next_domainID":pkt["backPath"][2].next_domainID,"nextDomainType":pkt["backPath"][2].nextDomainType,"s":1}
	    	},
	    "src":{"nextHdr":102,"len":length,"index":0},
	    "backPath":{
	    		"0":{"swID":0,"next_domainID":0,"nextDomainType":0,"s":1}
	    	},
	    "pathHd":{"nextHdr":34525,"len":0,"index":0},
	    "gre_ipv6":{"src":srcAddrOfIPv6,"dst":dstAddrOfIPv6,"nh":17}
    }
    json_str = json.dumps(pkt_struct)
    new_dict = json.loads(json_str)
    with open(receFile,"w") as f:
   		json.dump(new_dict,f)
  		

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