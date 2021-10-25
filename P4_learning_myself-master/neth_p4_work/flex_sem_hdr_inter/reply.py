#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time
import json

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IPv6, UDP

import header

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    # if len(sys.argv)<3:
    #     print ('pass 2 arguments: <destination> "<message>"')
    #     exit(1)
    # saddr = sys.argv[1]
    # addr = sys.argv[2]
    iface = get_if()

    # print ("sending on interface %s to %s" % (iface, str(addr)))
    # pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / IPv6(src=saddr,dst=addr) / UDP(dport=4321, sport=1234) / sys.argv[3]
    # pkt.show2()
    receFile = "linear-topo/"+iface+"_host_stack.json"


    with open(receFile,'r') as fp:
        pktStruct = json.load(fp)
        # pktStruct = json.dumps(pktStruct_str)
    # print(pktStruct)


    payload = "this is a repsponse packet!!!"

    # pktNew = Ether(src='11:11:11:11:11:11',dst='ff:ff:ff:ff:ff:ff',type=0x86dd)
    # pktNew = pktNew / IPv6(src=srcAddrOfIPv6,dst=localDomainSW,nh=0x65)
    # length = pkt["pathHd"].len
    # for i in range(length):
    #     swID = pkt["backPath"][i].swID
    #     next_domainID = pkt["backPath"][i].next_domainID
    #     nextDomainType = pkt["backPath"][i].nextDomainType
    #     s = 0
    #     if i == length - 1:
    #         s = 1
    #     pktNew = pktNew / srcList(swID=swID,next_domainID=next_domainID,nextDomainType=nextDomainType,s=s)
    # pktNew = pktNew / src(nextHdr=0x66,len=length,index=0)
    # pktNew = pktNew / backPath(swID=0,next_domainID=0,nextDomainType=0,s=1)
    # pktNew = pktNew / pathHd(nextHdr=0x86dd,len=0,index=0)
    # pktNew = pktNew / IPv6(src=srcAddrOfIPv6,dst=dstAddrOfIPv6,nh=0x11,plen=37) / UDP(dport=5432,sport=2345) /payload
    
    payloadLen = len(UDP(dport=5432,sport=2345) /payload)

    pktNew = Ether(src=pktStruct["Ether"]["src"],dst=pktStruct["Ether"]["dst"],type=pktStruct["Ether"]["type"])
    pktNew = pktNew / IPv6(src=pktStruct["IPv6"]["src"],dst=pktStruct["IPv6"]["dst"],nh=pktStruct["IPv6"]["nh"],plen=(payloadLen+140))
    pktNew = pktNew / header.srcList(swID=pktStruct["srcList"]["0"]["swID"],next_domainID=pktStruct["srcList"]["0"]["next_domainID"],nextDomainType=pktStruct["srcList"]["0"]["nextDomainType"],s=pktStruct["srcList"]["0"]["s"])
    pktNew = pktNew / header.srcList(swID=pktStruct["srcList"]["1"]["swID"],next_domainID=pktStruct["srcList"]["1"]["next_domainID"],nextDomainType=pktStruct["srcList"]["1"]["nextDomainType"],s=pktStruct["srcList"]["1"]["s"])
    pktNew = pktNew / header.srcList(swID=pktStruct["srcList"]["2"]["swID"],next_domainID=pktStruct["srcList"]["2"]["next_domainID"],nextDomainType=pktStruct["srcList"]["2"]["nextDomainType"],s=pktStruct["srcList"]["2"]["s"])
    pktNew = pktNew / header.src(nextHdr=pktStruct["src"]["nextHdr"],len=pktStruct["src"]["len"],index=pktStruct["src"]["index"])
    pktNew = pktNew / header.backPath(swID=0,next_domainID=0,nextDomainType=0,s=1)
    pktNew = pktNew / header.pathHd(nextHdr=pktStruct["pathHd"]["nextHdr"],len=0,index=0)
    pktNew = pktNew / IPv6(src=pktStruct["gre_ipv6"]["src"],dst=pktStruct["gre_ipv6"]["dst"],nh=pktStruct["gre_ipv6"]["nh"],plen=payloadLen) / UDP(dport=5432,sport=2345) /payload




    ic=0
    while True:
    	pktNew.show2()
        sendp(pktNew, iface=iface, verbose=False)
        print("reply {}-th packets".format(ic))
        ic=ic+1
        time.sleep(1)


if __name__ == '__main__':
    main()