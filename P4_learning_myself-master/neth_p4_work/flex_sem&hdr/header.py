#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IPv6, TCP, UDP, Raw, Ether, IP
from scapy.layers.inet import _IPOption_HDR
from scapy.packet import bind_layers,Padding


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