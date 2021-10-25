/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_GRE = 47;
const bit<16> TYPE_SRC = 101;
const bit<16> TYPE_PATH = 102;
const bit<16> TYPE_INTER = 153;

#define CONST_MAX_PORTS     32
#define CONST_MAX_SRC_HOPS 16

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;
typedef bit<128> swID_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header ipv6_t{
    bit<4> version;
    bit<8> trafficClass;
    bit<20> flowLable;
    bit<16> payLoadLen;
    bit<8> nextHdr;
    bit<8> hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr; 
}

header gre_t{
    bit<1> C;
    bit<1> zero_1;
    bit<1> K;
    bit<1> zero_2;
    bit<1> zero_3;
    bit<3> recursion;
    bit<5> flags;
    bit<3> version;
    bit<16> protocol;
    bit<16> checksum;
    bit<16> zero_4;
    bit<32> key;
}

header ipv4_t{
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header src_t {
    bit<16> nextHdr;
    bit<1> s;
    bit<6> len;
    bit<6> index;
    bit<3> exp;
}

header srcList_t {
	swID_t swID;
	bit<32> next_domainID;
	bit<16> nextDomainType;
	bit<1> s;
	bit<7> exp;
}

header interDomain_t {
	bit<32> srcDomainID;
	bit<32> dstDomainID;
	bit<16> nextHdr;
}

struct empty_t{
    
}

struct metadata {
    /* empty */
    swID_t curr_swID;
    swID_t next_swID;
    bit<32> curr_domainID;
    bit<32> next_domainID;
    bit<32> src_domainID;
    bit<32> dst_domainID;
    bit<16> currType;
    bit<16> nextType;
    bit<1> is_ingress_border;
    bit<1> is_egress_border;
    bit<1> is_src;
    bit<1> is_last_hop;
    bit<8> ttl;
    bit<4> option;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    srcList_t[CONST_MAX_SRC_HOPS]	 srcList;
    src_t        src;
    gre_t        gre;
    interDomain_t interDomain;
    ipv4_t       gre_ipv4;
    ipv6_t       gre_ipv6;
    srcList_t[CONST_MAX_SRC_HOPS]	 backPath;
    src_t        pathHd;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }
    
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            (bit<8>)TYPE_GRE: parse_gre;
            (bit<8>)TYPE_SRC: parse_srcList;
            (bit<8>)TYPE_PATH: parse_backpath;
            (bit<8>)TYPE_INTER: parse_interDomain;
            default: accept;
        }
    }

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr){
            (bit<8>)TYPE_GRE: parse_gre;
            (bit<8>)TYPE_SRC: parse_srcList;
            (bit<8>)TYPE_PATH: parse_backpath;
            (bit<8>)TYPE_INTER: parse_interDomain;
            default: accept;
        }
    }

    state parse_gre{
        packet.extract(hdr.gre);
        transition select(hdr.gre.protocol){
            TYPE_IPV6: parse_gre_ipv6;
            TYPE_IPV4: parse_gre_ipv4;
            default: accept;
        }
    }

    state parse_interDomain{
    	packet.extract(hdr.interDomain);
    	transition select(hdr.interDomain.nextHdr){
    		TYPE_IPV6: parse_gre_ipv6;
            TYPE_IPV4: parse_gre_ipv4;
            default: accept;
    	}
    }

    state parse_srcList{
    	packet.extract(hdr.srcList.next);
    	transition select(hdr.srcList.last.s){
    		0: parse_srcList;
            1: parse_src;
    		default: accept;
    	}
    }

    state parse_src{
        packet.extract(hdr.src);
        transition select(hdr.src.nextHdr){
            TYPE_PATH: parse_backpath;
            default: accept;
        }
    }

    state parse_backpath{
    	packet.extract(hdr.backPath.next);
    	transition select(hdr.backPath.last.s){
    		0: parse_backpath;
    		1: parse_pathHd;
    		default: accept;
    	}
    }

    state parse_pathHd{
    	packet.extract(hdr.pathHd);
    	transition select(hdr.pathHd.nextHdr){
    		TYPE_IPV4: parse_gre_ipv4;
            TYPE_IPV6: parse_gre_ipv6;
            default: accept;
    	}
    }

    state parse_gre_ipv6{
        packet.extract(hdr.gre_ipv6);
        transition accept;
    }
    
    state parse_gre_ipv4{
        packet.extract(hdr.gre_ipv4);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // add a ipv6-gre header for a ipv4 packet
    action add_ipv4_gre_header(ip6Addr_t srcip6, ip6Addr_t dstip6){
        hdr.gre.setValid();
        hdr.gre_ipv4.setValid();
        hdr.ipv6.setValid();
        hdr.gre_ipv4 = hdr.ipv4;
        hdr.gre.protocol = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_IPV6;
        hdr.ipv6.nextHdr = (bit<8>)TYPE_GRE;
        hdr.ipv6.version = (bit<4>)6;
        hdr.ipv6.srcAddr = srcip6;
        hdr.ipv6.dstAddr = dstip6;
        hdr.ipv6.payLoadLen = (bit<16>)hdr.ipv4.totalLen + 12; 
        hdr.ipv6.hopLimit = hdr.ipv4.ttl;
        hdr.ipv4.setInvalid();
        
    }

    // move away the ipv4-gre header from the ipv6 packet
    action mov_ipv4_gre_header(){
        hdr.ipv6.setValid();
        hdr.ipv6 = hdr.gre_ipv6;
        hdr.ethernet.etherType = hdr.gre.protocol;
        hdr.ipv6.hopLimit = hdr.ipv4.ttl;
        hdr.ipv4.setInvalid();
        hdr.gre.setInvalid();
        hdr.gre_ipv6.setInvalid();

    }

    // add a ipv4 header and a gre header for a ipv6 packet
    action add_ipv6_gre_header(ip4Addr_t srcip4, ip4Addr_t dstip4){
        hdr.gre.setValid();
        hdr.gre_ipv6.setValid();
        hdr.ipv4.setValid();
        hdr.gre_ipv6 = hdr.ipv6;
        hdr.gre.protocol = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ipv4.protocol = (bit<8>)TYPE_GRE;
        hdr.ipv4.version = (bit<4>)4;
        hdr.ipv4.totalLen = (bit<16>)hdr.ipv6.payLoadLen + 72;
        hdr.ipv4.ihl = (bit<4>)5;
        hdr.ipv4.srcAddr = srcip4;
        hdr.ipv4.dstAddr = dstip4;
        hdr.ipv4.ttl = hdr.ipv6.hopLimit;
        hdr.ipv6.setInvalid();
        
    }

    // move away the ipv6-gre header from the ipv4 packet

    action mov_ipv6_gre_header(){
        hdr.ipv4.setValid();
        hdr.ipv4 = hdr.gre_ipv4;
        hdr.ethernet.etherType = hdr.gre.protocol;
        hdr.ipv4.ttl = hdr.ipv6.hopLimit - 1;
        hdr.gre_ipv4.setInvalid();
        hdr.gre.setInvalid();
        hdr.ipv6.setInvalid();

    }

    // add src header
    // this action is just to simulate the source end which want send a packet across some domain.
    // so this action will just match in the end switch. just like a end host stack.
    // the parameters is request from the path server  

    action add_srcheader_v6_3(ip6Addr_t ipAddr,macAddr_t dstAddr, egressSpec_t port,swID_t sid1,bit<32>dmID1_1,bit<16>dmType1,swID_t sid2,bit<32>dmID2_1,bit<16>dmType2,swID_t sid3,bit<32>dmID3_1,bit<16>dmType3){
        
        hdr.srcList.push_front(1);
        hdr.srcList[0].setValid();
        hdr.srcList[0].swID = sid3;
        hdr.srcList[0].next_domainID = dmID3_1;
        hdr.srcList[0].nextDomainType = dmType3;
        hdr.srcList[0].s = 1;

        hdr.srcList.push_front(1);
        hdr.srcList[0].setValid();
        hdr.srcList[0].swID = sid2;
        hdr.srcList[0].next_domainID = dmID2_1;
        hdr.srcList[0].nextDomainType = dmType2;
        hdr.srcList[0].s = 0;

        hdr.srcList.push_front(1);
        hdr.srcList[0].setValid();
        hdr.srcList[0].swID = sid1;
        hdr.srcList[0].next_domainID = dmID1_1;
        hdr.srcList[0].nextDomainType = dmType1;
        hdr.srcList[0].s = 0;

        hdr.backPath.push_front(1);
        hdr.backPath[0].setValid();
        hdr.backPath[0].swID = 0;
        hdr.backPath[0].next_domainID = 0;
        hdr.backPath[0].s = 1;

        hdr.src.setValid();
        hdr.pathHd.setValid();
        hdr.gre_ipv6.setValid();
        hdr.gre_ipv6 = hdr.ipv6;


        hdr.ethernet.etherType = TYPE_IPV6;
        hdr.ipv6.nextHdr = (bit<8>)TYPE_SRC;
        hdr.src.nextHdr = TYPE_PATH;
        hdr.pathHd.nextHdr = TYPE_IPV6;
        hdr.ipv6.payLoadLen = 140 + hdr.ipv6.payLoadLen;

        hdr.src.len = 3;
        hdr.src.index = 0;

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.dstAddr = ipAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    action get_nextSrc(){
        meta.curr_swID = hdr.srcList[0].swID;
        meta.next_domainID = hdr.srcList[0].next_domainID;
        meta.nextType = hdr.srcList[0].nextDomainType;
    }

    action set_is_src_v4(bit<16> lastType,bit<32> currDomainID){
        meta.is_src = 1;
        meta.ttl = hdr.ipv4.ttl - 1;
        meta.curr_domainID = currDomainID;
        meta.currType = lastType;

        meta.is_ingress_border = 1;
    }

    action set_is_src_v6(bit<16> lastType,bit<32> currDomainID){
        meta.is_src = 1;
        meta.ttl = hdr.ipv6.hopLimit - 1;
        meta.curr_domainID = currDomainID;
        meta.currType = lastType;

        meta.is_ingress_border = 1;
    }

    action nextHop_forward_4to4(bit<32> srcAddr,bit<32>dstAddr){
     	hdr.ipv4.srcAddr = (bit<32>)srcAddr;
	    hdr.ipv4.dstAddr = (bit<32>)dstAddr;
	    hdr.ipv4.ttl = meta.ttl;

	    hdr.backPath.push_front(1);
        hdr.backPath[0].setValid();
        hdr.backPath[0].swID = hdr.srcList[0].swID;
        hdr.backPath[0].next_domainID = meta.curr_domainID;
        hdr.backPath[0].nextDomainType = meta.currType;
        	
        hdr.srcList.pop_front(1);
    }

    action nextHop_forward_4to6(bit<128> srcAddr,bit<128>dstAddr){
        hdr.ethernet.etherType = TYPE_IPV6;
        hdr.ipv6.version = 6;
	   	hdr.ipv6.srcAddr = (bit<128>)srcAddr;
	   	hdr.ipv6.dstAddr = (bit<128>)dstAddr;
        hdr.ipv6.payLoadLen = hdr.ipv4.totalLen - 20;
	    hdr.ipv6.hopLimit = meta.ttl;

	    hdr.backPath.push_front(1);
        hdr.backPath[0].setValid();
        hdr.backPath[0].swID = hdr.srcList[0].swID;
        hdr.backPath[0].next_domainID = meta.curr_domainID;
        hdr.backPath[0].nextDomainType = meta.currType;	
        hdr.srcList.pop_front(1);
    }

    action nextHop_forward_6to4(bit<32> srcAddr,bit<32>dstAddr){
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ipv4.version = 4;
	    hdr.ipv4.srcAddr = (bit<32>)srcAddr;
	    hdr.ipv4.dstAddr = (bit<32>)dstAddr;
        hdr.ipv4.totalLen = hdr.ipv6.payLoadLen + 20;
	    hdr.ipv4.ttl = meta.ttl;

        hdr.backPath.push_front(1);
        hdr.backPath[0].setValid();
        hdr.backPath[0].swID = hdr.srcList[0].swID;
        hdr.backPath[0].next_domainID = meta.curr_domainID;
        hdr.backPath[0].nextDomainType = meta.currType;		
        hdr.srcList.pop_front(1);
    }

    action nextHop_forward_6to6(bit<128> srcAddr,bit<128>dstAddr){
        hdr.ipv6.srcAddr = (bit<128>)srcAddr;
	    hdr.ipv6.dstAddr = (bit<128>)dstAddr;
	    hdr.ipv6.hopLimit = meta.ttl;

	    hdr.backPath.push_front(1);
        hdr.backPath[0].setValid();
        hdr.backPath[0].swID = hdr.srcList[0].swID;
        hdr.backPath[0].next_domainID = meta.curr_domainID;
        hdr.backPath[0].nextDomainType = meta.currType;	
        hdr.srcList.pop_front(1);
    }

    action endHop_forward_v4(bit<16> nextType){
    	hdr.ipv4.version = 4;
    	hdr.ipv4.ihl = 5;
    	hdr.ipv4.totalLen = 20;
    	hdr.ipv4.protocol = (bit<8>)TYPE_PATH;
    	hdr.ipv4.srcAddr = hdr.gre_ipv4.srcAddr;
    	hdr.ipv4.dstAddr = hdr.gre_ipv4.dstAddr;
    	hdr.ipv4.ttl = meta.ttl;

    	hdr.pathHd.nextHdr = (bit<16>)hdr.gre_ipv4.protocol;
    	hdr.backPath.push_front(1);
        hdr.backPath[0].setValid();
        hdr.backPath[0].swID = hdr.srcList[0].swID;
        hdr.backPath[0].next_domainID = meta.curr_domainID;;
        hdr.backPath[0].nextDomainType = meta.currType;
        hdr.pathHd.len = hdr.src.index;
        hdr.pathHd.index = hdr.src.len - hdr.src.index;	
        hdr.srcList.pop_front(1);
       	meta.is_last_hop = 1;
    }

    action endHop_forward_v6(bit<16> nextType){
    	hdr.ipv6.version = 6;
    	hdr.ipv6.nextHdr = (bit<8>)TYPE_PATH;
    	hdr.ipv6.srcAddr = hdr.gre_ipv6.srcAddr;
    	hdr.ipv6.dstAddr = hdr.gre_ipv6.dstAddr;
    	hdr.ipv6.hopLimit = meta.ttl;

    	hdr.pathHd.nextHdr = (bit<16>)hdr.gre_ipv6.nextHdr;
    	hdr.backPath.push_front(1);
        hdr.backPath[0].setValid();
        hdr.backPath[0].swID = hdr.srcList[0].swID;
        hdr.backPath[0].next_domainID = meta.curr_domainID;
        hdr.backPath[0].nextDomainType = meta.currType;
        hdr.pathHd.len = hdr.src.index;
        hdr.pathHd.index = hdr.src.len - hdr.src.index;	
        hdr.ipv6.payLoadLen = hdr.gre_ipv6.payLoadLen + (bit<16>)hdr.pathHd.len * 23 + 4;
        hdr.srcList.pop_front(1);

       	meta.is_last_hop = 1;
    }

    action add_interDomainID_v6(bit<32> srcDomainID,bit<32> dstDomainID){
    	hdr.interDomain.setValid();
    	hdr.gre_ipv6.setValid();
    	hdr.gre_ipv6 = hdr.ipv6;
    	hdr.interDomain.srcDomainID = srcDomainID;
    	hdr.interDomain.dstDomainID = dstDomainID;
    	hdr.interDomain.nextHdr = hdr.ethernet.etherType;

    	meta.is_ingress_border = 1;
    }

    action add_interDomainID_v4(bit<32> srcDomainID,bit<32> dstDomainID){
    	hdr.interDomain.setValid();
    	hdr.gre_ipv4.setValid();
    	hdr.gre_ipv4 = hdr.ipv4;
    	hdr.interDomain.srcDomainID = srcDomainID;
    	hdr.interDomain.dstDomainID = dstDomainID;
    	hdr.interDomain.nextHdr = hdr.ethernet.etherType;

    	meta.is_ingress_border = 1;
    }

    action mov_interDomainID_v4tov4(){
    	hdr.ipv4.srcAddr = hdr.gre_ipv4.srcAddr;
    	hdr.ipv4.dstAddr = hdr.gre_ipv4.dstAddr;
    	hdr.ipv4.protocol = hdr.gre_ipv4.protocol;

    	hdr.interDomain.setInvalid();
    	hdr.gre_ipv4.setInvalid();
    }

    action mov_interDomainID_v4tov6(){
    	hdr.ipv6.setValid();
    	hdr.ipv6.srcAddr = hdr.gre_ipv6.srcAddr;
    	hdr.ipv6.dstAddr = hdr.gre_ipv6.dstAddr;
    	hdr.ipv6.nextHdr = hdr.gre_ipv6.nextHdr;
    	hdr.ethernet.etherType = TYPE_IPV6;
        hdr.ipv6.hopLimit = hdr.ipv4.ttl;

    	hdr.interDomain.setInvalid();
    	hdr.gre_ipv6.setInvalid();
        hdr.ipv4.setInvalid();
    }

    action mov_interDomainID_v6tov4(){
    	hdr.ipv4.setValid();
    	hdr.ipv4.srcAddr = hdr.gre_ipv4.srcAddr;
    	hdr.ipv4.dstAddr = hdr.gre_ipv4.dstAddr;
    	hdr.ipv4.protocol = hdr.gre_ipv4.protocol;
    	hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ipv4.ttl = hdr.ipv6.hopLimit;
    	
    	hdr.interDomain.setInvalid();
    	hdr.gre_ipv4.setInvalid();
        hdr.ipv6.setInvalid();
    }

    action mov_interDomainID_v6tov6(){
    	hdr.ipv6.srcAddr = hdr.gre_ipv6.srcAddr;
    	hdr.ipv6.dstAddr = hdr.gre_ipv6.dstAddr;
    	hdr.ipv6.nextHdr = hdr.gre_ipv6.nextHdr;
    	hdr.ethernet.etherType = TYPE_IPV6;

    	hdr.interDomain.setInvalid();
    	hdr.gre_ipv6.setInvalid();
    }

    action interDomain_v6tov4_forward(bit<16> nextType,bit<32> srcAddr,bit<32> dstAddr){
    	hdr.ipv4.setValid();
    	hdr.ethernet.etherType = nextType;
    	hdr.ipv4.version = (bit<4>)4;
    	hdr.ipv4.srcAddr = srcAddr;
    	hdr.ipv4.dstAddr = dstAddr;
    	hdr.ipv4.protocol = (bit<8>)TYPE_INTER;
    	hdr.ipv4.ttl = hdr.ipv6.hopLimit;
        hdr.ipv6.setInvalid(); 
    }

    action interDomain_v6tov6_forward(bit<16> nextType,bit<128> srcAddr,bit<128> dstAddr){
    	hdr.ethernet.etherType = nextType;
    	hdr.ipv6.srcAddr = srcAddr;
    	hdr.ipv6.dstAddr = dstAddr;
    	hdr.ipv6.nextHdr = (bit<8>)TYPE_INTER;
    }

    action interDomain_v4tov4_forward(bit<16> nextType,bit<32> srcAddr,bit<32> dstAddr){
    	hdr.ethernet.etherType = nextType;
    	hdr.ipv4.srcAddr = srcAddr;
    	hdr.ipv4.dstAddr = dstAddr;
    	hdr.ipv4.protocol = (bit<8>)TYPE_INTER;
    }

    action interDomain_v4tov6_forward(bit<16> nextType,bit<128> srcAddr,bit<128> dstAddr){
    	hdr.ipv6.setValid();
    	hdr.ethernet.etherType = nextType;
    	hdr.ipv6.srcAddr = srcAddr;
    	hdr.ipv6.dstAddr = dstAddr;
    	hdr.ipv6.nextHdr = (bit<8>)TYPE_INTER;
        hdr.ipv6.hopLimit = hdr.ipv4.ttl;
    	hdr.ipv4.setInvalid();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table ipv4_tbl {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            //ipv4_forward;
            add_ipv4_gre_header;
            mov_ipv4_gre_header;
            set_is_src_v4;
            add_interDomainID_v6;
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }

    table ipv6_tbl {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            mov_ipv6_gre_header;
            add_ipv6_gre_header;
            add_srcheader_v6_3;
            add_interDomainID_v6;
            set_is_src_v6;
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }

    table src4_tbl {
        key = {
            meta.curr_swID : exact;
            meta.next_swID : exact;
            meta.next_domainID: exact;
            }
        actions = {
            nextHop_forward_4to4;
            nextHop_forward_4to6;
            endHop_forward_v4;
            endHop_forward_v6;
            NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }

    table src6_tbl {
        key = {
        	meta.curr_swID : exact;
            meta.next_swID : exact;
            meta.next_domainID: exact;
            }
        actions = {
            nextHop_forward_6to4;
            nextHop_forward_6to6;
            endHop_forward_v6;
            endHop_forward_v4;
            NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }

    table interDomain_v6_lpm{
    	key = {
    		hdr.interDomain.dstDomainID: exact;
    	}
    	actions = {
    		interDomain_v6tov6_forward;
    		interDomain_v6tov4_forward;
    		mov_interDomainID_v6tov4;
    		mov_interDomainID_v6tov6;
    		NoAction;
    	}
    	default_action = NoAction();
        size = 1024;
    }

    table interDomain_v4_lpm{
    	key = {
    		hdr.interDomain.dstDomainID: exact;
    	}
    	actions = {
    		interDomain_v4tov4_forward;
    		interDomain_v4tov6_forward;
    		mov_interDomainID_v4tov4;
    		mov_interDomainID_v4tov6;
    		NoAction;
    	}
    	default_action = NoAction();
        size = 1024;
    }

    apply {

        if(hdr.ipv6.isValid()){
            ipv6_tbl.apply();
            if(meta.is_src == 1 && hdr.src.isValid()){
            	if(hdr.src.index == 0){
            		hdr.backPath.pop_front(1);
            	}
            	if(hdr.src.index < hdr.src.len){
            		get_nextSrc();
            		if(hdr.src.index + 1 < hdr.src.len){
            			meta.next_swID = hdr.srcList[1].swID;
        			}else{
        				meta.next_swID = 0;
        			}
        			hdr.src.index = hdr.src.index + 1;
            	}
                if(meta.nextType == TYPE_IPV4){
                	hdr.ipv4.setValid();
                	hdr.ipv4.protocol = hdr.ipv6.nextHdr;
                	hdr.ipv4.totalLen = 20;
                	hdr.ethernet.etherType = TYPE_IPV4;
                	hdr.ipv6.setInvalid();
                }
                src6_tbl.apply();
                if(hdr.src.index == 1){
		        	hdr.backPath[0].s = 1;
		        }else{
		        	hdr.backPath[0].s = 0;
		        }	
            }

            if(meta.is_ingress_border == 1){
            	interDomain_v6_lpm.apply();
            	meta.is_ingress_border = 0;
            }
        }

        if(hdr.ipv4.isValid() && meta.is_src == 0 && meta.is_ingress_border == 0){
            ipv4_tbl.apply();
            if(meta.is_src == 1 && hdr.src.isValid()){
            	if(hdr.src.index == 0){
            		hdr.backPath.pop_front(1);
            	}
                if(hdr.src.index < hdr.src.len){
                	get_nextSrc();
                	if(hdr.src.index + 1 < hdr.src.len){
            			meta.next_swID = hdr.srcList[1].swID;
        			}else{
        				meta.next_swID = 0;
        			}
        			hdr.src.index = hdr.src.index + 1;
                }              
                if(meta.nextType == TYPE_IPV6){
                	hdr.ipv6.setValid();
                	hdr.ipv6.nextHdr = hdr.ipv4.protocol;
                	hdr.ethernet.etherType = TYPE_IPV6;
                	hdr.ipv4.setInvalid();
                }
                src4_tbl.apply();
                if(hdr.src.index == 1){
		        	hdr.backPath[0].s = 1;
		        }else{
		        	hdr.backPath[0].s = 0;
		        }	
            }
            if(meta.is_ingress_border == 1){
            	interDomain_v4_lpm.apply();
            	meta.is_ingress_border = 0;
            }
        }

        if(meta.is_last_hop == 1){
        	if(hdr.gre_ipv4.isValid()){
        		hdr.gre_ipv4.setInvalid();
        	}
        	if(hdr.gre_ipv6.isValid()){
        		hdr.gre_ipv6.setInvalid();
        	}
        	if(hdr.src.isValid()){
        		hdr.src.setInvalid();
        	}
        	//hdr.src.setInValid();

        }

        if (hdr.ethernet.etherType == TYPE_IPV4){
        	ipv4_lpm.apply();
        }
        if (hdr.ethernet.etherType == TYPE_IPV6){
        	ipv6_lpm.apply();
        }
        /*
        if(hdr.ipv6.isValid() && (meta.is_ingress_border == 1 || meta.is_egress_border == 1)){
            ipv6_lpm.apply();
        }
        */

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { 

        //if(meta.is_ingress_border == 1 || meta.is_egress_border == 1){
          //  recirculate(meta.empty);
        //}
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
     update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.srcList);
        packet.emit(hdr.src);
        packet.emit(hdr.gre);
        packet.emit(hdr.interDomain);
        packet.emit(hdr.backPath);
        packet.emit(hdr.pathHd);
        packet.emit(hdr.gre_ipv6);
        packet.emit(hdr.gre_ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
