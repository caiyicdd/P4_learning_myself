/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;

#define CONST_MAX_PORTS     32

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

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

struct empty_t{
    
}

struct metadata {
    /* empty */
    bit<1> is_ingress_border;
    bit<1> is_egress_border;
    empty_t empty;
    bit<14> option;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: add parser logic */
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV6:parse_ipv6;
            TYPE_IPV4:parse_ipv4;
            default:accept;
        }
    }
    

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr){
            (bit<8>)TYPE_IPV4:parse_ipv4;
            default:accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            default:accept;
        }
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

    action add_ipv6_header(ip6Addr_t srcip6, ip6Addr_t dstip6,macAddr_t dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.setValid();
        hdr.ethernet.etherType = TYPE_IPV6;
        hdr.ipv6.version = (bit<4>)6;
        //hdr.ipv6.trafficClass = hdr.ipv4.diffserv;
        hdr.ipv6.srcAddr = srcip6;
        hdr.ipv6.dstAddr = dstip6;
        hdr.ipv6.nextHdr = (bit<8>)TYPE_IPV4;
        hdr.ipv6.trafficClass = (bit<8>)0;
        hdr.ipv6.flowLable = (bit<20>)0;
        
        hdr.ipv6.hopLimit = hdr.ipv4.ttl;
        //hdr.ipv6.payLoadLen = hdr.ipv4.totalLen;
        //standard_metadata.egress_spec = port;
        meta.is_ingress_border = 1;
    }

    action mov_ipv6_header(macAddr_t dstAddr){
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv6.hopLimit - 1;
        hdr.ipv6.setInvalid();
        meta.is_egress_border = 1;
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
            ipv4_forward;
            add_ipv6_header;
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
            ipv6_forward;
            mov_ipv6_header;
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }
        
    apply {

        
        if(hdr.ipv6.isValid()){
            ipv6_tbl.apply();
        }

        if(hdr.ipv4.isValid()){
            ipv4_tbl.apply();
        }
        if(meta.is_ingress_border == 1){
            ipv6_lpm.apply();
        }
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
