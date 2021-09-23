/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_GRE = 47;

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
    gre_t        gre;
    ipv4_t       gre_ipv4;
    ipv6_t       gre_ipv6;
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
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }
    
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            (bit<8>)TYPE_GRE: parse_gre;
            default: accept;
        }
    }

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr){
            (bit<8>)TYPE_GRE: parse_gre;
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
        hdr.ipv6.hopLimit = hdr.ipv4.ttl;
        hdr.ipv4.setInvalid();
        
        meta.is_ingress_border = 1;
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

        meta.is_egress_border = 1;
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
        hdr.ipv4.srcAddr = srcip4;
        hdr.ipv4.dstAddr = dstip4;
        hdr.ipv4.ttl = hdr.ipv6.hopLimit;
        hdr.ipv6.setInvalid();
        
        meta.is_ingress_border = 1;
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
            add_ipv4_gre_header;
            mov_ipv4_gre_header;
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
            mov_ipv6_gre_header;
            add_ipv6_gre_header;
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
        if(hdr.ipv6.isValid() && (meta.is_ingress_border == 1 || meta.is_egress_border == 1)){
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
        packet.emit(hdr.gre);
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
