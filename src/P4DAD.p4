/* -*- P4_16 -*- */
# include <core.p4>
# include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8> NH_ICMPv6 = 58;

const bit<8> TYPE_NS = 135;
const bit<8> TYPE_NA = 136;

const bit<8> ADDR_IDLE=0;
const bit<8> ADDR_TENTATIVE=1;
const bit<8> ADDR_PREFERRED=2;
const bit<8> ADDR_DEPRECATED=3;
const bit<8> ADDR_UNAVAILABLE=4;
const bit<8> SRC_IN_PORT_ENTRY=5;
const bit<8> SRC_NOT_IN_PORT_ENTRY=6;
const bit<8> TARGET_ADDRESS_IN_PORT_ENTRY=7;
const bit<8> TARGET_ADDRESS_IS_TENTATIVE=8;
const bit<8> TARGET_ADDRESS_NOT_IN_PORT_ENTRY=9;

const bit<16> CPU_PORT=10;
const bit<8> BUILD_BINDING_ENTRY_FLAG=11;
const bit<8> DELETE_BINDING_ENTRY_FLAG=12;

/************************************ HEADERS ************************************/

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;
typedef bit<128> TargetAddress;
typedef bit<8> AddrState;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16> etherType;
}

header ipv6_h {
    bit<4> version;
    bit<8> tc;
    bit<20> fl;
    bit<16> plen;
    bit<8> nh;
    bit<8> hl;
    IPv6Address src;
    IPv6Address dst;
}

header icmpv6_ns_na_h {
    bit<8> type; // 135、136
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
    TargetAddress target_address;
}

// List of all recognized headers
struct my_headers_t {
    ethernet_h ethernet;
    ipv6_h ipv6;
    icmpv6_ns_na_h icmpv6; 
}

struct my_metadata_t {
    bit<8> src_state; /* Indicate source in port entry or not */
    bit<8> target_address_state; /*Indicate target address in port entry or not */
}

struct binding_entry_t{
    bit<16> port;
    IPv6Address addr;
    bit<8> addr_state; /* idle,tentative,preferred,deprecated,unavailable*/
}

/*********************************** REGISTER ***********************************/

/************************************ PARSER ************************************/
parser MyParser(packet_in                 packet,
                out my_headers_t          hdr,
                inout my_metadata_t       meta,
                inout standard_metadata_t standard_metadata){
    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV6: parse_ipv6;
            default: reject; /* what happens in reject state is defined by an architecture */
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nh){
            NH_ICMPv6: parse_icmpv6;
            default: reject;
        }
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition select(hdr.icmpv6.type){
            TYPE_NS: accept;
            TYPE_NA: accept;
            default: reject;
        }
    }
}

/****************************** CHECKSUM VERIFICATION ***************************/
control MyVerifyChecksum(inout my_headers_t hdr, inout my_metadata_t meta){
    apply{
    }
}

/****************************** INGRESS PROCESSING ******************************/
control MyIngress(inout my_headers_t hdr,
                 inout my_metadata_t meta,
                 inout standard_metadata_t standard_metadata){
    /* Declarations */

    action drop(){
        mark_to_drop();
    }

    action inspect_source_in_port_entry(out my_metadata_t meta,IPv6Address ipv6,
                                        AddrState addr_state){
        if(hdr.ipv6.src==ipv6){
            if(addr_state==ADDR_PREFERRED){
                meta.src_state=SRC_IN_PORT_ENTRY;
            }else{
                meta.src_state=SRC_NOT_IN_PORT_ENTRY;
            }
        }else{
            meta.src_state=SRC_NOT_IN_PORT_ENTRY;
        }
    }

    table port_match_source{
        key = {
            standard_metadata.ingress_port  :exact;
        }
        actions = {
            drop;
            inspect_source_in_port_entry;
        }
        const default_action = drop;
        size = 16384;
    }

    action inspect_target_address_in_port_entry(out my_metadata_t meta,IPv6Address ipv6,
                                        AddrState addr_state){
        if(hdr.icmpv6.target_address==ipv6){
            if(addr_state==ADDR_PREFERRED){
                meta.target_address_state=TARGET_ADDRESS_IN_PORT_ENTRY;
            }else{
                if(addr_state==ADDR_TENTATIVE){
                    meta.target_address_state=TARGET_ADDRESS_IS_TENTATIVE;
                }else{
                    meta.target_address_state=TARGET_ADDRESS_NOT_IN_PORT_ENTRY;
                }
            }
        }else{
            meta.target_address_state=TARGET_ADDRESS_NOT_IN_PORT_ENTRY;
        }
    }

    action build_binding_entry() {
        copy_to_cpu(hdr.ipv6.src,standard_metadata.ingress_port,BUILD_BINDING_ENTRY_FLAG); /*How to copy data to cpu in bmv2?*/
        /*
         * standard_metadata.egress_spec=CPU_PORT; 
         * can not modify egress_spec directly, because still need to normal forward?
         */
    }

    action delete_binding_entry(){
         copy_to_cpu(hdr.ipv6.src,standard_metadata.ingress_port,DELETE_BINDING_ENTRY_FLAG); /*How to copy data to cpu in bmv2?*/
    }

    table target_address_in_binding_entry {
        key = {
            standard_metadata.ingress_port  :exact;
        }
        actions = {
            drop;
            inspect_target_address_in_port_entry;
        }
        const default_action = drop;
        size = 16384;
    }

    action modify_egress_spec(bit<16> port){
        standard_metadata.egress_spec = port;
    }

    table forward {
        key = {
            hdr.ipv6.dst :exact;
            hdr.ethernet.dst :exact;
        }
        actions = {
            drop;
            modify_egress_spec; /*How to handle multicast?*/
        }
        const default_action = drop;
        size = 16384;
    }

    /* Code */
    apply{
        if(hdr.icmpv6.type==TYPE_NS){
            if(hdr.ipv6.src==0x0){
                target_address_in_binding_entry.apply();
                if (meta.target_address_state==TARGET_ADDRESS_NOT_IN_PORT_ENTRY){
                    build_binding_entry();
                }
                forward.apply();
            }else{
                port_match_source.apply();
                if (meta.src_state==SRC_NOT_IN_PORT_ENTRY){
                    drop();
                }
                forward.apply();
            }
        }else{
            if(hdr.icmpv6.type==TYPE_NA){
                if(hdr.ipv6.src==hdr.icmpv6.target_address){
                    port_match_source.apply();
                    if(meta.src_state==SRC_NOT_IN_PORT_ENTRY){
                        drop();
                    }
                    target_address_in_binding_entry.apply();
                    if(meta.target_address_state==TARGET_ADDRESS_IS_TENTATIVE){
                        delete_binding_entry();
                    }
                    forward.apply();
                }else{
                    drop();
                }
            }else{
                drop();
            }
        }
    }
}

/****************************** EGRESS PROCESSING *******************************/
control MyEgress(inout my_headers_t hdr,
                 inout my_metadata_t meta,
                 inout standard_metadata_t standard_metadata){
    apply{
    }
}

/****************************** COMPUTE CHECKSUM ********************************/

control MyComputeChecksum(inout my_headers_t hdr, inout my_metadata_t meta){
    apply {

    }
}

/******************************** DEPARSER **************************************/

control MyDeparser(packet_out packet, in my_headers_t hdr){
    apply{
        packet.emit(hdr);
    }
}

/******************************** SWITCH ****************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

