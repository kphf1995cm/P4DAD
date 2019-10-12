/* -*- P4_16 -*- */
# include <core.p4>
# include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8> NH_ICMPv6 = 58;

const bit<8> TYPE_NS = 135;
const bit<8> TYPE_NA = 136;

const bit<48> MULTICAST_ADDR =0x3333ff9088e1;

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

const bit<8> PORT_MAX_IPV6_NUM = 4;

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
}

struct binding_entry_t{
    bit<16> port;
    IPv6Address addr;
    bit<8> addr_state; /* idle,tentative,preferred,deprecated,unavailable*/
}

/*********************************** REGISTER ***********************************/
register<IPv6Address>(400) port_ipv6;
register<AddrState>(400) port_ipv6_state;
register<bit<8>>(100) port_ipv6_num;

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

    action modify_egress_spec(bit<16> port){
        standard_metadata.egress_spec = port;
    }

    table mac_forward {
        key = {
            hdr.ethernet.dst :exact;
        }
        actions = {
            drop;
            modify_egress_spec;
        }
        const default_action = drop;
        size = 16384;
    }

    action view_port_ipv6_num(){
        port_ipv6_num.read(bit<32>(standard_metadata.ingress_port),meta.port_ipv6_num);
    }

    action notify_controller_reply_na(){
    }

    action build_binding_entry(){
        bit<8> port_ipv6_num;
        port_ipv6_num.read(bit<32>(standard_metadata.ingress_port),port_ipv6_num);
        bit<32> index;
        index = standard_metadata.ingress_port*4;
        index = index + port_ipv6_num;
        port_ipv6.write(index,hdr.icmpv6.target_address);
        port_ipv6_state.write(index,ADDR_TENTATIVE);
        port_ipv6_num = port_ipv6_num + 1;
        port_ipv6_num.write(bit<32>(standard_metadata.ingress_port),port_ipv6_num);
    }

    action multicast(){
        standard_metadata.mcast_grp=1;
    }

    action port_match_source(){
        bit<8> port_ipv6_num;
        port_ipv6_num.read(bit<32>(standard_metadata.ingress_port),port_ipv6_num);
        if(port_ipv6_num>0){
            bit<32> index;
            index = standard_metadata.ingress_port*4;
            IPv6Address ipv6;
            port_ipv6.read(index,ipv6)
            if(ipv6==hdr.ipv6.src){
                port_ipv6_state.write(index,ADDR_PREFERRED);
                meta.src_state=SRC_IN_PORT_ENTRY;
            }else{
                port_ipv6.read(index+1,ipv6)
                if(ipv6==hdr.ipv6.src){
                    port_ipv6_state.write(index+1,ADDR_PREFERRED);
                    meta.src_state=SRC_IN_PORT_ENTRY;
                }
                else{
                    port_ipv6.read(index+2,ipv6)
                    if(ipv6==hdr.ipv6.src){
                        port_ipv6_state.write(index+2,ADDR_PREFERRED);
                        meta.src_state=SRC_IN_PORT_ENTRY;
                    }
                    else{
                        port_ipv6.read(index+3,ipv6)
                        if(ipv6==hdr.ipv6.src){
                            port_ipv6_state.write(index+3,ADDR_PREFERRED);
                            meta.src_state=SRC_IN_PORT_ENTRY;
                        }else{
                            meta.src_state=SRC_NOT_IN_PORT_ENTRY;
                        }
                    }
                }
            }
        }
    }

    action port_match_target_address(){
        bit<8> port_ipv6_num;
        port_ipv6_num.read(bit<32>(standard_metadata.ingress_port),port_ipv6_num);
        if(port_ipv6_num>0){
            bit<32> index;
            index = standard_metadata.ingress_port*4;
            IPv6Address ipv6;
            AddrState addr_state;
            port_ipv6.read(index,ipv6)
            if(ipv6==hdr.icmpv6.target_address){ 
                port_ipv6_state.read(index,addr_state)
                if(addr_state==ADDR_TENTATIVE){
                    port_ipv6_num.write(bit<32>(standard_metadata.ingress_port),port_ipv6_num-1);
                     /* Later 3 Register Move Forward*/
                }
            }else{
                // Tarverse Later 3 Register
            }
        }
    }

    /* Code */
    apply{
        if(hdr.icmpv6.type==TYPE_NS){
            if(hdr.ipv6.src==0x0){
                view_port_ipv6_num();
                if(meta.port_ipv6_num>=4){
                    notify_controller_reply_na();
                }else{
                    build_binding_entry();
                    multicast();
                }
            }else{
                port_match_source();
                if (meta.src_state==SRC_NOT_IN_PORT_ENTRY){
                    drop();
                }
                if(hdr.ethernet.dst==MULTICAST_ADDR){
                    multicast();
                }else{
                    mac_forward.apply();
                }
            }
        }else{
            if(hdr.icmpv6.type==TYPE_NA){
                if(hdr.ipv6.src==hdr.icmpv6.target_address){
                    port_match_source();
                    if(meta.src_state==SRC_NOT_IN_PORT_ENTRY){
                        drop();
                    }
                    port_match_target_address();
                    if(hdr.ethernet.dst==MULTICAST_ADDR){
                        multicast();
                    }else{
                        mac_forward.apply();
                    }
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

