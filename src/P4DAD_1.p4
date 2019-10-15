/* -*- P4_16 -*- */
# include <core.p4>
# include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8> NH_ICMPv6 = 58;

const bit<8> TYPE_NS = 135;
const bit<8> TYPE_NA = 136;

//const bit<48> MULTICAST_ADDR =0x3333ff9088e1;
const bit<48> MULTICAST_ADDR =0x3333ffe48900;

const bit<8> ADDR_TENTATIVE=1;
const bit<8> ADDR_PREFERRED=2;
const bit<8> ADDR_DEPRECATED=3;

const bit<8> SRC_IN_PORT_ENTRY=5;
const bit<8> SRC_NOT_IN_PORT_ENTRY=6;
const bit<8> MAC_IN_MAC_QUERY_TABLE=7;
const bit<8> MAC_NOT_IN_MAC_QUERY_TABLE=8;

/************************************ HEADERS ************************************/

typedef bit<48> MacAddress;
typedef bit<128> IPv6Address;
typedef bit<64> HalfIPv6Address;
// typedef bit<128> TargetAddress;
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
    IPv6Address target_address;
}

struct my_headers_t {
    ethernet_h ethernet;
    ipv6_h ipv6;
    icmpv6_ns_na_h icmpv6; 
}

struct mac_digest_data_t {
    bit<48> mac;
    bit<16> port;
}

struct ipv6_digest_data_t {
    IPv6Address ipv6;
    bit<8> index;
}

struct my_metadata_t {
    bit<8> src_state; /* Indicate source in port_ipv6 entry or not */
    bit<8> mac_state; // Indicate mac in mac_query table or not
    bit<8> index; // index of target_address in register
    mac_digest_data_t mac_digest;
    ipv6_digest_data_t ipv6_digest; 
}

/*********************************** REGISTER ***********************************/
register<HalfIPv6Address>(100) port_ipv6;
register<AddrState>(100) port_ipv6_state;

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
            default: accept; /* what happens in reject state is defined by an architecture */
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nh){
            NH_ICMPv6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition accept;
        /*transition select(hdr.icmpv6.type){
            TYPE_NS: accept;
            TYPE_NA: accept;
            default: accept;
        }*/
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
        mark_to_drop(standard_metadata);
    }

    action modify_egress_spec(bit<16> port){
        standard_metadata.egress_spec = (bit<9>)port;
    }
    
    action set_mac_in(){
        meta.mac_state=MAC_IN_MAC_QUERY_TABLE;
    }

    action set_mac_not_in(){
        meta.mac_state=MAC_NOT_IN_MAC_QUERY_TABLE;
    }

    action record_target_address_index(bit<8> index){
        meta.index = index;
    }

    table mac_query {
        key = {
            hdr.ethernet.src : exact;
        }
        actions = {
            set_mac_in;
            set_mac_not_in;
        }
        const default_action = set_mac_not_in;
        size = 1024;
    }

    table mac_forward {
        key = {
            hdr.ethernet.dst : exact;
        }
        actions = {
            drop;
            modify_egress_spec;
        }
        const default_action = drop;
        size = 1024;
    }

    table target_address_query {
        key = {
            hdr.icmpv6.target_address : exact;
        }
        actions = {
            record_target_address_inex;
            noAction;
        }
        const default_action = record_target_address_index;
        size = 1024;
    }

    action build_binding_entry(){
        bit<32> index;
        index = (bit<32>)standard_metadata.ingress_port;
        port_ipv6.write(index,(bit<64>)hdr.icmpv6.target_address);
        port_ipv6_state.write(index,ADDR_TENTATIVE);
    }

    action multicast(){
        //standard_metadata.mcast_grp=1;
        hdr.ipv6.src = 0xffffffff;
        standard_metadata.egress_spec = 1;
    }

    action verify_source(){
        HalfIPv6Address suffix;
        port_ipv6.read(suffix,(bit<32>)standard_metadata.ingress_port);
        if(suffix==(bit<64>)hdr.ipv6.src){
            /*port_ipv6_state.write(index,ADDR_PREFERRED);*/
            meta.src_state=SRC_IN_PORT_ENTRY;
        }else{
            meta.src_state=SRC_NOT_IN_PORT_ENTRY;
        }
    }

    /*action verify_target_address(){
        bit<32> index;
        index = (bit<32>)standard_metadata.ingress_port;
        IPv6Address ipv6;
        AddrState addr_state;
        port_ipv6.read(ipv6,index);
        if(ipv6==hdr.icmpv6.target_address){ 
            port_ipv6_state.read(addr_state,index);
            if(addr_state==ADDR_TENTATIVE){
                port_ipv6.write(index,0);
                port_ipv6_state.write(index,ADDR_DEPRECATED);
            }
        }
    }*/

    action notify_controller_build_mac_port(){
        /* transfer standard_metadata.ingress_port,hdr.ethernet.src parameter */
    }

    /* Code */
    apply{
        if(hdr.icmpv6.type==TYPE_NS){
            if(hdr.ipv6.src==0x0){
                // mac address learn 
                if(!mac_query.apply().hit){
                    meta.mac_digest.mac=hdr.ethernet.src;
                    meta.mac_digest.port=standard_metadata.ingress_port;
                    digest(1,meta.mac_digest); // Packet Digests to controller
                }
                if(!target_address_query.apply().hit){
                    build_binding_entry(); // Build port and ipv6 binding
                    meta.ipv6_digest.ipv6=hdr.icmpv6.target_address;
                    meta.ipv6_digest.index=standard_metadata.ingress_port;
                    digest(1,meta.ipv6_digest); 
                }
                multicast();
            }else{
                verify_source();
                if(meta.src_state==SRC_IN_PORT_ENTRY){ // change IPv6 address state
                    port_ipv6_state.write((bit<32>)standard_metadata.ingress_port,ADDR_PREFERRED);
                }else{
                    if (meta.src_state==SRC_NOT_IN_PORT_ENTRY){
                        drop();
                    }
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
                    verify_source();
                    if(meta.src_state==SRC_NOT_IN_PORT_ENTRY){
                        drop();
                    }
                    /*verify_target_address();*/
                    if(target_address_query.apply().hit){
                        HalfIPv6Address suffix;
                        AddrState addr_state;
                        port_ipv6.read(suffix,(bit<32>)meta.index);
                        if(suffix==(bit<64>)hdr.icmpv6.target_address){
                            port_ipv6_state.read(addr_state,(bit<32>)meta.index);
                            if(addr_state==ADDR_TENTATIVE){
                                /* Delete Binding Entry */
                                port_ipv6.write((bit<32>)meta.index,0);
                                port_ipv6_state.write((bit<32>)meta.index,ADDR_DEPRECATED);
                            }
                        }
                    }
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
        bit<48> timestamp;
        timestamp = standard_metadata.egress_global_timestamp-standard_metadata.ingress_global_timestamp;
        hdr.icmpv6.reserved = (bit<32>)timestamp;
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

/*
 * table_add MyIngress.mac_forward modify_egress_spec 33:33:ff:e4:89:00 => 2
 */