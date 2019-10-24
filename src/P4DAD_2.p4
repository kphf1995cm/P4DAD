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
const bit<8> TARGET_ADDRESS_IN_TARGET_ADDRESS_QUERY_TABLE=9;
const bit<8> TARGET_ADDRESS_NOT_IN_TARGET_ADDRESS_QUERY_TABLE=10;

const bit<32> NS_RECV_SUM = 0;
const bit<32> NS_RECV_FOR_DAD_SUM = 1;
const bit<32> NS_RECV_FOR_NOT_DAD_SUM = 2;
const bit<32> NS_FILTER_SUM = 3;
const bit<32> NA_RECV_SUM = 4;
const bit<32> NA_RECV_FOR_DAD_SUM = 5;
const bit<32> NA_RECV_FOR_NOT_DAD_SUM = 6;
const bit<32> NA_FILTER_SUM = 7;
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
    bit<8> target_address_state; // Indicate target_address in target_address_query table or not
    bit<8> index; // index of target_address in register
    mac_digest_data_t mac_digest;
    ipv6_digest_data_t ipv6_digest; 
}

/*********************************** REGISTER ***********************************/
register<HalfIPv6Address>(100) port_ipv6;
register<AddrState>(100) port_ipv6_state;
register<bit<64>>(8) statistics;  

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

    action multicast(){
        standard_metadata.egress_spec = 1;
    }

    /* Code */
    apply{
        if(hdr.icmpv6.type==TYPE_NS){
            if(hdr.ipv6.src==0x0){
                hdr.ipv6.src=0xffffffff;
            }else{
                hdr.ipv6.src=0xfffffffe;
            }
            multicast();
        }else{
            if(hdr.icmpv6.type==TYPE_NA){
               hdr.ipv6.src=0xfffffffd;
            }
            multicast();
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
        hdr.ethernet.dst = (bit<48>)standard_metadata.ingress_global_timestamp;
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