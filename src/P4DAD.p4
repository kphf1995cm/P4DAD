# include <core.p4>
# include <sum_switch.p4>

// How many bits fit in the query name.
#define QNAME_LENGTH 56
// How many bits we can return as a reponse.
#define DNS_RESPONSE_SIZE 128
// We can only send 256 bits to the CPU per packet.
// 64 are already taken with the Ethernet address for the learning
// switch.  I think we could take that down to 48 if this is a limit.
#define BITS_USED_FOR_DIGEST_FLAGS 8
#define BITS_USED_FOR_PORT_ID 8
#define IP_ADDR_LENGTH 32
#define DNS_TTL 32
#define UNUSED_DIGEST_BITS_COMPUTED 256 - 64 - BITS_USED_FOR_DIGEST_FLAGS - BITS_USED_FOR_PORT_ID
#if UNUSED_DIGEST_BITS_COMPUTED < 0
#error "Unused digest bits must be greater than or equal to 0"
#endif
// The preprocessor can't compute, so this actually needs to be done manually.
#define UNUSED_DIGEST_BITS 176
#if UNUSED_DIGEST_BITS != UNUSED_DIGEST_BITS_COMPUTED
#error "UNUSED_DIGEST_BITS must be updated whenever any lengths are updated"
#error "Also make sure to update sss_digest_header.py"
#endif

#define CPU_PORTS 8w0b10101010

#define IS_DNS 1
#define IS_DNS_RESPONSE 2
#define RECURSION_REQUESTED 4
#define FORWARDING_ENTRY 8

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;
typedef bit<128> TargetAddress;

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

header icmpv6_rs_h {
    bit<8> type; // 133
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
    //bit<32> options;
}

header icmpv6_ra_h {
    bit<8> type; // 134
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
    bit<32> reachable_time;
    bit<32> retrans_timer;
    //bit<32> options;
}

header icmpv6_ns_h {
    bit<8> type; // 135
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
    TargetAddress target_address;
    //bit<32> options;
}

header icmpv6_na_h {
    bit<8> type; // 136
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
    TargetAddress target_address;
    //bit<32> options;
}

header icmpv6_redirect_h { 
    bit<8> type; // 137
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
    TargetAddress target_address;
    IPv6Address destination_address;
    //bit<32> options;
}

header icmpv6_h {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header icmpv6_ns_na_h {
    bit<8> type; // 135、136
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
    TargetAddress target_address;
}

// List of all recognized headers
struct parsed_packet {
    ethernet_h ethernet;
    ipv6_h ipv6;
    icmpv6_ns_na_h icmpv6; 
}

// register

// parsers


