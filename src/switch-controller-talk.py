# coding:utf-8
#! /usr/bin/env python

from scapy.all import *
import random
import datetime

ifaceNames = ["enp0s31f6","docker0"]

linkSrcAddr = "fe80::437f:2137:3e16:b6ea"
linkDstAddr = "ff02::1:ff21:41f"

macSrcAddr = "8c:ec:4b:73:25:8d"
macOtherSrcAddr = "7c:76:35:de:0c:79"
macMultiAddr = "33:33:ff:e4:89:00"

def send_dad_ns_pkt(ifaceName):
	ether=Ether(src=macSrcAddr,dst=macMultiAddr)
	a=IPv6(src="::", dst=linkDstAddr)
	b=ICMPv6ND_NS(tgt=linkSrcAddr)
	print "send DAD NS packet target address:",linkSrcAddr
	sendp(ether/a/b,iface=ifaceName)

def send_ns_pkt(ifaceName):
	ether=Ether(src=macOtherSrcAddr,dst=macSrcAddr)
	a=IPv6(src=linkSrcAddr, dst=linkDstAddr)
	b=ICMPv6ND_NS(tgt=linkSrcAddr)
	print "send NS packet target address:",linkSrcAddr
	sendp(ether/a/b,iface=ifaceName)

if __name__ == "__main__":
	#for i in range(5) :
	#	send_dad_ns_pkt(ifaceNames[0])
	send_dad_ns_pkt(ifaceNames[0])
	while True:
		send_ns_pkt(ifaceNames[0])
