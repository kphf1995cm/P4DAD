# coding:utf-8
#! /usr/bin/env python

from scapy.all import *
import random
import datetime

ifaceNames = ["enp0s31f6","docker0"]

globalSrcAddr = "2001:db8:0:1:c0bc:a2a0:21d6:6a0b"
globalDstAddr = "ff02::1"

linkSrcAddr = "fe80::437f:2137:3e16:b6ea"
linkOtherSrcAddr = "fe80::437f:2137:3e16:b6eb"
linkDstAddr = "ff02::1"
linkFakeSrc = "fe80::437f:2137:3e16:ffff"

macSrcAddr = "8c:ec:4b:73:25:8d"
macMultiAddr = "33:33:ff:e4:89:00"

def send_ns_pkt(target_address,ifaceName):
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    a=IPv6(src="::", dst='ff02::1:ff21:41f')
    b=ICMPv6ND_NS(tgt=target_address)
    print "send NS packet target address:",target_address
    sendp(ether/a/b,count=1,iface=ifaceName)

def send_forge_ns_pkt(target_address,ifaceName):
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    a=IPv6(src=linkFakeSrc, dst='ff02::1:ff21:41f')
    b=ICMPv6ND_NS(tgt=target_address)
    print "send forge NS packet target address:",target_address
    sendp(ether/a/b,count=1,iface=ifaceName)  

def send_na_pkt(target_address,ifaceName):
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    a=IPv6(src=target_address, dst=linkDstAddr)
    b=ICMPv6ND_NA(tgt=target_address)
    print "send NA packet target address:",target_address
    sendp(ether/a/b,count=1,iface=ifaceName)

def send_forge_na_pkt(target_address,ifaceName):
    ether=Ether(src=macSrcAddr,dst=macMultiAddr)
    a=IPv6(src=linkFakeSrc, dst=linkDstAddr)
    b=ICMPv6ND_NA(tgt=target_address)
    print "send forge NA packet target address:",target_address
    sendp(ether/a/b,count=1,iface=ifaceName)

if __name__ == "__main__":
    start = datetime.datetime.now()
    ns_time = []
    forge_ns_time = []
    na_time = []
    forge_na_time = []
    ns_num = 0
    na_num = 0
    forge_ns_num = 0
    forge_na_num = 0
    forge_pkt_sum = 50
    normal_pkt_sum = 150
    while True:
        way = random.randint(0,7)
        ifIdx = 0
        if way>=0 and way <3 and ns_num < normal_pkt_sum:
            ns_time.append((datetime.datetime.now()-start).seconds*1000)
            send_ns_pkt(linkSrcAddr,ifaceNames[ifIdx])
            ns_num += 1
        if way==3 and forge_ns_num < forge_pkt_sum:
            forge_ns_time.append((datetime.datetime.now()-start).seconds*1000)
            send_forge_ns_pkt(linkSrcAddr,ifaceNames[ifIdx])
            forge_ns_num += 1
        if way>=4 and way <7 and na_num < normal_pkt_sum:
            na_time.append((datetime.datetime.now()-start).seconds*1000)
            send_na_pkt(linkSrcAddr,ifaceNames[ifIdx])
            na_num += 1
        if way==7 and forge_na_num < forge_pkt_sum:
            forge_na_time.append((datetime.datetime.now()-start).seconds*1000)
            send_forge_na_pkt(linkSrcAddr,ifaceNames[ifIdx])
            forge_na_num += 1
        if ns_num >= normal_pkt_sum and na_num >= normal_pkt_sum and forge_ns_num >= forge_pkt_sum and forge_na_num >=forge_pkt_sum:
            break
        sleep_time = random.randint(5,10)
        time.sleep(0.1*sleep_time)
    print "ns_time:",len(ns_time),ns_time
    print "na_time:",len(na_time),na_time
    print "forge_ns_time:",len(forge_ns_time),forge_ns_time
    print "forge_na_time:",len(forge_na_time),forge_na_time