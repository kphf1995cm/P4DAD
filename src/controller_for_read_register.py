import nnpy
import struct
import keyboard
import sys

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
#from p4utils.utils.runtime_API import RuntimeAPI
from scapy.all import Ether, sniff, Packet, BitField

class L2Controller(object):

    def __init__(self, sw_name):
        #self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = 9090
        #self.thrift_port = self.topo.get_thrift_port(sw_name)
        #self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.cpu_port = 2
        self.controller = SimpleSwitchAPI(self.thrift_port)

        self.init()

    def init(self):
        self.controller.reset_state()
        #self.add_boadcast_groups()
        self.add_mirror()
        #self.fill_table_test()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port)

    def read_register(self):
        ns_recv = self.controller.register_read("ns_recv")
        na_recv = self.controller.register_read("na_recv")
        ns_filter = self.controller.register_read("ns_filter")
        na_filter = self.controller.register_read("na_filter")
        ns_recv_no_zero = []
        for x in ns_recv:
            if x!= 0:
                ns_recv_no_zero.append(x)
        na_recv_no_zero = []
        for x in na_recv:
            if x!= 0:
                na_recv_no_zero.append(x)
        ns_filter_no_zero = []
        for x in ns_filter:
            if x!= 0:
                ns_filter_no_zero.append(x)
        na_filter_no_zero = []
        for x in na_filter:
            if x!= 0:
                na_filter_no_zero.append(x)
        print "ns_recv: ",ns_recv_no_zero
        print "ns_filter: ",ns_filter_no_zero
        print "na_recv: ",na_recv_no_zero
        print "na_filter: ",na_filter_no_zero

if __name__ == "__main__":
    sw_name = sys.argv[1]
    controller = L2Controller(sw_name)
    keyboard.wait('esc')
    controller.read_register()

