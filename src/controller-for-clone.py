import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField

# https://github.com/nsg-ethz/p4-learning/blob/master/exercises/04-L2_Learning/l2_learning_controller.py
# https://github.com/nsg-ethz/p4-learning/blob/master/documentation/simple-switch.md#cloning-packets

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]

class L2Controller(object):

    def __init__(self, sw_name):
        self.sw_name = sw_name
        self.thrift_port = 9090
        self.cpu_port = 2
        self.controller = SimpleSwitchAPI(self.thrift_port)

        self.init()

    def init(self):
        self.controller.reset_state()
        self.add_mirror()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port)

    def fill_mac_query_table_test(self):
        self.controller.table_add("mac_forward", "modify_egress_spec", ['00:00:0a:00:00:01'], ['1'])
        self.controller.table_add("mac_forward", "modify_egress_spec", ['00:00:0a:00:00:02'], ['2'])
        self.controller.table_add("mac_forward", "modify_egress_spec", ['00:00:0a:00:00:03'], ['3'])
        self.controller.table_add("mac_forward", "modify_egress_spec", ['00:00:0a:00:00:04'], ['4'])
    
    def mac_learn(self, learning_data):
        for mac_addr, ingress_port in  learning_data:
            print "mac: %012X ingress_port: %s " % (mac_addr, ingress_port)
            self.controller.table_add("mac_query", "set_mac_in", [str(mac_addr)])
            self.controller.table_add("mac_forward", "modify_egress_spec", [str(mac_addr)], [str(ingress_port)])
    
    def ipv6_learn(self,learning_data):
        for target_address, index in learning_data:
            print "target_address: %012X index: %s " % (target_address, index)
            self.controller.table_add("target_address_query","set_target_address_in",[str(target_address)],[str(index)])

    def unpack_digest(self, msg, num_samples):
        digest = []
        print len(msg), num_samples
        starting_index = 32
        for sample in range(num_samples):
            mac0, mac1, ingress_port = struct.unpack(">LHH", msg[starting_index:starting_index+8])
            starting_index +=8
            mac_addr = (mac0 << 16) + mac1
            digest.append((mac_addr, ingress_port))

        return digest

    def recv_msg_digest(self, msg):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                          msg[:32])
        digest = self.unpack_digest(msg, num)
        print "digest:",digest," digest len:",len(digest)
        self.mac_learn(digest)

        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        sub.connect('ipc:///tmp/bmv2-0-notifications.ipc')
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
	print "run_digest_loop"

        while True:
            msg = sub.recv()
            #print "msg:",msg
            self.recv_msg_digest(msg)

    def recv_msg_cpu(self, pkt):
        packet = Ether(str(pkt))
        if packet.type == 0x1234:
            cpu_header = CpuHeader(packet.payload)
            self.mac_learn([(cpu_header.macAddr, cpu_header.ingress_port)])

    def run_cpu_port_loop(self):
        cpu_port_intf = "docker0"
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)

if __name__ == "__main__":
    import sys
    sw_name = sys.argv[1]
    receive_from = sys.argv[2]
    if receive_from == "digest":
        controller = L2Controller(sw_name)
        controller.run_digest_loop()
    elif receive_from == "cpu":
        controller = L2Controller(sw_name)
        controller.run_cpu_port_loop()
