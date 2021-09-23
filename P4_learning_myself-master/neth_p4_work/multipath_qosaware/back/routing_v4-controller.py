from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
import json
import subprocess

class RoutingController(object):

    def __init__(self):

        self.topo = Topology(db="topology.db")
        self.controllers = {}
        self.hosts = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)
            # print("############################")
            # print("p4switch:",p4switch)
            # print("thrift_port:",thrift_port)
            # print("self.controllers[p4switch]",self.controllers[p4switch])
            # print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

    def set_table_defaults(self):
        for controller in self.controllers.values():
            controller.table_set_default("ipv4_tbl", "drop", [])
            #controller.table_set_default("ecmp_group_to_nhop", "drop", [])
            
            # print("############################")
            # print("controller:",controller)
            # print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

    def route(self):

        switch_ecmp_groups = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}
        # print("############################")
        # print("switch_ecmp_groups:",switch_ecmp_groups)
        # print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

        for sw_name, controller in self.controllers.items():
            for sw_dst in self.topo.get_p4switches():

                #if its ourselves we create direct connections
                if sw_name == sw_dst:
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        sw_port = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.hosts[host]
                        host_mac = self.topo.get_host_mac(host)

                        # print("############################")
                        # print("sw_name:",sw_name)
                        # print("sw_dst:",sw_dst)
                        # print("sw_port:",sw_port)
                        # print("host:",host)
                        # print("host_ip:",host_ip)
                        # print("host_mac:",host_mac)
                        # print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

                        #add rule
                        print "table_add at {}:".format(sw_name)
                        self.controllers[sw_name].table_add("ipv4_tbl", "ipv4_forward", [str(host_ip)], [str(host_mac), str(sw_port)])

                #check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        paths = self.topo.get_shortest_paths_between_nodes(sw_name, sw_dst)

                        for host in self.topo.get_hosts_connected_to(sw_dst):

                            next_hop = paths[0][1]

                            host_ip = self.hosts[host]
                            sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                            dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)

                            #add rule
                            print "table_add at {}:".format(sw_name)
                            self.controllers[sw_name].table_add("ipv4_tbl", "ipv4_forward", [str(host_ip)],
                                                                [str(dst_sw_mac), str(sw_port)])


                            # if len(paths) == 1:
                            #     next_hop = paths[0][1]

                            #     host_ip = self.topo.get_host_ip(host) + "/24"
                            #     sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                            #     dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)

                            #     #add rule
                            #     print "table_add at {}:".format(sw_name)
                            #     self.controllers[sw_name].table_add("ipv4_lpm", "set_nhop", [str(host_ip)],
                            #                                         [str(dst_sw_mac), str(sw_port)])

                            # elif len(paths) > 1:
                            #     next_hops = [x[1] for x in paths]
                            #     dst_macs_ports = [(self.topo.node_to_node_mac(next_hop, sw_name),
                            #                        self.topo.node_to_node_port_num(sw_name, next_hop))
                            #                       for next_hop in next_hops]
                            #     host_ip = self.topo.get_host_ip(host) + "/24"

                            #     #check if the ecmp group already exists. The ecmp group is defined by the number of next
                            #     #ports used, thus we can use dst_macs_ports as key
                            #     if switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None):
                            #         ecmp_group_id = switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None)
                            #         print "table_add at {}:".format(sw_name)
                            #         self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                            #                                             [str(ecmp_group_id), str(len(dst_macs_ports))])

                            #     #new ecmp group for this switch
                            #     else:
                            #         new_ecmp_group_id = len(switch_ecmp_groups[sw_name]) + 1
                            #         switch_ecmp_groups[sw_name][tuple(dst_macs_ports)] = new_ecmp_group_id

                            #         #add group
                            #         for i, (mac, port) in enumerate(dst_macs_ports):
                            #             print "table_add at {}:".format(sw_name)
                            #             self.controllers[sw_name].table_add("ecmp_group_to_nhop", "set_nhop",
                            #                                                 [str(new_ecmp_group_id), str(i)],
                            #                                                 [str(mac), str(port)])

                            #         #add forwarding rule
                            #         print "table_add at {}:".format(sw_name)
                            #         self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                            #                                             [str(new_ecmp_group_id), str(len(dst_macs_ports))])

    def config_hosts(self):
        print("config_hosts:")
        with open('linear-topo/hosts.json','r') as fp:
            self.hosts = json.load(fp)

        # for sw_name in self.topo.get_p4switches():
        #     for host in self.topo.get_hosts_connected_to(sw_name):
        #         host = "h{}".format(v6route['port'])
        for host in self.hosts:
            # print(subprocess.call([host, "ip", "addr", "flush", "dev", "{}-eth0".format(host)]))
            subprocess.call(["mx", host, "ip", "addr", "flush", "dev", "{}-eth0".format(host)])
            subprocess.call(["mx", host, "sysctl", "net.ipv6.conf.{}-eth0.disable_ipv6=0".format(host)])

            # Set down & up to regain link local address
            subprocess.call(["mx", host, "ip", "link", "set", "{}-eth0".format(host), "down"])
            subprocess.call(["mx", host, "ip", "link", "set", "{}-eth0".format(host), "up"])
            subprocess.call(["mx", host, "ip", "addr", "add", self.hosts[host], "dev", "{}-eth0".format(host)])


    def main(self):
        self.config_hosts()
        self.route()


if __name__ == "__main__":
    controller = RoutingController().main()
