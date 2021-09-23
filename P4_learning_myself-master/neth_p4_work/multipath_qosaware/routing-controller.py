from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
import json
import subprocess
import time

import os
from networkx.algorithms import all_pairs_dijkstra
from cli import CLI

class RoutingController(object):

    def __init__(self):

        self.topo = Topology(db="topology.db")
        self.controllers = {}
        self.hosts = {}
        self.links = {}
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
            controller.table_set_default("ipv6_tbl", "drop", [])
            #controller.table_set_default("ecmp_group_to_nhop", "drop", [])
            
            # print("############################")
            # print("controller:",controller)
            # print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

    def get_interfaces(self, link):
        """Return tuple of interfaces on both sides of the link."""
        node1, node2 = link
        if_12 = self.topo[node1][node2]['intf']
        if_21 = self.topo[node2][node1]['intf']
        return if_12, if_21

    def set_topoWeight(self,graph,type=0):
        # type = 0 ipv4_links
        # type = 1 ipv6_links
        print("set all topo-links weigth:")
        # file = open('linear-topo/links_weight.json','r')
        # for line in file.readlines():
        #     dic = json.loads(line)
        #     self.links.append(dic)
        
        # load the weight of links file which can be observed by measurement
        with open('linear-topo/links_weight.json','r') as fp:
            self.links = json.load(fp)

        # update the graph edges which will be used in the dijkstra to compute the shortest path
        typeOflink = "ipv4_links"
        if type == 1:
            typeOflink = "ipv6_links"

        for link in graph.edges:
            node1, node2 = link
            if1, if2 = self.get_interfaces(link)
            if node1 in self.links[typeOflink] and node2 in self.links[typeOflink][node1]:
                graph[node1][node2]["bw"] = self.links[typeOflink][node1][node2]["bw"]
                graph[node2][node1]["bw"] = self.links[typeOflink][node1][node2]["bw"]
                graph[node1][node2]["delay"] = self.links[typeOflink][node1][node2]["delay"]
                graph[node2][node1]["delay"] = self.links[typeOflink][node1][node2]["delay"]
                graph[node1][node2]["loss"] = self.links[typeOflink][node1][node2]["loss"]
                graph[node2][node1]["loss"] = self.links[typeOflink][node1][node2]["loss"]
                graph[node1][node2]["weight"] = self.links[typeOflink][node1][node2]["weight"]
                graph[node2][node1]["weight"] = self.links[typeOflink][node1][node2]["weight"]
                graph[node1][node2]["queue_length"] = self.links[typeOflink][node1][node2]["queue_length"]
                graph[node2][node1]["queue_length"] = self.links[typeOflink][node1][node2]["queue_length"]
            elif node2 in self.links[typeOflink] and node1 in self.links[typeOflink][node2]:
                graph[node1][node2]["bw"] = self.links[typeOflink][node2][node1]["bw"]
                graph[node2][node1]["bw"] = self.links[typeOflink][node2][node1]["bw"]
                graph[node1][node2]["delay"] = self.links[typeOflink][node2][node1]["delay"]
                graph[node2][node1]["delay"] = self.links[typeOflink][node2][node1]["delay"]
                graph[node1][node2]["loss"] = self.links[typeOflink][node2][node1]["loss"]
                graph[node2][node1]["loss"] = self.links[typeOflink][node2][node1]["loss"]
                graph[node1][node2]["weight"] = self.links[typeOflink][node2][node1]["weight"]
                graph[node2][node1]["weight"] = self.links[typeOflink][node2][node1]["weight"]
                graph[node1][node2]["queue_length"] = self.links[typeOflink][node2][node1]["queue_length"]
                graph[node2][node1]["queue_length"] = self.links[typeOflink][node2][node1]["queue_length"]
         
    
    def dijkstra(self, failures=None,type=0):
        """Compute shortest paths and distances.

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            tuple(dict, dict): First dict: distances, second: paths.
        """
        graph = self.topo.network_graph

        if failures is not None:
            graph = graph.copy()
            for failure in failures:
                graph.remove_edge(*failure)

        self.set_topoWeight(graph,type)
        # Compute the shortest paths from switches to hosts.

        # print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        # print("graph[s2][s4]['weight'] : ",graph['s2']['s4']['weight'])
        # print("-%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%-")

        dijkstra = dict(all_pairs_dijkstra(graph, weight='weight'))

        distances = {node: data[0] for node, data in dijkstra.items()}
        paths = {node: data[1] for node, data in dijkstra.items()}

        return distances, paths

    def route_4(self,failures=None):

        switch_ecmp_groups = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}
        # print("############################")
        # print("switch_ecmp_groups:",switch_ecmp_groups)
        # print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

        # get all shortest paths of the whole graph
        
        all_shortest_paths = self.dijkstra(failures=failures)[1]
        print("###############################")
        print("all shoretest path:")
        print(all_shortest_paths)
        print("_______________________________")

        for sw_name, controller in self.controllers.items():
            self.controllers[sw_name].table_clear("ipv4_tbl")
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
                        paths = all_shortest_paths[sw_name][sw_dst]

                        for host in self.topo.get_hosts_connected_to(sw_dst):

                            next_hop = paths[1]

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

    
    def route_6(self,failures=None):

        switch_ecmp_groups = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}
        # print("############################")
        # print("switch_ecmp_groups:",switch_ecmp_groups)
        # print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

        all_shortest_paths = self.dijkstra(failures=failures,type=1)[1]
        print("###############################")
        print("all shoretest path:")
        print(all_shortest_paths)
        print("_______________________________")

        for sw_name, controller in self.controllers.items():
            self.controllers[sw_name].table_clear("ipv6_tbl")
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
                        self.controllers[sw_name].table_add("ipv6_tbl", "ipv6_forward", [str(host_ip)], [str(host_mac), str(sw_port)])

                #check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        paths =  all_shortest_paths[sw_name][sw_dst]

                        for host in self.topo.get_hosts_connected_to(sw_dst):

                            next_hop = paths[1]

                            host_ip = self.hosts[host]
                            sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                            dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)

                            #add rule
                            print "table_add at {}:".format(sw_name)
                            self.controllers[sw_name].table_add("ipv6_tbl", "ipv6_forward", [str(host_ip)],
                                                                [str(dst_sw_mac), str(sw_port)])


                            # if len(paths) == 1:
                            #     next_hop = paths[0][1]


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
        # print("*********************************************")
        # print(self.topo._interface("s1","s2")["bw"])
        # print(self.topo._interface("s1","s2")['delay'])
        # print(self.topo._interface("s1","s2")['loss'])
        # print(self.topo._interface("s1","s2")['weight'])
        # print("*********************************************")

    def test_getPath(self):
        # shortest_path1 = self.topo.get_shortest_paths_between_nodes_by_weight("s1","s4","bw")
        # shortest_path2 = self.topo.get_shortest_paths_between_nodes_by_weight("s1","s4","delay")
        # shortest_path3 = self.topo.get_shortest_paths_between_nodes_by_weight("s1","s4","loss")
        # shortest_path4 = self.topo.get_shortest_paths_between_nodes_by_weight("s1","s4","weight")
        # all_paths = self.topo.get_all_paths_between_nodes("s1","s4")
        # print("###############################################################")
        # print("shortest_path1:",shortest_path1)
        # print("shortest_path2:",shortest_path2)
        # print("shortest_path3:",shortest_path3)
        # print("shortest_path4:",shortest_path4)
        # print("all_paths    :",all_paths)
        # print("***************************************************************")
        
        print("##################################################################")
        print("self.topo:",self.topo)
        print("******************************************************************")

    def main(self):
        self.config_hosts()
        self.test_getPath()
        ic=0
        while True:
            self.route_4()
            self.route_6()
            print("compute routing table {}-th".format(ic))
            ic = ic + 1
            time.sleep(20)
        
        


if __name__ == "__main__":
    controller = RoutingController().main()
