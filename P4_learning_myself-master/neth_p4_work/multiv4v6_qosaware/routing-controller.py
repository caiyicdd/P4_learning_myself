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
        self.switches = {}
        self.tunnels = {}
        self.ipv4_host = {}
        self.ipv6_host = {}
        self.graph_ipv4 = self.topo.network_graph.copy()
        self.graph_ipv6 = self.topo.network_graph.copy()
        self.fullRouting_tbl = {sw_name:[] for sw_name in self.topo.get_p4switches().keys()}
        self.virtualHost = {sw_name:[] for sw_name in self.topo.get_p4switches().keys()}
        self.all_distance = {}
        self.all_shortest_paths = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()
        self.load_config()

    def load_config(self):
        config = {}
        with open('linear-topo/conf.json','r') as fp:
            config = json.load(fp)
        self.switches["ipv4"] = config["network"]["ipv4"]
        self.switches["ipv6"] = config["network"]["ipv6"]
        self.tunnels = config["network"]["tunnels"]
        self.ipv4_host = config["network"]["ipv4_host"]
        self.ipv6_host = config["network"]["ipv6_host"]
        
        all_switch = {sw_name for sw_name in self.topo.get_p4switches().keys()}
        ipv4_switch = {}
        ipv6_switch = {}
        for i in range(len(self.switches["ipv4"])):
            ipv4_switch[i] = self.switches["ipv4"][i]
        for i in range(len(self.switches["ipv6"])):
            ipv6_switch[i] = self.switches["ipv6"][i]


        not_ipv4_switch = all_switch - set(ipv4_switch.values())
        not_ipv6_switch = all_switch - set(ipv6_switch.values())

        # print("&&&&&&&&&&&&& before topo ipv4 &&&&&&&&&&&&&&&&&&&&&")
        # print("all_switch:",all_switch)
        # print("ipv4_switch:",ipv4_switch)
        # print("not_ipv4_switch:",not_ipv4_switch)
        # print(self.traverse_graph(self.graph_ipv4))
        # print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")

        for sw in not_ipv4_switch:
            for sw2 in not_ipv4_switch - set(sw):
                if self.graph_ipv4.has_edge(sw,sw2):
                    self.graph_ipv4.remove_edge(sw,sw2)
            self.graph_ipv4.remove_node(sw)

        for sw in not_ipv6_switch:
            for sw2 in not_ipv6_switch - set(sw):
                if self.graph_ipv6.has_edge(sw,sw2):
                    self.graph_ipv6.remove_edge(sw,sw2)
            self.graph_ipv6.remove_node(sw)

        # print("&&&&&&&&&&&&& after topo ipv4 &&&&&&&&&&&&&&&&&&&&&")
        # print(self.traverse_graph(self.graph_ipv6))
        # print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
        # print(self.traverse_graph(self.topo.network_graph))

    def traverse_graph(self,graph):
        for node in graph.__iter__():
            print("node:",node)
            print("neighbors:")
            for adj_node in graph.neighbors(node):
                print(adj_node)

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
        if type == 0 :
            graph = self.graph_ipv4
        elif type == 1 :
            graph = self.graph_ipv6

        if failures is not None:
            graph = graph.copy()
            for failure in failures:
                graph.remove_edge(*failure)

        self.set_topoWeight(graph,type)
        # Compute the shortest paths from switches to hosts.

        dijkstra = dict(all_pairs_dijkstra(graph, weight='weight'))

        distances = {node: data[0] for node, data in dijkstra.items()}
        paths = {node: data[1] for node, data in dijkstra.items()}

        return distances, paths

    def route_4(self,failures=None):
        
        self.all_distance["ipv4"], self.all_shortest_paths["ipv4"] = self.dijkstra(failures=failures, type=0)

        for sw_name, controller in self.controllers.items():
            if not self.graph_ipv4.has_node(sw_name):
                continue;
            self.controllers[sw_name].table_clear("ipv4_tbl")
            for sw_dst in self.topo.get_p4switches():               
                #if its ourselves we create direct connections
                if sw_name == sw_dst:
                    host_to_sw = self.topo.get_hosts_connected_to(sw_name)
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        sw_port = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.hosts[host]
                        host_mac = self.topo.get_host_mac(host)

                        #add rule
                        print "table_add at {}(fforward):".format(sw_name)
                        self.controllers[sw_name].table_add("ipv4_tbl", "ipv4_forward", [str(host_ip)], [str(host_mac), str(sw_port)])

                #check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        if not self.graph_ipv4.has_node(sw_dst):
                            continue;
                        paths = self.all_shortest_paths["ipv4"][sw_name][sw_dst]

                        for host in self.topo.get_hosts_connected_to(sw_dst):
                            if host not in self.ipv4_host:
                                continue
                            next_hop = paths[1]
                
                            host_ip = self.hosts[host]
                            sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                            dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)

                            if sw_name in self.tunnels["6over4"] and sw_dst in self.tunnels["6over4"]:
                               dst_type,src_gre_ip,dst_gre_ip = self.tunnel(sw_name, sw_dst, "0x0800", host_ip)
                               print("*********************IPv4 Routing***************************")
                               if dst_type != "0x0800":
                                    print("diferent path should be selected:")
                                    if self.all_distance.has_key("ipv6"):
                                        print("the former paht : (wight = {})".format(self.all_distance["ipv4"][sw_name][sw_dst]))
                                        print(self.all_shortest_paths["ipv4"][sw_name][sw_dst])
                                    print("the new path : (wight = {})".format(self.all_distance["ipv6"][sw_name][sw_dst]))
                                    print(self.all_shortest_paths["ipv6"][sw_name][sw_dst])

                                    print "table_add at {} (add_gre_header):".format(sw_name)
                                    self.controllers[sw_name].table_add("ipv4_tbl","add_ipv4_gre_header",[str(host_ip)],[str(src_gre_ip),str(dst_gre_ip)])
                                    self.controllers[sw_name].table_add("ipv4_tbl","ipv4_forward",[str()])

                               else:
                                    next_hop = paths[1]
                                    sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                    dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)
                                    #add rule
                                    print "table_add at {} (forward):".format(sw_name)
                                    self.controllers[sw_name].table_add("ipv4_tbl", "ipv4_forward", [str(host_ip)],
                                                                            [str(dst_sw_mac), str(sw_port)])
                               
                               print("**************************************************")

                            else :
                                next_hop = paths[1]
                                sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)
                                #add rule
                                print "table_add at {} (forward):".format(sw_name)
                                self.controllers[sw_name].table_add("ipv4_tbl", "ipv4_forward", [str(host_ip)],
                                                                            [str(dst_sw_mac), str(sw_port)])

                            if sw_dst in self.tunnels["6over4"]:
                                next_hop = paths[1]
                                sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)
                                for i in range(len(self.virtualHost[sw_dst])):
                                    if self.virtualHost[sw_dst][i][0] == "0x0800":
                                        host_ip = self.virtualHost[sw_dst][i][1] + "/32"
                                        self.controllers[sw_name].table_add("ipv4_tbl", "ipv4_forward", [str(host_ip)],
                                                                        [str(dst_sw_mac), str(sw_port)])

    
    def route_6(self,failures=None):

        self.all_distance["ipv6"], self.all_shortest_paths["ipv6"] = self.dijkstra(failures=failures,type=1)

        for sw_name, controller in self.controllers.items():
            if not self.graph_ipv6.has_node(sw_name):
                continue;
            self.controllers[sw_name].table_clear("ipv6_tbl")
            for sw_dst in self.topo.get_p4switches():                
                #if its ourselves we create direct connections
                if sw_name == sw_dst:
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        sw_port = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.hosts[host]
                        host_mac = self.topo.get_host_mac(host)

                        #add rule
                        print "table_add at {}:(v6 fforward)".format(sw_name)
                        self.controllers[sw_name].table_add("ipv6_tbl", "ipv6_forward", [str(host_ip)], [str(host_mac), str(sw_port)])
                        

                #check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        if not self.graph_ipv6.has_node(sw_dst):
                            continue;
                        paths =  self.all_shortest_paths["ipv6"][sw_name][sw_dst]

                        for host in self.topo.get_hosts_connected_to(sw_dst):
                            if host not in self.ipv6_host:
                                continue
                                                        
                            host_ip = self.hosts[host]
                            
                            if sw_name in self.tunnels["4over6"] and sw_dst in self.tunnels["4over6"]:
                                dst_type,src_gre_ip,dst_gre_ip = self.tunnel(sw_name, sw_dst,"0x08dd",host_ip)
                                print("###################IPv6 Routing##########################")
                                if dst_type != "0x08dd":
                                    print("diferent path should be selected:")
                                    if self.all_distance.has_key("ipv4"):
                                        print("the former paht : (wight = {})".format(self.all_distance["ipv6"][sw_name][sw_dst]))
                                        print(self.all_shortest_paths["ipv6"][sw_name][sw_dst])
                                    print("the new path : (wight = {})".format(self.all_distance["ipv4"][sw_name][sw_dst]))
                                    print(self.all_shortest_paths["ipv4"][sw_name][sw_dst])

                                    print "table_add at {} (v6 add_gre_header):".format(sw_name)
                                    self.controllers[sw_name].table_add("ipv6_tbl","add_ipv6_gre_header",[str(host_ip)],[str(src_gre_ip),str(dst_gre_ip)])

                                else :
                                    next_hop = paths[1]
                                    sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                    dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)
                                    #add rule
                                    print "table_add at {} (v6 forward 1):".format(sw_name)
                                    self.controllers[sw_name].table_add("ipv6_tbl", "ipv6_forward", [str(host_ip)],
                                                                        [str(dst_sw_mac), str(sw_port)])
                                
                                
                                    for i in range(len(self.virtualHost[sw_dst])):
                                        if self.virtualHost[sw_dst][i][0] == "0x08dd":
                                            host_ip = self.virtualHost[sw_dst][i][1] + "/128"
                                            print "table_add at {} (v6 forward 3):".format(sw_name)
                                            self.controllers[sw_name].table_add("ipv6_lpm", "ipv6_forward", [str(host_ip)],
                                                                            [str(dst_sw_mac), str(sw_port)])
                                print("##############################################")
                            else:
                                next_hop = paths[1]
                                sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)
                                #add rule
                                print "table_add at {} (v6 forward 2):".format(sw_name)
                                self.controllers[sw_name].table_add("ipv6_tbl", "ipv6_forward", [str(host_ip)],
                                                                        [str(dst_sw_mac), str(sw_port)])



                    if sw_dst in self.tunnels["4over6"]:
                        paths =  self.all_shortest_paths["ipv6"][sw_name][sw_dst]
                        next_hop = paths[1]
                        sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                        dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)
                        for i in range(len(self.virtualHost[sw_dst])):
                            if self.virtualHost[sw_dst][i][0] == "0x08dd":
                                host_ip = self.virtualHost[sw_dst][i][1] + "/128"
                                print "table_add at {} (v6 forward 3):".format(sw_name)
                                self.controllers[sw_name].table_add("ipv6_tbl", "ipv6_forward", [str(host_ip)],
                                                                        [str(dst_sw_mac), str(sw_port)])

                            


    def tunnel(self, sw1, sw2, src_type, dstip):
        print("config and keep tunnel alive...")
        dst_ip = self.tunnels["4over6"][sw2]
        src_ip = self.tunnels["4over6"][sw1]
        if src_type == "0x0800":
            graph = self.graph_ipv4
            dst_type = "0x08dd"
            # ipv4over6 = self.tunnels["4over6"]
            if not self.all_shortest_paths.has_key("ipv6"):
                res_type = src_type
                src_gre_ip = None
                dst_gre_ip = None
                return res_type, src_gre_ip, dst_gre_ip
            path =  self.all_shortest_paths["ipv6"][sw1][sw2]
            next_hop = path[1]
            
            sw_port = self.topo.node_to_node_port_num(sw1, next_hop)
            dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw1)
            bw,delay,loss,wight,queue_length = self.get_allWeights(dst_type, sw1, sw2)
            index = -1

            for i in range(len(self.fullRouting_tbl[sw1])):
                try:
                    index = self.fullRouting_tbl[sw1][i].index((dst_type,sw2))
                except ValueError:
                    pass
                else:
                    index = i
                    break
            if index == -1:
                # item:[(type,dstSwID),srcSwID,srcip,dstip,]
                # type : the forward network type
                # destSwID,srcSwID : border router of tunnel
                # srcip,dstip : the ip address of border router , new type ,encapuslate in the new header
                # bw,delay,loss,wight,queue_length : get from measurement
                new_item = [(dst_type,sw2),sw1,src_ip,dst_ip,sw_port,bw,delay,loss,wight,queue_length]
                self.fullRouting_tbl[sw1].append(new_item)
                print("{} add a new item:".format(sw1))
                print(new_item)
                print("add a new tunnel interfaces({}).".format(dst_type))

                self.virtualHost[sw1].append((dst_type,src_ip))
                self.virtualHost[sw1]=list(set(self.virtualHost[sw1]))

            else:
                print("{} update exist item: {} ".format(sw1,index))
                print("before update:")
                print(self.fullRouting_tbl[sw1][index])
                self.fullRouting_tbl[sw1][index] = [(dst_type,sw2),sw1,src_ip,dst_ip,sw_port,bw,delay,loss,wight,queue_length]
                print("after update:")
                print(self.fullRouting_tbl[sw1][index])

                self.virtualHost[sw1].append((dst_type,src_ip))
                self.virtualHost[sw1]=list(set(self.virtualHost[sw1]))

        self.controllers[sw1].table_add("ipv6_tbl","mov_ipv6_gre_header",[str(src_ip+"/64")])
        self.controllers[sw2].table_add("ipv6_tbl","mov_ipv6_gre_header",[str(dst_ip+"/64")])


        dst_ip = self.tunnels["6over4"][sw2]
        src_ip = self.tunnels["6over4"][sw1]
        if src_type == "0x08dd" :
            dst_type = "0x0800"
            if not self.all_shortest_paths.has_key("ipv4"):
                res_type = src_type
                src_gre_ip = None
                dst_gre_ip = None
                return res_type, src_gre_ip, dst_gre_ip
            path =  self.all_shortest_paths["ipv4"][sw1][sw2]
            next_hop = path[1]
            
            sw_port = self.topo.node_to_node_port_num(sw1, next_hop)
            dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw1)
            bw,delay,loss,wight,queue_length = self.get_allWeights(dst_type, sw1, sw2)
            index = -1
            for i in range(len(self.fullRouting_tbl[sw1])):
                try:
                    index = self.fullRouting_tbl[sw1][i].index((dst_type,sw2))
                except ValueError:
                    pass
                else:
                    index = i
                    break
            if index == -1:
                # item:[(type,dstSwID),srcSwID,srcip,dstip,]
                # type : the forward network type
                # destSwID,srcSwID : border router of tunnel
                # srcip,dstip : the ip address of border router , new type ,encapuslate in the new header
                # bw,delay,loss,wight,queue_length : get from measurement
                new_item = [(dst_type,sw2),sw1,src_ip,dst_ip,sw_port,bw,delay,loss,wight,queue_length]
                self.fullRouting_tbl[sw1].append(new_item)
                print("add a new item:")
                print(new_item)

                self.virtualHost[sw1].append((dst_type,src_ip))
                self.virtualHost[sw1]=list(set(self.virtualHost[sw1]))

            else:
                print("update exist item: ",index)
                print("before update:")
                print(self.fullRouting_tbl[sw1][index])
                self.fullRouting_tbl[sw1][index] = [(dst_type,sw2),sw1,src_ip,dst_ip,sw_port,bw,delay,loss,wight,queue_length]
                print("after update:")
                print(self.fullRouting_tbl[sw1][index])

                self.virtualHost[sw1].append((dst_type,src_ip))
                self.virtualHost[sw1]=list(set(self.virtualHost[sw1]))

        self.controllers[sw1].table_add("ipv4_tbl","mov_ipv4_gre_header",[str(src_ip+"/24")])
        self.controllers[sw2].table_add("ipv4_tbl","mov_ipv4_gre_header",[str(dst_ip+"/24")])

        bw1,delay1,loss1,wight1,queue_length1 = self.get_allWeights(src_type, sw1, sw2)
        res_wight = wight1
        res_type = src_type
        src_gre_ip = None
        dst_gre_ip = None

        print("^^^^^^^^^^^^^^^^^^^^^before calc weight^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
        print("weight : ",res_wight)
        print("type : ",res_type)
        print("{} <-> {}".format(sw1,sw2))
        print("{} <-> {}".format(src_gre_ip,dst_gre_ip))
        
        for i in range(len(self.fullRouting_tbl[sw1])):
            try:
                index = self.fullRouting_tbl[sw1][i][1].index(sw2)
            except ValueError:
                pass
            else:
                index = i   
                     
            bw2,delay2,loss2,wight2,queue_length2 = self.get_allWeights(self.fullRouting_tbl[sw1][i][0][0], sw1, sw2)
            print("compare with : ",self.fullRouting_tbl[sw1][i][0])
            if wight2 != None and res_wight > wight2:
                res_type = self.fullRouting_tbl[sw1][i][0][0]
                res_wight = wight2
                src_gre_ip = self.fullRouting_tbl[sw1][i][2]
                dst_gre_ip = self.fullRouting_tbl[sw1][i][3]

        print("^^^^^^^^^^^^^^^^^^^^^after calc weight^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
        print("weight : ",res_wight)
        print("type : ",res_type)
        print("{} <-> {}".format(sw1,sw2))
        print("{} <-> {}".format(src_gre_ip,dst_gre_ip))
            
        return res_type,src_gre_ip,dst_gre_ip



    # def addVitualLink(self,sw1,sw2,dst_type,src_ip,dst_ip):
    #     index = -1
    #     for i in range(len(self.virtualLink)):
    #         try:
    #             index = self.virtualLink[i].index((sw1,sw2,dst_type))
    #         except ValueError:
    #             pass
    #         else:
    #             index = i
    #             break

    def printTopoGraph(self,graph):
        for sw , swAdj in graph.adjacency():
            print("switch : ",sw)
            for nb ,eattr in swAdj.items():
                print ('neighbors : ',nb)
                print("edge-attr : ",eattr)

    def get_allWeights(self, type, sw1, sw2):
        bw = None
        delay = None
        loss = None
        weight = None
        queue_length = None
        if type == "0x0800":
            paths = self.all_shortest_paths["ipv4"][sw1][sw2]
            bw = self.graph_ipv4[paths[0]][paths[1]]["bw"]
            delay = self.graph_ipv4[paths[0]][paths[1]]["delay"]
            loss = self.graph_ipv4[paths[0]][paths[1]]["loss"]
            weight = self.graph_ipv4[paths[0]][paths[1]]["weight"]
            queue_length = self.graph_ipv4[paths[0]][paths[1]]["queue_length"]
            for i in range(1,len(paths)):
                if i + 1 < len(paths):
                    bw = min(bw, self.graph_ipv4[paths[i]][paths[i+1]]["bw"])
                    delay = delay + self.graph_ipv4[paths[i]][paths[i+1]]["delay"]
                    loss = loss + self.graph_ipv4[paths[i]][paths[i+1]]["loss"]
                    weight = weight + self.graph_ipv4[paths[i]][paths[i+1]]["weight"]
                    queue_length = min(queue_length,self.graph_ipv4[paths[i]][paths[i+1]]["queue_length"])
        elif type == "0x08dd":
            paths = self.all_shortest_paths["ipv6"][sw1][sw2]
            bw = self.graph_ipv6[paths[0]][paths[1]]["bw"]
            delay = self.graph_ipv6[paths[0]][paths[1]]["delay"]
            loss = self.graph_ipv6[paths[0]][paths[1]]["loss"]
            weight = self.graph_ipv6[paths[0]][paths[1]]["weight"]
            queue_length = self.graph_ipv6[paths[0]][paths[1]]["queue_length"]
            for i in range(1,len(paths)):
                if i + 1 < len(paths):
                    bw = min(bw, self.graph_ipv6[paths[i]][paths[i+1]]["bw"])
                    delay = delay + self.graph_ipv6[paths[i]][paths[i+1]]["delay"]
                    loss = loss + self.graph_ipv6[paths[i]][paths[i+1]]["loss"]
                    weight = weight + self.graph_ipv6[paths[i]][paths[i+1]]["weight"]
                    queue_length = min(queue_length,self.graph_ipv6[paths[i]][paths[i+1]]["queue_length"])
        return bw,delay,loss,weight,queue_length

    def config_hosts(self):
        print("config_hosts:")
        with open('linear-topo/hosts.json','r') as fp:
            self.hosts = json.load(fp)

        for host in self.hosts:
            # print(subprocess.call([host, "ip", "addr", "flush", "dev", "{}-eth0".format(host)]))
            subprocess.call(["mx", host, "ip", "addr", "flush", "dev", "{}-eth0".format(host)])
            subprocess.call(["mx", host, "sysctl", "net.ipv6.conf.{}-eth0.disable_ipv6=0".format(host)])

            # Set down & up to regain link local address
            subprocess.call(["mx", host, "ip", "link", "set", "{}-eth0".format(host), "down"])
            subprocess.call(["mx", host, "ip", "link", "set", "{}-eth0".format(host), "up"])
            subprocess.call(["mx", host, "ip", "addr", "add", self.hosts[host], "dev", "{}-eth0".format(host)])
  

    def test_getPath(self):

        print("test line...............................")
        for sw in self.fullRouting_tbl:
            print("{}'s routing table:".format(sw))
            for i in range(len(self.fullRouting_tbl[sw])):
                print(self.fullRouting_tbl[sw][i])

        print("******************************************")
        print("self.virtualHost:")
        print(self.virtualHost)




    
        

    def main(self):
        self.config_hosts()
        self.test_getPath()
        ic=0
        while True:
            self.route_4()
            self.route_6()
            # self.tunnel()
            self.test_getPath()
            print("compute routing table {}-th".format(ic))
            ic = ic + 1
            time.sleep(20)
            if ic == 30:
                break
        
        


if __name__ == "__main__":
    controller = RoutingController().main()
