""" Umbrella FAUCET config generator """
#!/usr/bin/env python3

import logging
import sys

import xml.etree.ElementTree as ET

from collections import defaultdict
import ruamel.yaml
from ruamel.yaml.scalarstring import (DoubleQuotedScalarString as dq)

YAML = ruamel.yaml.YAML()


class Umbrella():
    """ Umbrella FAUCET config generator

        This script uses information obtained from the IXP manager as well as
        network topologies generated through the use of mxgraph, and generates
        a FAUCET yaml config for the specified network."""

    def __init__(self):
        self.ixpyaml = self.__load_yaml()
        self.of_switches = self.__load_of_yaml()
        self.logging = Umbrella.__get_logger('INFO')
        self.faucet_yaml = {}
        self.core_links = {}
        self.addresses_to_ports = {}
        self.group_id = 0
        self.xml_file = self.__read_xml()
        self.switches = []
        self.links = []
        self.link_nodes = []
        self.hosts = []
        self.graph = Umbrella.Graph()

    def open(self):
        """ Opens and starts the program """
        self.__organise_xml()
        self.__output_spf_data()
        for edge in self.link_nodes:
            self.graph.add_edge(*edge)

        self.__generate_faucet()


    def __organise_xml(self):
        """ Reads through the XML file and organises it into usable data """
        for child in self.xml_file:
            for elem in child:
                if 'link' in elem.attrib:
                    self.logging.info(
                        "Found link: %s %s", elem.tag, elem.attrib)
                    self.links.append({'link': {
                        'name': elem.attrib['link'],
                        'speed': elem.attrib['speed']}})
                elif 'switch' in elem.attrib:
                    self.logging.info(
                        "Found switch: %s %s", elem.tag, elem.attrib)
                    self.switches.append(elem.attrib['switch'])
                elif 'host' in elem.attrib:
                    self.logging.info(
                        "Found host: %s %s", elem.tag, elem.attrib)
                    self.hosts.append(elem.attrib['host'])
                else:
                    mxid = int(elem.attrib['id'])
                    if mxid in (0, 1):
                        continue
                    self.logging.info(
                        "Found garbage. %s %s \nPlease check input data",
                        elem.tag, elem.attrib)

    def __output_spf_data(self):
        """ Cleans up link data to be used within the dijkstra's algorithm """
        for link in self.links:
            cost = 100000/int(link['link']['speed'])
            nodes = link['link']['name'].split(',')
            self.link_nodes.append([nodes[0], nodes[2], cost])

    def __generate_faucet(self):
        """ Uses yaml input to generate the faucet.yaml file """
        self.__process_vlans()
        self.__process_dps()

        print(f"Printing core links:\n{self.core_links}\n")
        print(f"Printing links:\n{self.links}\n")
        print(f"Printing addresses to ports:\n{self.addresses_to_ports}\n")

        self.__generate_acls()
        self.__save_faucet_conf()

    def __process_vlans(self):
        """ Adds vlan tags and information to faucet config """
        self.faucet_yaml.setdefault("vlans", {})

        for vlan_name, vlan in self.ixpyaml["vlans"].items():
            self.logging.info("Found Vlan: %s} with id: %s",
                              vlan['description'], vlan['vid'])
            self.faucet_yaml["vlans"][vlan_name] = {
                "vid": vlan["vid"],
                "description": vlan["description"]
            }

    def __process_dps(self):
        """ Goes through switches and datapaths and adds them to faucet config
        """
        self.faucet_yaml.setdefault("dps", {})

        for switch in self.ixpyaml['switches']:
            if switch not in self.of_switches:
                self.logging.warning(("Switch: %s was not found in the "
                                      "of_switch.yaml file. Please check your "
                                      "config again or ignore if this is a core"),
                                     switch)
                self.__process_core_sw(switch)
                continue
            self.addresses_to_ports.setdefault(switch, {})
            self.logging.info("Configuring: %s", switch)
            self.faucet_yaml["dps"][switch] = self.of_switches[switch]
            # Need to set hardware value again but with double quotes
            self.faucet_yaml["dps"][switch]["hardware"] = dq(
                self.of_switches[switch]["hardware"])
            # Gets and sets interface used in faucet yaml, easier to access dict
            f_iface = self.faucet_yaml["dps"][switch].setdefault(
                "interfaces", {})
            self.core_links.setdefault(switch, {})

            for iface, port_dict in \
                    self.ixpyaml["switches"][switch]["interfaces"].items():
                f_iface[iface] = {}
                f_iface[iface]["name"] = dq(port_dict['name'])
                vids = []

                if 'core' in port_dict:
                    f_iface[iface]["opstatus_reconf"] = False
                    yang_name = port_dict["name"].split(',')
                    self.core_links[switch].setdefault(
                        iface, {yang_name[2]: yang_name[3]}
                    )

                    if len(self.faucet_yaml["vlans"]) < 2:
                        vlan = next(iter(self.faucet_yaml["vlans"]))
                        vid = self.faucet_yaml["vlans"][vlan]["vid"]
                        f_iface[iface]["native_vlan"] = vid
                        continue

                    for vlan in self.faucet_yaml["vlans"]:
                        vids.append(self.faucet_yaml["vlans"][vlan]["vid"])
                    f_iface[iface]["tagged_vlans"] = vids
                    continue

                # Checks type of address, and stores it to use in ACLS later
                for vlan, details in port_dict['vlans'].items():
                    if details["details"]["ipv4_addresses"]:
                        for addr in details["details"]["ipv4_addresses"]:
                            self.addresses_to_ports[switch][addr] = {
                                "port": iface,
                                "addr_type": "ipv4",
                                "name": port_dict['name']}

                    if details["details"]["ipv6_addresses"]:
                        for addr in details["details"]["ipv6_addresses"]:
                            self.addresses_to_ports[switch][addr] = {
                                "port": iface,
                                "addr_type": "ipv6",
                                "name": port_dict['name']}

                    for addr in details["details"]["macaddresses"]:
                        self.addresses_to_ports[switch][addr] = {
                            "port": iface,
                            "addr_type": "mac",
                            "name": port_dict['name']}
                    vids.append(vlan)

                # Native and tagged vlans are set based on
                if len(vids) == 1:
                    f_iface[iface]["native_vlan"] = vids[0]
                else:
                    f_iface[iface]["tagged_vlans"] = vids

    def __process_core_sw(self, switch):
        """ Adds all the links from core switches """
        self.core_links.setdefault(switch, {})
        for iface, port_dict in \
                    self.ixpyaml["switches"][switch]["interfaces"].items():
            yang_name = port_dict["name"].split(',')
            self.core_links[switch].setdefault(iface, {
                yang_name[2]: yang_name[3]})

    def __generate_acls(self):
        """ Generates the acl rules needed for the faucet config """
        acl_num = 0
        self.faucet_yaml["acls"] = {}
        for switch in self.addresses_to_ports:
            acl_num += 1
            self.faucet_yaml["acls"][acl_num] = []
            self.group_id -= self.group_id % -1000
            self.__add_acl_to_interface(acl_num, switch)
            for addr, details in self.addresses_to_ports[switch].items():
                if details["addr_type"] == 'ipv4':
                    self.__own_ipv4_acl(addr, details["port"], acl_num)
                if details["addr_type"] == 'ipv6':
                    self.__own_ipv6_acl(addr, details["port"], acl_num)
                if details["addr_type"] == 'mac':
                    self.__own_mac_acl(addr, details["port"], acl_num)
                    self.__port_to_mac_acl(addr, details["port"], acl_num)
            for other_switch in self.addresses_to_ports:
                # To make sure we don't send out traffic to other switches when
                # hosts are directly connected
                if switch == other_switch:
                    continue
                # route = self.dijkstra(self.graph, switch, other_switch)
                for addr, details in \
                        self.addresses_to_ports[other_switch].items():
                    route = Umbrella.dijkstra(self.graph,
                                              switch, details['name'])

                    if len(route) <= 3:
                        ports = []
                        other_ports = []
                        for link in self.core_links[switch]:
                            if other_switch in self.core_links[switch][link]:
                                ports.append(link)
                            else:
                                other_ports.append(link)
                        ports.extend(other_ports)
                        if details["addr_type"] == 'ipv4':
                            self.__other_ipv4_acl(addr, ports, acl_num)
                        if details["addr_type"] == 'ipv6':
                            self.__other_ipv6_acl(addr, ports, acl_num)
                        if details["addr_type"] == 'mac':
                            self.__other_mac_acl(addr, ports, acl_num)
                    else:
                        self.__umbrella_acl(addr, details["addr_type"],
                                        acl_num, route, switch)

    def __umbrella_acl(self, addr, addr_type, acl_num, route, switch):
        """ Generates the umbrella rules for rewriting macs  """
        out_port = 0
        ports = []
        print(f"Printing route: {route}")
        for hop in route:
            # To avoid sending stuff back to main switch
            if hop == switch:
                prev_hop = hop
                continue
            if hop == route[-1]:
                last_port = self.addresses_to_ports[prev_hop][addr]['port']
                ports.append(last_port)
                continue
            for port, details in self.core_links[prev_hop].items():
                if hop in details:
                    if prev_hop == switch:
                        out_port = port
                    else:
                        ports.append(port)
            prev_hop = hop

        print(f"Ports to reach target host:\nOutport:{out_port}  Rest:{ports}\n")
        ports.extend([0] * (6 - len(ports)))
        mac = ""
        count = 1
        for port in ports:
            # Changes port to the byte value for rewriting macs
            port_str = str(hex(port)).split('0x')[1]
            if len(port_str) == 1:
                port_str = "0" + port_str
            mac += port_str
            if count < len(ports):
                mac += ":"
                count += 1
        if addr_type == 'ipv4':
            self.__umbrella_ipv4_acl(addr, out_port, acl_num, mac)
        if addr_type == 'ipv6':
            self.__umbrella_ipv6_acl(addr, out_port, acl_num, mac)
        if addr_type == 'mac':
            self.__umbrella_mac_acl(addr, out_port, acl_num, mac)

    def __add_acl_to_interface(self, acl_num, switch):
        """ Associates an ACL number with a switch and it's ports """
        for iface, details in \
                self.faucet_yaml["dps"][switch]["interfaces"].items():
            details["acl_in"] = acl_num

    def __own_ipv4_acl(self, addr, port, acl_num):
        """ Generates ACL rule for ipv4 addresses directly connected to the
            switch """
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_type": "0x806",
                "dl_dst": dq("ff:ff:ff:ff:ff:ff"),
                "arp_tpa": dq(addr),
                "actions": {
                    "output": {
                        "port": port
                    }
                }
            }
        })

    def __own_ipv6_acl(self, addr, port, acl_num):
        """ Generates ACL rule for ipv6 addresses directly connected to the
            switch """
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_type": "0x86DD",
                "ip_proto": 58,
                "icmpv6": 135,
                "ipv6_nd_target": dq(addr),
                "actions": {
                    "output": {
                        "port": port
                    }
                }
            }
        })

    def __own_mac_acl(self, addr, port, acl_num):
        """ Generate ACL rule for mac addresses directly connected to the
            switch """
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_dst": dq(addr),
                "actions": {
                    "output": {
                        "port": port
                    }
                }
            }
        })

    def __other_ipv4_acl(self, addr, ports, acl_num):
        """ Generates ACL rule for ipv4 addresses not directly connected to the
            switch """
        self.group_id += 1
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_type": "0x806",
                "dl_dst": dq("ff:ff:ff:ff:ff:ff"),
                "arp_tpa": dq(addr),
                "actions": {
                    "output": {
                        "failover": {
                            "group_id": self.group_id,
                            "ports": ports
                        }
                    }
                }
            }
        })

    def __other_ipv6_acl(self, addr, ports, acl_num):
        """ Generates ACL rule for ipv6 addresses not directly connected to the
            switch """
        self.group_id += 1
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_type": "0x86DD",
                "ip_proto": 58,
                "icmpv6": 135,
                "ipv6_nd_target": dq(addr),
                "actions": {
                    "output": {
                        "failover": {
                            "group_id": self.group_id,
                            "ports": ports
                        }
                    }
                }
            }
        })

    def __other_mac_acl(self, addr, ports, acl_num):
        """ Generate ACL rule for mac addresses not directly connected to the
            switch """
        self.group_id += 1
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_dst": dq(addr),
                "actions": {
                    "output": {
                        "failover": {
                            "group_id": self.group_id,
                            "ports": ports
                        }
                    }
                }
            }
        })

    def __umbrella_ipv4_acl(self, addr, out_port, acl_num, mac):
        """ Generates an Umbrella ACL rule for ipv4 addresses more than two hops
            away from the edge router """
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_type": "0x806",
                "dl_dst": dq("ff:ff:ff:ff:ff:ff"),
                "arp_tpa": dq(addr),
                "actions": {
                    "output": {
                        "set_fields": [{"eth_dst": dq(mac)}],
                        "port": out_port
                    }
                }
            }
        })

    def __umbrella_ipv6_acl(self, addr, out_port, acl_num, mac):
        """ Generates ACL rule for ipv6 addresses directly connected to the
            switch """
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_type": "0x86DD",
                "ip_proto": 58,
                "icmpv6": 135,
                "ipv6_nd_target": dq(addr),
                "actions": {
                    "output": {
                        "set_fields": [{"eth_dst": dq(mac)}],
                        "port": out_port
                    }
                }
            }
        })

    def __umbrella_mac_acl(self, addr, out_port, acl_num, mac):
        """ Generate ACL rule for mac addresses directly connected to the
            switch """
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_dst": dq(addr),
                "actions": {
                    "output": {
                        "set_fields": [{"eth_dst": dq(mac)}],
                        "port": out_port
                    },
                }
            }
        })

    def __port_to_mac_acl(self, addr, port, acl_num):
        """ Clean up after umbrella to rewrite mac to correct destination """
        port_str = str(hex(port)).split('0x')[1]
        if len(port_str) == 1:
            port_str = "0" + port_str
        self.faucet_yaml["acls"][acl_num].append({
            "rule": {
                "dl_dst": dq(f"{port_str}:00:00:00:00:00"),
                "actions": {
                    "output": {
                        "set_fields": [{"eth_dst": dq(addr)}],
                        "port": port
                    }
                }
            }
        })

    def __save_faucet_conf(self):
        """ Saves the faucet dictionary to a yaml file """
        with open('faucet_out.yaml', 'w+') as outfile:
            # disable default flow style for a prettier output
            YAML.dump(self.faucet_yaml, outfile)

    @classmethod
    def dijkstra(cls, graph, initial, end):
        """ Dijkstra's algorithm used to determine shortest path """
        # shortest paths is a dict of nodes
        # whose value is a tuple of (previous node, weight)
        shortest_paths = {initial: (None, 0)}
        current_node = initial
        visited = set()

        while current_node != end:
            visited.add(current_node)
            destinations = graph.edges[current_node]
            weight_to_current_node = shortest_paths[current_node][1]

            for next_node in destinations:
                weight = graph.weights[(
                    current_node, next_node)] + weight_to_current_node
                if next_node not in shortest_paths:
                    shortest_paths[next_node] = (current_node, weight)
                else:
                    current_shortest_weight = shortest_paths[next_node][1]
                    if current_shortest_weight > weight:
                        shortest_paths[next_node] = (current_node, weight)

            next_destinations = {
                node: shortest_paths[node] for node in shortest_paths
                if node not in visited}
            if not next_destinations:
                return "Route Not Possible"
            # next node is the destination with the lowest weight
            current_node = min(next_destinations,
                               key=lambda k: next_destinations[k][1])

        # Work back through destinations in shortest path
        path = []
        while current_node is not None:
            path.append(current_node)
            next_node = shortest_paths[current_node][0]
            current_node = next_node
        # Reverse path
        path = path[::-1]
        return path

    class Graph():
        """ Graphs all possible next nodes from a node """
        def __init__(self):
            """
            self.edges is a dict of all possible next nodes
            e.g. {'X': ['A', 'B', 'C', 'E'], ...}
            self.weights has all the weights between two nodes,
            with the two nodes as a tuple as the key
            e.g. {('X', 'A'): 7, ('X', 'B'): 2, ...}
            """
            self.edges = defaultdict(list)
            self.weights = {}

        def add_edge(self, from_node, to_node, weight):
            """ Adds a new edge to existing node """
            # Note: assumes edges are bi-directional
            self.edges[from_node].append(to_node)
            self.edges[to_node].append(from_node)
            self.weights[(from_node, to_node)] = weight
            self.weights[(to_node, from_node)] = weight

    # Reading files

    def __load_yaml(self):
        """ Loads the yaml file that has been generated from IXP-manager """
        try:
            with open("ixpdetails.yaml", 'r') as stream:
                yaml_file = YAML.load(stream.read())
        except (UnicodeDecodeError, ValueError) as err:
            self.logging.error("Error in file: %s", str(err))
            return None
        except FileNotFoundError as err:
            self.logging.error(
                'Could not find requested file: ixpdetails.yaml')
            return None
        return yaml_file

    def __read_xml(self):
        """ Reads in the XML file that mxgraph produced """
        in_file = "core.xml"
        topo_file = ET.parse(in_file).getroot()
        if not topo_file:
            self.logging.error("Could not find %s please check input data",
                               in_file)
        return(topo_file)

    def __load_of_yaml(self):
        """ Loads the yaml file containing the OF switch details """
        try:
            with open("of_switch.yaml", 'r') as stream:
                yaml_file = YAML.load(stream.read())
        except (UnicodeDecodeError, ValueError) as err:
            self.logging.error("Error in file: %s", str(err))
            return None
        except FileNotFoundError as err:
            self.logging.error("Could not find requested file: of_switch.yaml")
            return None
        return yaml_file

    @classmethod
    def __get_logger(cls, loglevel):
        """ Create and return a logger object."""

        logger = logging.getLogger("Umbrella")
        logger_handler = logging.StreamHandler(sys.stdout)
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
        logger_handler.setFormatter(
            logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
        logger.addHandler(logger_handler)
        logger.setLevel(loglevel)

        return logger


if __name__ == "__main__":
    Umbrella().open()
