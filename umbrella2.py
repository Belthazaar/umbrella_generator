#!/usr/bin/env python3

import logging
import sys
import yaml

import ruamel.yaml
from ruamel.yaml.scalarstring import (DoubleQuotedScalarString as dq)

yaml = ruamel.yaml.YAML()


class Umbrella():

    def __init__(self):
        self.ixpyaml = self.load_yaml()
        self.of_switches = self.load_of_yaml()
        self.logger = self.get_logger('INFO')
        self.faucet_yaml = {}
        self.core_links = {}
        self.addresses_to_ports = {}
        self.group_id = 0

    def open(self):
        """ Opens and starts the program """
        self.generate_faucet()

    def load_yaml(self):
        """ Loads the yaml file that has been generated from IXP-manager """
        try:
            with open("ixpdetails.yaml", 'r') as stream:
                yaml_file = yaml.load(stream.read())
        except (UnicodeDecodeError, ValueError) as err:
            self.logger.error("Error in file: %s", str(err))
            return None
        except FileNotFoundError as err:
            self.logger.error('Could not find requested file: ixpdetails.yaml')
            return None
        return yaml_file

    def load_of_yaml(self):
        """ Loads the yaml file containing the OF switch details """
        try:
            with open("of_switch.yaml", 'r') as stream:
                yaml_file = yaml.load(stream.read())
        except (UnicodeDecodeError, ValueError) as err:
            self.logger.error("Error in file: %s", str(err))
            return None
        except FileNotFoundError as err:
            self.logger.error("Could not find requested file: of_switch.yaml")
            return None
        return yaml_file

    def get_logger(self, loglevel):
        """ Create and return a logger object."""

        logger = logging.getLogger("Umbrella")
        logger_handler = logging.StreamHandler(sys.stdout)
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
        logger_handler.setFormatter(
            logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
        logger.addHandler(logger_handler)
        logger.setLevel(loglevel)

        return logger

    def generate_faucet(self):
        """ Uses yaml input to generate the faucet.yaml file """
        self.process_vlans()
        self.process_dps()
        self.genrate_acls()
        self.save_faucet_conf()

    def process_vlans(self):
        """ Adds vlan tags and information to faucet config """
        self.faucet_yaml.setdefault("vlans", {})

        for vlan_name, vlan in self.ixpyaml["vlans"].items():
            self.logger.info("Found Vlan: %s} with id: %s",
                             vlan['description'], vlan['vid'])
            self.faucet_yaml["vlans"][vlan_name] = {
                "vid": vlan["vid"],
                "description": vlan["description"]
            }

    def process_dps(self):
        """ Goes through switches and datapaths and adds them to faucet config
        """
        self.faucet_yaml.setdefault("dps", {})

        for switch in self.ixpyaml['switches']:
            self.addresses_to_ports.setdefault(switch, {})
            if switch not in self.of_switches:
                self.logger.error(("Switch: %s was not found in the "
                                   "of_switch.yaml file. Please check your "
                                   "config again"), switch)
                continue
            self.logger.info("Configuring: %s", switch)
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
                                "addr_type": "ipv4"}

                    if details["details"]["ipv6_addresses"]:
                        for addr in details["details"]["ipv6_addresses"]:
                            self.addresses_to_ports[switch][addr] = {
                                "port": iface,
                                "addr_type": "ipv6"}

                    for addr in details["details"]["macaddresses"]:
                        self.addresses_to_ports[switch][addr] = {
                            "port": iface,
                            "addr_type": "mac"}
                    vids.append(vlan)

                # Native and tagged vlans are set based on
                if len(vids) == 1:
                    f_iface[iface]["native_vlan"] = vids[0]
                else:
                    f_iface[iface]["tagged_vlans"] = vids

    def genrate_acls(self):
        """ Generates the acl rules needed for the faucet config """
        acl_num = 0
        self.faucet_yaml["acls"] = {}
        for switch in self.addresses_to_ports:
            acl_num += 1
            self.faucet_yaml["acls"][acl_num] = []
            self.group_id -= self.group_id % -1000
            self.add_acl_to_interface(acl_num, switch)
            for addr, details in self.addresses_to_ports[switch].items():
                if details["addr_type"] == 'ipv4':
                    self.own_ipv4_acl(addr, details["port"], acl_num)
                if details["addr_type"] == 'ipv6':
                    self.own_ipv6_acl(addr, details["port"], acl_num)
                if details["addr_type"] == 'mac':
                    self.own_mac_acl(addr, details["port"], acl_num)
            for other_switch in self.addresses_to_ports:
                # To make sure we don't send out traffic to other switches when
                # hosts are directly connected
                if switch == other_switch:
                    continue
                for addr, details in \
                        self.addresses_to_ports[other_switch].items():
                    ports = []
                    other_ports = []
                    for link in self.core_links[switch]:
                        if other_switch in self.core_links[switch][link]:
                            ports.append(link)
                        else:
                            other_ports.append(link)
                    ports.extend(other_ports)
                    if details["addr_type"] == 'ipv4':
                        self.other_ipv4_acl(addr, ports, acl_num)
                    if details["addr_type"] == 'ipv6':
                        self.other_ipv6_acl(addr, ports, acl_num)
                    if details["addr_type"] == 'mac':
                        self.other_mac_acl(addr, ports, acl_num)

    def add_acl_to_interface(self, acl_num, switch):
        """ Associates an ACL number with a switch and it's ports """
        for iface, details in \
                self.faucet_yaml["dps"][switch]["interfaces"].items():
            details["acl_in"] = acl_num

    def own_ipv4_acl(self, addr, port, acl_num):
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

    def own_ipv6_acl(self, addr, port, acl_num):
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

    def own_mac_acl(self, addr, port, acl_num):
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

    def other_ipv4_acl(self, addr, ports, acl_num):
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

    def other_ipv6_acl(self, addr, ports, acl_num):
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

    def other_mac_acl(self, addr, ports, acl_num):
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

    def save_faucet_conf(self):
        """ Saves the faucet dictionary to a yaml file """
        with open('faucet_out.yaml', 'w+') as outfile:
            # disable default flow style for a prettier output
            yaml.dump(self.faucet_yaml, outfile)


if __name__ == "__main__":
    Umbrella().open()
