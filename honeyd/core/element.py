#!/usr/bin/env python

"""
  Contains elements which build up our network topology
"""

class Device(object):
    """
      Defines devices on the network, like machines, routers, switches, etc.
    """
    def __init__(self, name, personality, actions, services, binds):
        # possible values are filtered through XSD validation
        self.name = name
        self.personality = personality
        self.action_dictionary = actions
        self.service_list = services
        self.bind_list = binds

    def handle_packet(self, packet):
        pass

class Route(object):
    """
      Defines connections between the devices on the network
    """
    def __init__(self, ip, subnet, entry, links, unreaches):
        self.ip = ip
        self.subnet = subnet

        self.entry = None
        if entry=='true':
          self.entry = True
        if entry=='false':
          self.entry = False

        self.link_list = links
        self.unreach_list = unreaches

    def handle_packet(self, packet):
        pass

class External(object):
    """
      Defines bindings of external machine interfaces to virtual ips in the network
    """
    def __init__(self, ip, interface):
        self.ip = ip
        # TODO: check for interface in current host machine
        self.interface = interface

    def handle_packet(self, pkt):
        pass
