#!/usr/bin/env python

import impacket

import honeyd
from honeyd.protocols import TCPHandler, UDPHandler, ICMPHandler

"""
  Contains elements which build up our network topology
"""

class Device(object):
    """
      Defines devices on the network, like machines, routers, switches, etc.
    """
    def __init__(self, name, personality, ethernet, actions, services, binds):
        # possible values are filtered through XSD validation
        self.name = name
        self.personality = personality
        self.ethernet= ethernet
        self.action_dictionary = actions
        self.service_list = services
        self.bind_list = binds
        # TODO: investigate possibility of using one handler for every device -> requires more complex structures and administration
        self.protocol_mapping = (
            ('icmp', 1, ICMPHandler()), # IP_PROTO_ICMP
            ('tcp', 6, TCPHandler()), # IP_PROTO_TCP
            ('udp', 17, UDPHandler()) # IP_PROTO_UDP
        )

    def handle_packet(self, ethernet_packet, path):
        ip_packet = ethernet_packet.child()
        ip_packet_protocol = ip_packet.get_ip_p()
        packet = ip_packet.child()
        port = None
        # TODO: use getattr() to tidy this up
        if ip_packet_protocol == impacket.ImpactPacket.TCP.protocol:
            port = packet.get_th_dport()
        elif ip_packet_protocol == impacket.ImpactPacket.UDP.protocol:
            port = packet.get_uh_dport()

        # TODO: set ethernet address if needed
        for protocol_name, protocol_number, protocol_class in protocol_mapping:
            if ip_packet.get_ip_p() == protocol_number:
                # search for defined services
                for service in self.service_list:
                    if protocol_name == service[0] and port == service[1]:
                        if service[2] in ['filtered', 'blocked']:
                            reply = protocol_class.filtered(ip_packet, path, self.personality)
                        elif service[2] == 'closed':
                            reply = protocol_class.closed(ip_packet, path, self.personality)
                        elif service[2] == 'open':
                            reply = protocol_class.opened(ip_packet, path, self.personality)
                        else:
                            # TODO: execute script
                            pass

                # check default actions
                if self.action_dictionary[protocol_name] in  ['filtered', 'blocked']:
                    reply = protocol_class.filtered(ip_packet, path, self.personality)
                elif self.action_dictionary[protocol_name] == 'closed':
                    reply = protocol_class.closed(ip_packet, path, self.personality)
                elif self.action_dictionary[protocol_name] == 'open':
                    reply = protocol_class.opened(ip_packet, path, self.personality)
                break
        # TODO: encapsulate ethernet frame, set mac address
        return reply
"""        
                    # FILTERED: for TCP and UDP send ICMP error type 3 code 13
                    # -sS -sN -sF -sX -sA SYN -> ignore OR ICMP type 3 code 0, 1, 2, 3, 9, 10, 13
                    # -sT
                    # -sU UDP -> ICMP type code 0, 1, 2, 9, 10, 13
                    # -sO ICMP type 3 code 0, 1, 9, 10, 13
                    
                    # CLOSED: for TCP send RST | for UDP send ICMP type 3 code 3
                    # -sS -sN -sF -sX -sA SYN -> RST
                    # -sT
                    # -sW SYN -> RST with zero window value
                    # -sU UDP -> ICMP type 3 code 3
                    # -sO ICMP type 3 code 2           
                    
                    # OPEN: actively accepting TCP, UDP
                    # -sS -sA SYN -> SYN/ACK
                    # -sN -sF -sX No Reponse
                    # -sT
                    # -sW SYN -> RST with positive window value
                    # -sU UDP -> rUDP
                    # -sO any response                    
"""
class Route(object):
    """
      Defines connections between the devices on the network
    """
    def __init__(self, ip, subnet, entry, latency, loss, connects, links, unreaches):
        self.ip = ip
        self.subnet = subnet

        self.entry = None
        if entry=='true':
          self.entry = True
        if entry=='false':
          self.entry = False

        self.latency = latency
        self.loss = loss

        self.connect_list = connects
        self.link_list = links
        self.unreach_list = unreaches

class External(object):
    """
      Defines bindings of external machine interfaces to virtual ips in the network
    """
    def __init__(self, ip, interface):
        self.ip = ip
        # TODO: check for interface in current host machine
        self.interface = interface

    def handle_packet(self, packet, path):
        # TODO
        pass
