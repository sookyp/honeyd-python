#!/usr/bin/env python

import logging

import sys
"""
ISSUES WITH SNIFFERS:
    * there are few forum posts about pcap and pycapy missing some packets, which is critical for a honeypot
      this needs to be checked in the future. We will stick with pcap for the time being.
    * pycapy hangs the event loop and makes the honeypot unresponsive
    * pyshark supposedly captures all packets, except it provides the output as text. this can be parsed easily,
      however the issue with proxies and subsystems is not avoidable as these need raw packets. I rewrote the project
      using pyshark, in case I figure out something.
    * scapy also handles all packets except it is very slow in benchmarks, this would cause the honeypot to sacrifice
      potential throughput and would greatly increase performance requirements.
"""
# import pcapy
import pcap
import impacket
import random
import socket
import networkx
import netifaces
import ipaddress

from impacket import ImpactPacket
from impacket import ImpactDecoder

import honeyd
from honeyd.utilities.attack_event import AttackEvent

logger = logging.getLogger(__name__)

# TODO: handle subsystems, proxies

class Dispatcher(object):
    def __init__(self, interface, network, default, elements, hpfeeds):
        self.interface = interface
        self.mac = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr']
        self.network = network
        self.default = default
        self.devices, self.routes, self.externals = elements
        self.hpfeeds = hpfeeds
        self.entry_points = list()
        self.unreach_list = list()
        self.pcap_object = pcap.pcap(self.interface)
        self.decoder = ImpactDecoder.EthDecoder()
        logger.info('Started dispatcher listening on interface %s', self.interface)
        for r in self.routes:
            if r.entry:
                self.entry_points.append(r)
            self.unreach_list.extend(r.unreach_list)
        try:
            for ts, pkt in self.pcap_object:
                self.callback(ts, pkt)
        except KeyboardInterrupt:
            return


    def icmp_reply(self, eth_src, eth_dst, ip_src, ip_dst, type, code):
        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(type)
        reply_icmp.set_icmp_code(code)
        reply_icmp.set_icmp_id(0) # TODO ?
        reply_icmp.set_icmp_seq(0) # TODO ?
        reply_icmp.calculate_checksum()
        reply_icmp.auto_checksum = 1

        # ip packet
        reply_ip = ImpactPacket.IP()
        reply_ip.set_ip_v(4)
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_rf(False)
        reply_ip.set_ip_df(False)
        reply_ip.set_ip_mf(False)
        reply_ip.set_ip_src(ip_src)
        reply_ip.set_ip_dst(ip_dst)
        reply_ip.set_ip_id(0) # TODO ?
        reply_ip.contains(reply_icmp)

        # ethernet frame
        reply_eth = ImpactPacket.Ethernet()
        reply_eth.set_ether_type(0x800)
        reply_icmp.set_ether.shost(eth_src)
        reply_icmp.set_ether.dhost(eth_dst)
        reply_eth.contains(reply_ip)

        # send raw frame
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((self.interface, 0))
        s.send(reply_eth.get_packet())

    def callback(self, ts, pkt):
        reply_packet = None

        # TODO: check other mac from config addresses as well
        # QUESTION: filter out ARP ?
        
        # ethernet layer
        eth = self.decoder.decode(pkt)
        eth_type = eth.get_ether_type()
        eth_src = eth.as_eth_addr(eth.get_ether_shost())
        eth_dst = eth.as_eth_addr(eth.get_ether_dhost())

        if eth_src == self.mac or eth_type == ImpactPacket.ARP.ethertype:
            return
        if eth_type != ImpactPacket.IP.ethertype:
            logger.info('Not supported non-IP packet type %s', hex(eth_type))
            return

        # ip layer
        ip = eth.child()
        ip_src = unicode(ip.get_ip_src())
        ip_dst = unicode(ip.get_ip_dst())
        ip_proto = ip.get_ip_p()
        ip_ttl = ip.get_ip_ttl()

        # tcp/udp/icmp layer
        proto = ip.child()
        port_src = 0
        port_dst = 0
        if ip_proto == ImpactPacket.TCP.protocol:
            proto_src = proto.get_th_sport()
            proto_dst = proto.get_th_dport()
        elif ip_proto == ImpactPacket.UDP.protocol:
            proto_src = proto.get_uh_sport()
            proto_dst = proto.get_uh_dport()
        
        # attack event
        attack_event = AttackEvent()
        attack_event.eth_src = eth_src
        attack_event.eth_dst = eth_dst
        attack_event.eth_type = eth_type
        attack_event.ip_src = ip_src
        attack_event.ip_dst = ip_dst
        attack_event.port_src = port_src
        attack_event.port_dst = port_dst
        attack_event.proto = ip_proto
        attack_event.raw_pkt = pkt
        attack_event = attack_event.event_dict()

        logger.info('SRC=%s:%s (%s) -> DST=%s:%s (%s) TYPE=%s PROTO=%s TTL=%s', ip_src, proto_src, eth_src, ip_dst, proto_dst, eth_dst, eth_type, ip_proto, ip_ttl)
        if self.hpfeeds.enabled:
            self.hpfeeds.publish(attack_event)

        # TODO: log into database

        # TODO: verify checksum to ensure validity of incoming packets
        """
        s = 0
         
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            s = s + w
         
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
         
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        """
        """
        ip_checksum = ip.get_ip_sum()
        ip_bytes = ip.get_bytes()
        number_of_bytes = len(ip_bytes)
        ip_calculated_checksum = 0
        position = 0
        while number_of_bytes > 1:
            ip_calculated_checksum = ip_bytes[position] * 256 + (ip_bytes[position+1] + ip_calculated_checksum)
            position += 2
            number_of_bytes -= 2
        if number_of_bytes == 1:
            ip_calculated_checksum += ip_bytes[position] * 256
        ip_calculated_checksum = (ip_calculated_checksum >> 16) + (ip_calculated_checksum & 0xFFFF)
        ip_calculated_checksum += (ip_calculated_checksum >> 16)
        ip_calculated_checksum = (~ip_calculated_checksum & 0xFFFF)
        print ip_calculated_checksum
        if ip_checksum != ip_calculated_checksum:
            # TODO: need for logging ?
            return
        # else:
        """

        # unreachables in network
        for subnet in self.unreach_list:
            if ipaddress.ip_address(ip_src) in ipaddress.ip_network(subnet):
                self.icmp_reply(eth_dst, eth_src, self.entry_points[0].ip, ip_src, ImpactPacket.ICMP.ICMP_UNREACH, ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB)
                return

        # find corresponding device template
        handler = self.default
        for device in self.devices:
            if ip_dst in device.bind_list:
                handler = device
                break
        if handler == self.default:
            for external in self.externals:
                if ip_dst == external.ip:
                    handler = device
                    break

        # find corresponding router
        target_router = None
        for route in self.routes:
            # router in network - path via connect_list
            if ipaddress.ip_address(ip_dst) == ipaddress.ip_address(route.ip):
                target_router = route
                break
        if target_router is None:
            # direct path in network - path via link_list
            for route in self.routes:
                for link in route.link_list:
                    if ipaddress.ip_address(ip_dst) in ipaddress.ip_network(link):
                        target_router = route
                        break
                if target_router is not None:
                    break
        if target_router is None:
            # no direct path - path via reachable subnet
            for route in self.routes:
                if ipaddress.ip_address(ip_dst) in ipaddress.ip_network(route.subnet):
                    target_router = route
                    break
        if target_router is None:
            # packet destination ip not in unreachables, connections or links
            # QUESTION: reply ICMP error or ignore ?
            self.icmp_reply(eth_dst, eth_src, self.entry_points[0].ip, ip_src, ImpactPacket.ICMP.ICMP_UNREACH, ImpactPacket.ICMP.ICMP_UNREACH_HOST_UNKNOWN)
            return

        for entry in self.entry_points:
            if networkx.has_path(self.network, entry.ip, target_router.ip):
                path = networkx.shortest_path(self.network, entry.ip, target_router.ip)
                subgraph = self.network.subgraph(path)
                # get attributes like latency, loss,
                attributes = {'latency':networkx.get_edge_attributes(subgraph, 'latency'), 'loss':networkx.get_edge_attributes(subgraph, 'loss')}
                # filter out everything where we do not care about the protocols and behavior

                # loss and latency calculation
                drop_threshold = 1.0
                for loss in attributes['loss']:
                    if loss > 100:
                        loss = 100
                    elif loss < 0:
                        loss = 0
                    drop_threshold *= float(1.0 - loss/100.0) # probability of no error in path
                drop = random.uniform(0.0, 1.0) # TODO: test corner cases
                if drop > drop_threshold:
                    return
                
                latency = sum(attributes['latency'])

                # check reachability according to ttl
                if len(path) > ip_ttl:
                    # TTL < path length
                    self.icmp_reply(eth_dst, eth_src, target_router.ip, ip_src, ImpactPacket.ICMP.ICMP_TIMXCEED, ImpactPacket.ICMP.ICMP_TIMXCEED_INTRANS)
                    return

                reply_packet = handler.handle_packet(eth, path, (ip_proto, port_dst))
                break
            # else-branch: router with no defined entry to it - ignore

        print reply_packet
        # TODO: handle reply - wait according to latency
        if reply_packet is not None:
            # self.pcap_object.sendpacket(reply_packet.get_packet())
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((self.interface, 0))
            s.sendto(reply_packet.get_packet(), (ip_src, proto_src))
