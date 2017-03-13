#!/usr/bin/env python

import logging

import sys
import pcapy
import impacket
# import dpkt
import socket
import networkx
import inetfaces
import ipaddress

logger = logging.getLogger(__name__)

# TODO: handle subsystems, proxies

class Dispatcher(object):
    def __init__(self, interface, network, default, elements):
        self.interface = interface
        self.mac = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr']
        self.network = network
        self.default = default
        self.devices, self.routes, self.externals = elements
        self.entry_points = list()
        self.unreach_list = list()
        self.pcapy_object = pcapy.open_live(self.interface, 1500, 1, 0)
        logger.info('Started dispatcher listening on interface %s', self.interface)
        for r in self.routes:
            if r.entry:
                self.entry_points.append(r)
            self.unreach_list.extend(r.unreach_list)
        self.pcapy_object.loop(0, self.callback)

    def icmp_reply(self, src, dst, type, code):
        # TODO: fill additional fields if needed - id, seq
        reply_icmp = impacket.ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(type)
        reply_icmp.set_icmp_code(code)
        reply_icmp.auto_checksum = 1

        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_src(src)
        reply_ip.set_ip_dst(dst)
        reply_ip.contains(reply_icmp)

        # reply_eth = impacket.ImpactPacket.Ethernet()
        # reply_eth.set_ether_type(0x800)
        # reply_eth.contains(reply_ip)
        
        # set_packet(reply_eth)

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.IPPROTO_IP, socket.HDRINCL, 1)
        s.sendto(reply_ip.get_packet(), (dst, 0))

    def callback(self, header, data):
        reply = None
        # unpack Ethernet frame
        eth = self.decoder.decode(data)

        # TODO: check other mac from config addresses as well
        if as_eth_addr(eth.get_ether_shost()) == self.mac:
            continue

        # TODO: log extracted packet information ?

        # ignore non-IP packets, ethertype != 0x800
        if eth.get_ether_type != impacket.ImpactPacket.IP.ethertype:
            logger.info('Not supported non-IP packet type %s', eth.get_ether_tpye().__class__.__name__)
            continue

        ip = eth.child()
        source_ip = ip.get_ip_src()
        destination_ip = ip.get_ip_dst()
        # log any additional information if needed
        logger.info('IP src=%s -> dst=%s proto=%s tos=%s ttl=%s', source_ip, destination_ip, ip.get_ip_p(), ip.get_ip_tos() ip.get_ip_ttl())

        # TODO: log into database

        # TODO: verify checksum to ensure validity of incoming packets
        ip_checksum = ip.get_ip_sum()
        ip_bytes = ip.get_bytes()
        if ip_checksum != ip.compute_checksum(ip_bytes):
            # TODO: need for logging ?
            return
        else:

        # unreachables in network
        for subnet in self.unreach_list:
            if ipaddress.ip_address(source_ip) in ipaddress.ip_network(subnet):
                self.icmp_reply(self.entry_points[0].ip, source_ip, impacket.ImpactPacket.ICMP.ICMP_UNREACH, impacket.ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB)
                return

        # find corresponding device template
        handler = self.default
        for device in self.devices:
            if destination_ip in device.bind_list:
                handler = device
                break
        if handler == self.default:
            for external in self.externals:
                if destination_ip == external.ip:
                    handler = device
                    break

        # find corresponding router
        target_router = None
        for route in self.routes:
            # router in network - path via connect_list
            if ipaddress.ip_address(destination_ip) == ipaddress.ip_address(route.ip):
                target_router = route
                break
        if target_router is None:
            # direct path in network - path via link_list
            for route in self.routes:
                if ipaddress.ip_address(destination_ip) in ipaddress.ip_network(route.link_list):
                    target_router = route
                    break
        if target_router is None:
            # no direct path - path via reachable subnet
            for route in self.routes:
                if ipaddress.ip_address(destination_ip) in ipaddress.ip_network(route.subnet):
                    target_router = route
                    break
        if target_router is None:
            # TODO: packet destination ip not in unreachables, connections or links
            # reply ICMP error or ignore
            self.icmp_reply(self.entry_points[0].ip, source_ip, impacket.ImpactPacket.ICMP.ICMP_UNREACH, impacket.ImpactPacket.ICMP.ICMP_UNREACH_HOST_UNKNOWN)
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
                if len(path) > ip.get_ip_ttl():
                    # TTL < path length
                    self.icmp_reply(target_router.ip, source_ip, impacket.ImpactPacket.ICMP.ICMP_TIMXCEED, impacket.ImpactPacket.ICMP.ICMP_TIMXCEED_INTRANS)
                    return

                reply = handler.handle_packet(eth, path)
                break
            # else-branch: router with no defined entry to it - ignore

        # handle reply - wait according to latency
        if reply is not None:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.setsockopt(socket.IPPROTO_IP, socket.HDRINCL, 1)
            s.sendto(reply.get_packet(), (source_ip, 0))
