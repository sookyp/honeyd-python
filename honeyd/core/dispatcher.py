#!/usr/bin/env python

import logging
import pcapy
import impacket
import random
import networkx
import netifaces
import ipaddress
import struct
import array

from collections import deque
from impacket import ImpactPacket, ImpactDecoder

import honeyd
from honeyd.loggers.attack_event import AttackEvent

logger = logging.getLogger(__name__)


class Dispatcher(object):

    def __init__(self, interface, network, default, elements, loggers, tunnels):
        self.interface = interface
        self.mac = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr']
        self.network = network
        self.default = default
        self.devices, self.routes, self.externals = elements
        self.hpfeeds, self.dblogger = loggers
        self.tunnels = tunnels
        self.packet_queue = deque()
        self.entry_points = list()
        self.unreach_list = list()
        self.pcapy_object = pcapy.open_live(self.interface, 65535, 1, 1000)
        self.decoder = ImpactDecoder.EthDecoder()
        self.mac_set = set([self.mac])
        for d in self.devices:
            if len(d.mac):
                self.mac_set.add(d.mac)
        for r in self.routes:
            if r.entry:
                self.entry_points.append(r)
            self.unreach_list.extend(r.unreach_list)
        logger.info('Started dispatcher listening on interface %s', self.interface)
        while True:
            try:
                (hdr, pkt) = self.pcapy_object.next()
                self.callback(hdr, pkt)
            except KeyboardInterrupt:
                return
        """
        self.pcapy_object.loop(-1, self.callback)
        try:
            for ts, pkt in self.pcap_object:
                self.callback(ts, pkt)
        except KeyboardInterrupt:
            return
        """

    def icmp_reply(self, eth_src, eth_dst, ip_src, ip_dst, type, code):
        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(type)
        reply_icmp.set_icmp_code(code)
        reply_icmp.set_icmp_id(0)
        reply_icmp.set_icmp_seq(0)
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
        reply_ip.set_ip_id(0) 
        reply_ip.contains(reply_icmp)

        # ethernet frame
        reply_eth = ImpactPacket.Ethernet()
        reply_eth.set_ether_type(0x800)
        eth_src = [int(i, 16) for i in eth_src.split(':')]
        eth_dst = [int(i, 16) for i in eth_dst.split(':')]
        reply_eth.set_ether_shost(eth_src)
        reply_eth.set_ether_dhost(eth_dst)
        reply_eth.contains(reply_ip)

        logger.debug('Sending reply: %s', reply_eth)
        # send raw frame
        self.pcapy_object.sendpacket(reply_eth.get_packet())

    def arp_reply(self, arp_pkt):
        # arp packet
        reply_arp = ImpactPacket.ARP()
        reply_arp.set_ar_hln(6)  # Ethernet size 6
        reply_arp.set_ar_pln(4)  # IPv4 size 4
        reply_arp.set_ar_hrd(1)  # 1:'ARPHRD ETHER', 6:'ARPHRD IEEE802', 15:'ARPHRD FRELAY'
        reply_arp.set_ar_op(2)  # 1:'REQUEST', 2:'REPLY', 3:'REVREQUEST', 4:'REVREPLY', 8:'INVREQUEST', 9:'INVREPLY'
        reply_arp.set_ar_pro(0x800)  # IPv4 0x800
        mac = [int(i, 16) for i in self.mac.split(':')]
        reply_arp.set_ar_sha(mac)
        reply_arp.set_ar_tha(arp_pkt.get_ar_sha())
        reply_arp.set_ar_spa(arp_pkt.get_ar_tpa())
        reply_arp.set_ar_tpa(arp_pkt.get_ar_spa())

        # ethernet frame
        reply_eth = ImpactPacket.Ethernet()
        reply_eth.set_ether_type(0x800)
        reply_eth.set_ether_shost(mac)
        reply_eth.set_ether_dhost(arp_pkt.get_ar_sha())
        reply_eth.contains(reply_arp)

        logger.debug('Sending reply: %s', reply_eth)
        # send raw frame
        self.pcapy_object.sendpacket(reply_eth.get_packet())

    def get_tunnel_reply(self):
        try:
            ip_pkt = self.packet_queue.pop()
        except IndexError:
            # queue empty -> no replies from remote server
            return None
        proto = ip_pkt.get_ip_p()
        if proto == 4:
            # ipip
            reply_ip = ip_pkt.child()
        elif proto == 47:
            # gre
            # we expect standard GRE packets, version 0
            gre_pkt = ip_pkt.child()
            gre_bytes = gre_pkt.get_bytes()
            padding = 4
            if gre_bytes[0] & 128:
                padding += 4
            if gre_bytes[0] & 32:
                padding += 4
            if gre_bytes[0] & 16:
                padding += 4
            inner_ip = gre_bytes[padding:]
            decoder = ImpactDecoder.IPDecoder()
            reply_ip = decoder.decode(inner_ip)

        return reply_ip

    def callback(self, ts, pkt):
        reply_packet = None

        # ethernet layer
        try:
            eth = self.decoder.decode(pkt)
        except BaseException:
            logger.exception('Exception: Cannot decode packet')
            return None
        eth_type = eth.get_ether_type()
        eth_src = eth.as_eth_addr(eth.get_ether_shost())
        eth_dst = eth.as_eth_addr(eth.get_ether_dhost())

        if eth_src in self.mac_set:
            return
        if eth_type == 0x00:
            # Dot11
            return
        elif eth_type == ImpactPacket.ARP.ethertype:
            arp = eth.child()
            self.arp_reply(arp)
            return
        elif eth_type != ImpactPacket.IP.ethertype:
            logger.info('Not supported non-IP packet type %s', hex(eth_type))
            return

        # ip layer
        ip = eth.child()
        ip_src = unicode(ip.get_ip_src())
        ip_dst = unicode(ip.get_ip_dst())
        ip_proto = ip.get_ip_p()
        ip_ttl = ip.get_ip_ttl()

        # get tunnel packets
        ip_tunnels = [str(t[1]) for t in self.tunnels]
        if ip_src in ip_tunnels:
            if ip_proto in [4, 47]:
                self.packet_queue.append(ip)
                return
            else:
                # we assume that the remote server is a honeypot, therefore no packet should come
                # from there except GRE or IPIP traffic, currently we do not log this as attack
                logger.info(
                    'Unexpected traffic from remote host: SRC=%s -> DST=%s PROTO=%s TTL=%s',
                    ip_src,
                    ip_dst,
                    ip_proto,
                    ip_ttl)
                return

        # tcp/udp/icmp layer
        proto = ip.child()
        proto_src = 0
        proto_dst = 0
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
        attack_event.port_src = proto_src
        attack_event.port_dst = proto_dst
        attack_event.proto = ip_proto
        attack_event.raw_pkt = pkt
        attack_event = attack_event.event_dict()

        logger.info('SRC=%s:%s (%s) -> DST=%s:%s (%s) TYPE=%s PROTO=%s TTL=%s', ip_src,
                    proto_src, eth_src, ip_dst, proto_dst, eth_dst, eth_type, ip_proto, ip_ttl)
        if self.hpfeeds.enabled:
            self.hpfeeds.publish(attack_event)
        if self.dblogger.enabled:
            self.dblogger.insert(attack_event)

        # save original checksum
        checksum = ip.get_ip_sum()
        # recalculate checksum
        ip.auto_checksum = 1
        p = ip.get_packet()
        d = ImpactDecoder.IPDecoder()
        i = d.decode(p)
        valid_checksum = i.get_ip_sum()
        if checksum != valid_checksum:
            logger.info('Invalid checksum in IP header, dropping packet.')
            return

        # unreachables in network
        for subnet in self.unreach_list:
            if ipaddress.ip_address(ip_src) in ipaddress.ip_network(subnet):
                self.icmp_reply(
                    eth_dst,
                    eth_src,
                    self.entry_points[0].ip,
                    ip_src,
                    ImpactPacket.ICMP.ICMP_UNREACH,
                    ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB)
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
            self.icmp_reply(
                eth_dst,
                eth_src,
                self.entry_points[0].ip,
                ip_src,
                ImpactPacket.ICMP.ICMP_UNREACH,
                ImpactPacket.ICMP.ICMP_UNREACH_HOST_UNKNOWN)
            return

        for entry in self.entry_points:
            if networkx.has_path(self.network, entry.ip, target_router.ip):
                path = networkx.shortest_path(self.network, entry.ip, target_router.ip)
                subgraph = self.network.subgraph(path)
                # get attributes like latency, loss,
                attributes = {
                    'latency': networkx.get_edge_attributes(subgraph, 'latency'),
                    'loss': networkx.get_edge_attributes(subgraph, 'loss')}
                # filter out everything where we do not care about the protocols and behavior

                # loss and latency calculation
                drop_threshold = 1.0
                for loss in attributes['loss']:
                    if loss > 100:
                        loss = 100
                    elif loss < 0:
                        loss = 0
                    drop_threshold *= float(1.0 - loss / 100.0)  # probability of no error in path
                drop = random.uniform(0.0, 1.0)  # TODO: test corner cases
                if drop > drop_threshold:
                    return

                latency = sum(attributes['latency'])

                # check reachability according to ttl
                if len(path) > ip_ttl:
                    # TTL < path length
                    self.icmp_reply(
                        eth_dst,
                        eth_src,
                        target_router.ip,
                        ip_src,
                        ImpactPacket.ICMP.ICMP_TIMXCEED,
                        ImpactPacket.ICMP.ICMP_TIMXCEED_INTRANS)
                    return

                reply_packet = handler.handle_packet(
                    eth, path, (ip_proto, proto_dst), self.tunnels, cb_tunnel=self.get_tunnel_reply)
                break
            # else-branch: router with no defined entry to it - ignore

        # print '-------------------------------------------------------'
        # print reply_packet
        # print '-------------------------------------------------------'

        # TODO: handle reply - wait according to latency
        if reply_packet is not None:
            logger.debug('Sending reply: %s', reply_packet)
            self.pcapy_object.sendpacket(reply_packet.get_packet())
