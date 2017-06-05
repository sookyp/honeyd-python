#!/usr/bin/env python
"""Dispatcher.py is responsible for sniffing the intercepted network traffic and simulating the network routing."""
import logging
import random
import netifaces
import ipaddress
import pcapy

import networkx
from networkx.readwrite import json_graph

from requests import post
from json import dumps
from collections import deque
from impacket import ImpactPacket, ImpactDecoder

from honeyd.loggers.attack_event import AttackEvent

logger = logging.getLogger(__name__)


class Dispatcher(object):
    """Class dispatcher handles the sniffing, element lookup in the network, routing, etc."""
    def __init__(self, interface, network, default, elements, loggers, tunnels):
        """Function initialized the dipatcher
        Args:
            interface : name of the network interface to listen
            network : networkx graph representation of the network
            default : default template
            elements : elements of the network
            loggers : instances of the logger modules
            tunnels : tunnel configuration
        """
        self.interface = interface
        self.mac = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr']
        self.network = network
        try:
            post('http://localhost:8080/network', json=dumps(json_graph.node_link_data(self.network)))
        except:
            logger.exception('Exception: Cannot connect to local server.')
        self.default = default
        self.devices, self.routes, self.externals = elements
        self.hpfeeds, self.dblogger = loggers
        self.tunnels = tunnels
        self.packet_queue = dict()
        self.entry_points = list()
        self.unreach_list = list()
        self.pcapy_object = pcapy.open_live(self.interface, 65535, 1, 10)
        self.decoder = ImpactDecoder.EthDecoder()
        self.ip_decoder = ImpactDecoder.IPDecoder()
        self.ip_icmp_decoder = ImpactDecoder.IPDecoderForICMP()
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

    def _log_event(self, eth):
        """Function extracts data from intercepted packets and logs the information
        Args:
            eth : received packet
        Return:
            attack_event : dictionary containing extracted information
        """
        # ethernet
        """
        eth_src, eth_dst, eth_type
        """
        eth_type = eth.get_ether_type()
        eth_src = eth.as_eth_addr(eth.get_ether_shost())
        eth_dst = eth.as_eth_addr(eth.get_ether_dhost())

        # ip/ip6/arp/dot1x/llc/data
        """
        pkt_src, pkt_dst, pkt_proto, ip_ttl, proto_src, proto_dst, info
        """
        pkt = eth.child()
        info = None
        proto_src, proto_dst, pkt_proto, ip_ttl = (0,) * 4
        if eth_type == 0x00:
            return None
        elif eth_type == 0x800:  # IPv4
            # IP
            pkt_src = unicode(pkt.get_ip_src())
            pkt_dst = unicode(pkt.get_ip_dst())
            pkt_proto = pkt.get_ip_p()
            ip_ttl = pkt.get_ip_ttl()
            info = "Length:" + str(pkt.get_ip_len())

            # TCP/UDP/ICMP/IGMP
            proto = pkt.child()

            if pkt_proto == ImpactPacket.TCP.protocol:
                proto_src = proto.get_th_sport()
                proto_dst = proto.get_th_dport()
                flags = "(" + str(proto.get_th_flags()) + ") "
                if proto.get_CWR():
                    flags += "C"
                if proto.get_ECE():
                    flags += "E"
                if proto.get_URG():
                    flags += "U"
                if proto.get_ECE():
                    flags += "E"
                if proto.get_ACK():
                    flags += "A"
                if proto.get_PSH():
                    flags += "P"
                if proto.get_RST():
                    flags += "R"
                if proto.get_SYN():
                    flags += "S"
                if proto.get_FIN():
                    flags += "F"
                info += " Flags:" + flags

            elif pkt_proto == ImpactPacket.UDP.protocol:
                proto_src = proto.get_uh_sport()
                proto_dst = proto.get_uh_dport()

            elif pkt_proto == ImpactPacket.ICMP.protocol:
                info += \
                    " Type:" + str(proto.get_icmp_type()) + \
                    " Code:" + str(proto.get_icmp_code())

            elif pkt_proto == ImpactPacket.IGMP.protocol:
                # there is an issue with impacket properly decoding igmp packets
                # info += \
                #     " Type:" + str(proto.get_igmp_type()) + \
                #     " Code:" + str(proto.get_igmp_code()) + \
                #     " GroupAddress:" + str(proto.get_igmp_group())
                pass

        elif eth_type == 0x86dd:  # IPv6
            # deprecated soon
            pkt_src = unicode(pkt.get_source_address())
            pkt_dst = unicode(pkt.get_destination_address())
            pkt_proto = pkt.get_next_header()
            ip_ttl = pkt.get_hop_limit()
            info = "Length:" + str(pkt.get_payload_length())

            # TCP/UDP/ICMP/IGMP
            proto = pkt.child()

            if pkt_proto == ImpactPacket.TCP.protocol:
                proto_src = proto.get_th_sport()
                proto_dst = proto.get_th_dport()
                info += " Flags:" + str(proto.get_th_flags())

            elif pkt_proto == ImpactPacket.UDP.protocol:
                proto_src = proto.get_uh_sport()
                proto_dst = proto.get_uh_dport()

            elif pkt_proto == ImpactPacket.ICMP.protocol:
                info += \
                    " Type:" + str(proto.get_icmp_type()) + \
                    " Code:" + str(proto.get_icmp_code())

            elif pkt_proto == ImpactPacket.IGMP.protocol:
                info += \
                    " Type:" + str(proto.get_igmp_type()) + \
                    " Code:" + str(proto.get_igmp_code())

        elif eth_type == 0x806:  # ARP
            pkt_src = unicode(pkt.as_pro(pkt.get_ar_spa()))
            pkt_dst = unicode(pkt.as_pro(pkt.get_ar_tpa()))
            info = "Operation:" + pkt.get_op_name(pkt.get_ar_op())
        # elif eth_type == 0x888e: # EAPOL - we cannot extract too much valuable data
        # else-branch non-supported decoder in ImpactDecoder
        else:
            logger.info('Not supported packet type: %s', hex(eth_type))
            pkt_src = unicode('0')
            pkt_dst = unicode('0')

        # attack event
        attack_event = AttackEvent()
        attack_event.eth_src = eth_src
        attack_event.eth_dst = eth_dst
        attack_event.eth_type = eth_type
        attack_event.ip_src = pkt_src
        attack_event.ip_dst = pkt_dst
        attack_event.port_src = proto_src
        attack_event.port_dst = proto_dst
        attack_event.proto = pkt_proto
        attack_event.info = info
        attack_event.raw_pkt = repr(pkt)
        event = attack_event.event_dict()

        logger.info('SRC=%s:%s (%s) -> DST=%s:%s (%s) TYPE=%s PROTO=%s TTL=%s {%s}', pkt_src,
                    proto_src, eth_src, pkt_dst, proto_dst, eth_dst, hex(eth_type), pkt_proto, ip_ttl, info)
        if self.hpfeeds.enabled:
            self.hpfeeds.publish(event)
        if self.dblogger.enabled:
            self.dblogger.insert(event)
        try:
            post('http://localhost:8080/post', json=dumps(event))
        except:
            logger.exception('Exception: Cannot connect to local server.')
        return event

    def icmp_reply(self, eth_src, eth_dst, ip_src, ip_dst, i_type, i_code, ip_pkt):
        # TODO: we have access to the personality here
        """Function creates and sends back an ICMP reply
        Args:
            eth_src : ethernet source address
            eth_dst : ethernet destination address
            ip_src : ip source address
            ip_dst : ip destination address
            i_type : type of the icmp reply
            i_code : code of the icmp reply
        """
        # truncate inner packet
        l = ip_pkt.get_ip_len()
        hdr = None
        if l > 1472: # (MTU) 1500 - (IPv4) 20 - (ICMP) 8 = 1472
            hdr = ip_pkt.get_packet()[:1472]
        else:
            hdr = ip_pkt.get_packet()

        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(i_type)
        reply_icmp.set_icmp_code(i_code)
        reply_icmp.set_icmp_id(0)
        reply_icmp.set_icmp_seq(0)
        reply_icmp.set_icmp_void(0)
        reply_icmp.contains(ImpactPacket.Data(hdr))
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
        reply_ip.set_ip_id(random.randint(0, 50000)) # TODO: provide IP IDs according to personality, altough tracepath does not care
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
        try:
            self.pcapy_object.sendpacket(reply_eth.get_packet())
        except pcapy.PcapError as ex:
            logger.exception('Exception: Cannot send reply packet: %s', ex)

    def arp_reply(self, arp_pkt):
        """Function creates and sends back an ARP reply
        Args:
            arp_pkt : received arp packet
        """
        # arp packet
        reply_arp = ImpactPacket.ARP()
        reply_arp.set_ar_hln(6)  # Ethernet size 6
        reply_arp.set_ar_pln(4)  # IPv4 size 4
        reply_arp.set_ar_hrd(1)  # 1:'ARPHRD ETHER', 6:'ARPHRD IEEE802', 15:'ARPHRD FRELAY'
        reply_arp.set_ar_op(2)  # 1:'REQUEST', 2:'REPLY', 3:'REVREQUEST', 4:'REVREPLY', 8:'INVREQUEST', 9:'INVREPLY'
        reply_arp.set_ar_pro(0x800)  # IPv4 0x800
        mac = [int(i, 16) for i in self.mac.split(':')]
        target_ip = unicode('.'.join(map(str, arp_pkt.get_ar_tpa())))
        for d in self.devices:
            if target_ip in d.bind_list:
                mac = [int(i, 16) for i in d.mac.split(':')]
                break
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
        try:
            self.pcapy_object.sendpacket(reply_eth.get_packet())
        except pcapy.PcapError as ex:
            logger.exception('Exception: Cannot send reply packet: %s', ex)

    def get_tunnel_reply(self, src_ip):
        """Function obtains the first response from a packet queue containing replies from remote hosts
        Args:
            src_ip : ip address of tunnel interface
        Return:
            ip packet extracted from its carrier envelope
        """
        if src_ip not in self.packet_queue.keys():
            # remote host does not exist in dictionary -> no replies from remote server
            return None
        queue = self.packet_queue[src_ip]
        try:
            tun_pkt = queue.pop()
        except IndexError:
            # queue empty
            del self.packet_queue[src_ip]
            return None
        proto = tun_pkt.get_ip_p()
        if proto == 4:
            # ipip
            ip_pkt = tun_pkt.child()
            inner_ip = ip_pkt.get_bytes()
            try:
                reply_ip = self.ip_decoder.decode(inner_ip)
            except BaseException:
                try:
                    reply_ip = self.ip_icmp_decoder.decode(inner_ip)
                except BaseException:
                    logger.exception('Exception: Cannot decode packet from ipip tunnel interface.')
                    return None
        elif proto == 47:
            # gre
            # we expect standard GRE packets, version 0
            gre_pkt = tun_pkt.child()
            gre_bytes = gre_pkt.get_bytes()
            padding = 4
            if gre_bytes[0] & 128:
                padding += 4
            if gre_bytes[0] & 32:
                padding += 4
            if gre_bytes[0] & 16:
                padding += 4
            inner_ip = gre_bytes[padding:]

            try:
                reply_ip = self.ip_decoder.decode(inner_ip)
            except BaseException:
                try:
                    reply_ip = self.ip_icmp_decoder.decode(inner_ip)
                except BaseException:
                    logger.exception('Exception: Cannot decode packet from gre tunnel interface')
                    return None

        return reply_ip

    def callback(self, ts, pkt):
        """Function invoked for each intercepted packet, responsible for filtering, routing, transmitting replies
        Args:
            ts : timestamp for intercepted packet
            pkt : received packet
        """
        if not len(pkt):
            return

        reply_packet = None
        # ethernet layer
        try:
            eth = self.decoder.decode(pkt)
        except BaseException:
            logger.exception('Exception: Cannot decode incoming packet')
            return None
        # filter own packets
        eth_src = eth.as_eth_addr(eth.get_ether_shost())
        if eth_src in self.mac_set:
            return

        # log attack event
        event = self._log_event(eth)
        if event is None:
            return

        if event['ethernet_type'] == ImpactPacket.ARP.ethertype:
            arp = eth.child()
            self.arp_reply(arp)
            return
        elif event['ethernet_type'] != ImpactPacket.IP.ethertype:
            logger.info('Dropping packet: Not supported non-IP packet type %s', hex(event['ethernet_type']))
            return

        # ip layer
        ip = eth.child()
        ip_ttl = ip.get_ip_ttl()

        # get tunnel packets
        ip_tunnels = [str(t[1]) for t in self.tunnels]
        if event['ip_src'] in ip_tunnels:
            if event['protocol'] in [4, 47]:
                addr = ipaddress.ip_address(event['ip_src'])
                if addr not in self.packet_queue.keys():
                    self.packet_queue[addr] = deque()
                self.packet_queue[addr].append(ip)
                return
            else:
                # we assume that the remote server is a honeypot, therefore no packet should come
                # from there except GRE or IPIP traffic, currently we do not log this as attack
                logger.info(
                    'Unexpected traffic from remote host: SRC=%s -> DST=%s PROTO=%s TTL=%s',
                    event['ip_src'],
                    event['ip_dst'],
                    event['protocol'],
                    ip_ttl)
                return

        # save original checksum
        checksum = ip.get_ip_sum()
        # recalculate checksum
        ip.auto_checksum = 1
        i = None
        try:
            p = ip.get_packet()
            i = self.ip_decoder.decode(p)
        except BaseException:
            try:
                i = self.ip_icmp_decoder.decode(p)
            except BaseException:
                logger.exception('Exception: Cannot decode constructed packet. Ignoring checksum verification.')
        except TypeError:
            logger.exception('Exception: Cannot obtain inner packet. Ignoring checksum verification.')
        if i is not None:
            valid_checksum = i.get_ip_sum()
            if checksum != valid_checksum:
                logger.info('Invalid checksum in IP header, dropping packet.')
                return

        # unreachables in network
        for subnet in self.unreach_list:
            if ipaddress.ip_address(event['ip_src']) in ipaddress.ip_network(subnet) and len(self.entry_points):
                entry_ip = None
                try:
                    entry_ip = self.entry_points[0].ip
                except (AttributeError, IndexError):
                    logger.exception('Exception: No entry point exists in configuration.')
                    return
                self.icmp_reply(
                    event['ethernet_dst'],
                    event['ethernet_src'],
                    entry_ip,
                    event['ip_src'],
                    ImpactPacket.ICMP.ICMP_UNREACH,
                    ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB,
                    ip)
                return

        # find corresponding device template
        handler = self.default
        for device in self.devices:
            if event['ip_dst'] in device.bind_list:
                handler = device
                break
        if handler == self.default:
            for external in self.externals:
                if event['ip_dst'] == external.ip:
                    handler = external
                    break

        additional_path_length = 0
        # find corresponding router
        target_router = None
        for route in self.routes:
            # router in network - path via connect_list
            if ipaddress.ip_address(event['ip_dst']) == ipaddress.ip_address(route.ip):
                target_router = route
                break
        if target_router is None:
            # direct path in network - path via link_list
            for route in self.routes:
                for link in route.link_list:
                    if ipaddress.ip_address(event['ip_dst']) in ipaddress.ip_network(link):
                        target_router = route
                        break
                if target_router is not None:
                    break
        if target_router is None:
            # no direct path - path via reachable subnet
            for route in self.routes:
                if ipaddress.ip_address(event['ip_dst']) in ipaddress.ip_network(route.subnet):
                    target_router = route
                    additional_path_length = random.randint(1, 9)  # unknown number of devices in path
                    break
        if target_router is None and len(self.entry_points):
            # packet destination ip not in unreachables, connections or links
            entry_ip = None
            try:
                entry_ip = self.entry_points[0].ip
            except (AttributeError, IndexError):
                logger.exception('Exception: No entry point exists in configuration.')
                return
            self.icmp_reply(
                event['ethernet_dst'],
                event['ethernet_src'],
                entry_ip,
                event['ip_src'],
                ImpactPacket.ICMP.ICMP_UNREACH,
                ImpactPacket.ICMP.ICMP_UNREACH_HOST_UNKNOWN,
                ip)
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
                for loss in attributes['loss'].values():
                    if loss > 100:
                        loss = 100
                    elif loss < 0:
                        loss = 0
                    drop_threshold *= float(1.0 - loss / 100.0)  # probability of no error in path
                drop = random.uniform(0.01, 0.99)
                if drop > drop_threshold:
                    logger.info('Dropping packet: Drop rate for router exceeds threshold.')
                    return

                latency = sum(attributes['latency'].values())

                # check reachability according to ttl
                path_len = len(path) + additional_path_length
                if path_len >= ip_ttl:
                    self.icmp_reply(
                        event['ethernet_dst'],
                        event['ethernet_src'],
                        target_router.ip,
                        event['ip_src'],
                        ImpactPacket.ICMP.ICMP_TIMXCEED,
                        ImpactPacket.ICMP.ICMP_TIMXCEED_INTRANS,
                        ip)
                    logger.info('Dropping packet: TTL reached zero.')
                    return

                reply_packet = handler.handle_packet(
                    eth, path_len, event, self.tunnels, cb_tunnel=self.get_tunnel_reply)
                break
            # else-branch: router with no defined entry to it - ignore

        # TODO: wait according to latency characteristics
        # implement queueing system with timestamps for each packet
        if reply_packet is not None:
            logger.debug('Sending reply: %s', reply_packet)
            try:
                self.pcapy_object.sendpacket(reply_packet.get_packet())
            except pcapy.PcapError as ex:
                logger.exception('Exception: Cannot send reply packet: %s', ex)
