#!/usr/bin/env python

import logging

import re
import gevent
import netifaces
import ipaddress
from impacket import ImpactPacket, ImpactDecoder

import honeyd
from honeyd.protocols.tcp import TCPHandler
from honeyd.protocols.udp import UDPHandler
from honeyd.protocols.icmp import ICMPHandler

logger = logging.getLogger(__name__)

import sys

"""
  Contains elements which build up our network topology
"""


class Device(object):
    """
      Defines devices on the network, like machines, routers, switches, etc.
    """

    def __init__(self, name, personality, ethernet, actions, services, binds):
        logger.debug('Creating device %s on IPs %s', name, binds)
        self.name = name
        self.personality = personality
        self.mac = ethernet
        try:
            self.ethernet = [int(i, 16) for i in self.mac.split(':')]
        except BaseException:
            logger.exception('Exception: MAC conversion for device %s failed: %s', self.name, self.mac)
            sys.exit(1)

        self.action_dictionary = actions
        self.service_list = services
        self.bind_list = binds

        self.protocol_mapping = (
            ('icmp', 1, ICMPHandler()),  # IP_PROTO_ICMP
            ('tcp', 6, TCPHandler()),  # IP_PROTO_TCP
            ('udp', 17, UDPHandler())  # IP_PROTO_UDP
        )
        self.metadata = {
            'ip_id': 0,  # IP ID
            'ip_id_delta': 0,
            'cip_id': 0,  # CLOSED IP ID
            'cip_id_delta': 0,
            'icmp_id': 0,  # ICMP ID
            'icmp_id_delta': 0,
            'tcp_isn': 0,  # TCP ISN
            'tcp_isn_delta': 0,
            'tcp_isn_gcd': 0,
            'tcp_isn_dev': 0,
            'tcp_ts': 0,  # TCP TS
            'tcp_ts_delta': 0
        }
        self.ip_id_generator()
        self.tcp_isn_generator()
        self.tcp_ts_generator()
        # have to check for ICMP with incomplete header
        # script can return IP()/ICMP() -> see impacket bug #4870, use IPDecoderForICMP
        self.decoder = ImpactDecoder.IPDecoder()
        self.decoder_icmp = ImpactDecoder.IPDecoderForICMP()

    def handle_packet(self, ethernet_packet, path, target, tunnels, cb_tunnel=None):
        """
        Forwards packet to the appropriate protocol handler based on configuration
        """
        reply = None
        ip_packet = ethernet_packet.child()
        ip_protocol, port_number = target
        eth_dst = ethernet_packet.get_ether_shost()

        for protocol_name, protocol_number, protocol_class in self.protocol_mapping:
            if ip_protocol == protocol_number:
                # search for defined services
                for service in self.service_list:
                    if protocol_name == service[0] and port_number == service[1]:
                        try:
                            if service[2] == 'filtered':
                                reply = protocol_class.filtered(
                                    ip_packet, path, self.personality, cb_ipid=self.get_ip_id, cb_icmpid=self.get_icmp_id)

                            elif service[2] == 'closed':
                                reply = protocol_class.closed(
                                    ip_packet,
                                    path,
                                    self.personality,
                                    cb_cipid=self.get_cip_id,
                                    cb_tcpseq=self.get_tcp_seq,
                                    cb_tcpts=self.get_tcp_ts)

                            elif service[2] == 'open':
                                reply = protocol_class.opened(
                                    ip_packet,
                                    path,
                                    self.personality,
                                    cb_ipid=self.get_ip_id,
                                    cb_tcpseq=self.get_tcp_seq,
                                    cb_tcpts=self.get_tcp_ts)

                            elif service[2] == 'block':
                                reply = protocol_class.blocked(ip_packet, path, self.personality)

                            elif service[2].startswith('proxy '):
                                proxy_data = service[2][len('proxy '):].split(':')
                                proxy_ip = ipaddress.ip_address(unicode(proxy_data[0]))
                                proxy_mode = proxy_data[1]

                                # find configured tunnel interface
                                for tunnel_interface, remote_ip, tunnel_mode in tunnels:

                                    # self.interface, self.remote_ip, self.tunnel_mode
                                    if remote_ip == proxy_ip:

                                        # update ttl
                                        delta_ttl = ip_packet.get_ip_ttl() - len(path)
                                        ip_packet.set_ip_ttl(delta_ttl)
                                        ip_packet.auto_checksum = 1

                                        # create tunnel outer encapsulation # IPPROTO_GRE || IPPROTO_IPIP
                                        if tunnel_mode == 'gre':
                                            s = gevent.socket.socket(
                                                gevent.socket.AF_PACKET, gevent.socket.SOCK_RAW, gevent.socket.IPPROTO_GRE)
                                            s.sendto(ip_packet.get_packet(), (tunnel_interface, 0x0800))
                                        else:
                                            s = gevent.socket.socket(
                                                gevent.socket.AF_PACKET, gevent.socket.SOCK_RAW, gevent.socket.IPPROTO_IPIP)
                                            s.sendto(ip_packet.get_packet(), (tunnel_interface, 0x0800))

                                        reply_ip = cb_tunnel(proxy_ip)
                                        if reply_ip is None:
                                            return None
                                        delta_ttl = reply_ip.get_ip_ttl() - len(path)
                                        reply_ip.set_ip_ttl(delta_ttl)
                                        reply_ip.auto_checksum = 1
                                        reply_ip.set_ip_src(ip_packet.get_ip_dst())

                                        reply_eth = ImpactPacket.Ethernet()
                                        reply_eth.set_ether_type(0x800)
                                        reply_eth.set_ether_shost(self.ethernet)
                                        reply_eth.set_ether_dhost(eth_dst)

                                        reply_eth.contains(reply_ip)
                                        return reply_eth

                                else:
                                    logger.error('Error: No interface found for proxy IP %s', proxy_data[0])
                                return None
                            else:
                                # script is excpected to provide proper IP packet as a reply as series of
                                # bytes through stdout
                                script = gevent.subprocess.Popen(
                                    service[2], shell=True, stdin=gevent.subprocess.PIPE, stdout=gevent.subprocess.PIPE, stderr=None)
                                try:
                                    output, error = script.communicate(input=ip_packet.get_packet(), timeout=10)
                                    try:
                                        reply = self.decoder.decode(output)
                                    except BaseException:
                                        try:
                                            reply = self.decoder_icmp.decode(output)
                                        except BaseException:
                                            logger.exception(
                                                'Exception: Cannot decode packet from script.')
                                            return None

                                    """
                                    inner_packet = reply.child()

                                    if reply.get_ip_p() == 6:
                                        inner_packet.set_th_sport(port_number)
                                        packet = ip_packet.child()
                                        inner_packet.set_th_dport(packet.get_th_sport())
                                        inner_packet.calculate_checksum()
                                        reply.contains(inner_packet)

                                    elif reply.get_ip_p() == 17:
                                        inner_packet.set_uh_sport(port_number)
                                        packet = ip_packet.child()
                                        inner_packet.set_uh_dport(packet.get_uh_sport())
                                        inner_packet.calculate_checksum()
                                        reply.contains(inner_packet)
                                    """

                                    reply.set_ip_id(self.get_ip_id())
                                    reply.set_ip_src(ip_packet.get_ip_dst())
                                    reply.set_ip_dst(ip_packet.get_ip_src())
                                    reply.auto_checksum = 1

                                except gevent.subprocess.TimeoutExpired:
                                    logger.exception('Exception: script timeout expired.')
                                    script.kill()
                                except BaseException:
                                    logger.exception('Exception: script subprocess error.')
                                    script.kill()

                        except Exception as ex:
                            # log exception
                            logger.exception('Exception: Device %s with issue: %s', self.name, ex)

                        if reply is not None:
                            reply_eth = ImpactPacket.Ethernet()
                            reply_eth.set_ether_type(0x800)
                            reply_eth.set_ether_shost(self.ethernet)
                            reply_eth.set_ether_dhost(eth_dst)

                            reply_eth.contains(reply)
                            return reply_eth
                        return None

                # check default actions
                try:
                    if self.action_dictionary[protocol_name] == 'filtered':
                        reply = protocol_class.filtered(
                            ip_packet, path, self.personality, cb_ipid=self.get_ip_id, cb_icmpid=self.get_icmp_id)

                    elif self.action_dictionary[protocol_name] == 'closed':
                        reply = protocol_class.closed(
                            ip_packet,
                            path,
                            self.personality,
                            cb_cipid=self.get_cip_id,
                            cb_tcpseq=self.get_tcp_seq,
                            cb_tcpts=self.get_tcp_ts)

                    elif self.action_dictionary[protocol_name] == 'open':
                        reply = protocol_class.opened(
                            ip_packet,
                            path,
                            self.personality,
                            cb_ipid=self.get_ip_id,
                            cb_tcpseq=self.get_tcp_seq,
                            cb_tcpts=self.get_tcp_ts)

                    elif self.action_dictionary[protocol_name] == 'block':
                        reply = protocol_class.blocked(ip_packet, path, self.personality)

                    elif self.action_dictionary[protocol_name].startswith('proxy '):
                        proxy_data = self.action_dictionary[protocol_name][len('proxy '):].split(':')
                        proxy_ip = ipaddress.ip_address(unicode(proxy_data[0]))
                        proxy_mode = proxy_data[1]

                        # find configured tunnel interface
                        for tunnel_interface, remote_ip, tunnel_mode in tunnels:

                            # self.interface, self.remote_ip, self.tunnel_mode
                            if remote_ip == proxy_ip:

                                # update ttl
                                delta_ttl = ip_packet.get_ip_ttl() - len(path)
                                ip_packet.set_ip_ttl(delta_ttl)
                                ip_packet.auto_checksum = 1

                                # create tunnel outer encapsulation # IPPROTO_GRE || IPPROTO_IPIP
                                if tunnel_mode == 'gre':
                                    s = gevent.socket.socket(
                                        gevent.socket.AF_PACKET, gevent.socket.SOCK_RAW, gevent.socket.IPPROTO_GRE)
                                    s.sendto(ip_packet.get_packet(), (tunnel_interface, 0x0800))
                                else:
                                    s = gevent.socket.socket(
                                        gevent.socket.AF_PACKET, gevent.socket.SOCK_RAW, gevent.socket.IPPROTO_IPIP)
                                    s.sendto(ip_packet.get_packet(), (tunnel_interface, 0x0800))

                                reply_ip = cb_tunnel()
                                if reply_ip is None:
                                    return None
                                delta_ttl = reply_ip.get_ip_ttl() - len(path)
                                reply_ip.set_ip_ttl(delta_ttl)
                                reply_ip.auto_checksum = 1
                                reply_ip.set_ip_src(ip_packet.get_ip_dst())
                                reply_ip.set_ip_dst(ip_packet.get_ip_src())
                                reply = reply_ip

                                break
                        else:
                            logger.error('Error: No interface found for proxy IP %s', proxy_data[0])
                        return None

                except Exception as ex:
                    # log exception
                    logger.exception('Exception: Device %s with issue: %s', self.name, ex)

                if reply is not None:
                    reply_eth = ImpactPacket.Ethernet()
                    reply_eth.set_ether_type(0x800)
                    try:
                        reply_eth.set_ether_shost(self.ethernet)
                    except IndexError:
                        logger.exception('Exception: Invalid ethernet format: %s', self.ethernet)
                    reply_eth.set_ether_dhost(eth_dst)

                    reply_eth.contains(reply)
                    return reply_eth
                return None

    def ip_id_generator(self):
        """
        Responsible for proper IP ID generation in outgoing packets. The numbers used are randomly selected in accordance with the nmap testing algorithm.
        """
        # TI
        if 'TI' in self.personality.fp_seq:
            if self.personality.fp_seq['TI'] == 'Z':
                self.metadata['ip_id_delta'] = 0
            elif self.personality.fp_seq['TI'] == 'RD':
                self.metadata['ip_id_delta'] = 20011
            elif self.personality.fp_seq['TI'] == 'RI':
                self.metadata['ip_id_delta'] = 1019
            elif self.personality.fp_seq['TI'] == 'BI':
                self.metadata['ip_id_delta'] = 1280
            elif self.personality.fp_seq['TI'] == 'I':
                self.metadata['ip_id_delta'] = 1
            else:
                try:
                    self.metadata['ip_id_delta'] = int(self.personality.fp_seq['TI'], 16)
                except BaseException:
                    logger.exception(
                        'Exception: Device %s issue with IP ID generation. Possible invalid values in configuration. Check fingerprint section SEQ:TI',
                        self.name)

        # CI
        if 'CI' in self.personality.fp_seq:
            if self.personality.fp_seq['CI'] == 'Z':
                self.metadata['cip_id_delta'] = 0
            elif self.personality.fp_seq['CI'] == 'RD':
                self.metadata['cip_id_delta'] = 20011
            elif self.personality.fp_seq['CI'] == 'RI':
                self.metadata['cip_id_delta'] = 1019
            elif self.personality.fp_seq['CI'] == 'BI':
                self.metadata['cip_id_delta'] = 1280
            elif self.personality.fp_seq['CI'] == 'I':
                self.metadata['cip_id_delta'] = 1
            else:
                try:
                    self.metadata['cip_id_delta'] = int(self.personality.fp_seq['CI'], 16)
                except BaseException:
                    logger.exception(
                        'Exception: Device %s issue with IP ID generation. Possible invalid values in configuration. Check fingerprint section SEQ:CI',
                        self.name)

        # SS
        if 'SS' in self.personality.fp_seq:
            if self.personality.fp_seq['SS'] == 'S':
                self.metadata['icmp_id'] = None
                self.metadata['icmp_id_delta'] = None
            elif self.personality.fp_seq['SS'] == 'O':
                # II
                if 'II' in self.personality.fp_seq:
                    if self.personality.fp_seq['II'] == 'Z':
                        self.metadata['icmp_id_delta'] = 0
                    elif self.personality.fp_seq['II'] == 'RD':
                        self.metadata['icmp_id_delta'] = 20011
                    elif self.personality.fp_seq['II'] == 'RI':
                        self.metadata['icmp_id_delta'] = 1019
                    elif self.personality.fp_seq['II'] == 'BI':
                        self.metadata['icmp_id_delta'] = 1280
                    elif self.personality.fp_seq['II'] == 'I':
                        self.metadata['icmp_id_delta'] = 1
                    else:
                        try:
                            self.metadata['icmp_id_delta'] = int(self.personality.fp_seq['II'], 16)
                        except BaseException:
                            logger.exception(
                                'Exception: Device %s issue with IP ID generation, using value 0. Possible invalid values in configuration. Check fingerprint section SEQ:II',
                                self.name)
        for i in range(5):
            # generate IP ID
            self.metadata['ip_id'] += self.metadata['ip_id_delta']
            self.metadata['ip_id'] %= 0x10000
            self.metadata['cip_id'] += self.metadata['cip_id_delta']
            self.metadata['cip_id'] %= 0x10000

            # generate ICMP ID
            if self.metadata['icmp_id'] is not None:
                self.metadata['icmp_id'] += self.metadata['icmp_id_delta']
                self.metadata['icmp_id'] %= 0x10000

    def tcp_isn_generator(self):
        """
        Responsible for proper TCP Initial Sequence Number generation.
        """
        avg_ppi = 0.11  # Nmap default value, average time interval per packet 150 ms = 2Hz
        delta_i = 0
        index = 0
        isn = list()
        if 'GCD' in self.personality.fp_seq:
            isn_list = re.split('[|-]', self.personality.fp_seq['GCD'])
            for i in isn_list:
                if i.startswith('>'):
                    delta_i = 1
                    index = 1
                elif i.startswith('<'):
                    delta_i = -1
                    index = 1
                try:
                    isn.append(int(i[index:], 16) + delta_i)
                except BaseException:
                    isn.append(1)
        self.metadata['tcp_isn_gcd'] = isn[0]

        if 'ISR' in self.personality.fp_seq:
            isr = self.personality.fp_seq['ISR'].split('-')
            try:
                if len(isr) == 1:
                    isr = int(isr[0], 16)
                else:
                    isr = (int(isr[0], 16) + int(isr[1], 16)) / 2
            except BaseException:
                logger.exception(
                    'Exception: Device %s issue with TCP ISN generation, using value 0. Possible invalid values in configuration. Check fingerprint section SEQ:ISR',
                    self.name)
                isr = 0

        if 'SP' in self.personality.fp_seq:
            sp = self.personality.fp_seq['SP'].split('-')
            try:
                sp = int(sp[0], 16)
                """
                if len(sp) == 1:
                    sp = int(sp[0], 16)
                else:
                    sp = (int(sp[0], 16) + int(sp[1], 16) ) / 2
                """
            except BaseException:
                logger.exception(
                    'Exception: Device %s issue with TCP ISN generation, using value 0. Possible invalid values in configuration. Check fingerprint section SEQ:SP',
                    self.name)
                sp = 0

        self.metadata['tcp_isn_dev'] = 2**(sp / 8.0) * avg_ppi
        self.metadata['tcp_isn_delta'] = 2**(isr / 8.0) * avg_ppi
        if self.metadata['tcp_isn_gcd'] > 9:
            self.metadata['tcp_isn_dev'] *= self.metadata['tcp_isn_gcd']

        for i in range(5):
            self.metadata['tcp_isn_dev'] *= -1
            self.metadata['tcp_isn'] += self.metadata['tcp_isn_delta']
            self.metadata['tcp_isn'] %= 0x100000000

    def tcp_ts_generator(self):
        """
        Responsible for proper TCP Timestamp generation
        """
        avg_ppi = 0.11  # average time interval per packet 150 ms
        if 'TS' in self.personality.fp_seq:
            if self.personality.fp_seq['TS'] in ['Z', 'U']:
                self.metadata['tcp_ts_delta'] = 0
            else:
                try:
                    ts = re.split('[|-]', self.personality.fp_seq['TS'])
                    ts = int(ts[0], 16)
                    self.metadata['tcp_ts_delta'] = (2**ts) * avg_ppi
                except BaseException:
                    pass

        for i in range(5):
            self.metadata['tcp_ts'] += self.metadata['tcp_ts_delta']
            self.metadata['tcp_ts'] %= 0x100000000

    def get_ip_id(self):
        # get
        result = self.metadata['ip_id']
        # update
        self.metadata['ip_id'] += self.metadata['ip_id_delta']
        self.metadata['ip_id'] %= 0x10000
        return result

    def get_cip_id(self):
        # get
        result = self.metadata['cip_id']
        # update
        self.metadata['cip_id'] += self.metadata['cip_id_delta']
        self.metadata['cip_id'] %= 0x10000
        return result

    def get_icmp_id(self):
        # get
        if self.metadata['icmp_id'] is None:
            result = self.get_ip_id()
            return result
        # update
        result = self.metadata['icmp_id']
        self.metadata['icmp_id'] += self.metadata['icmp_id_delta']
        self.metadata['icmp_id'] %= 0x10000
        return result

    def get_tcp_seq(self):
        result = self.metadata['tcp_isn'] + self.metadata['tcp_isn_dev']
        self.metadata['tcp_isn_dev'] *= -1
        result = int(int(result / self.metadata['tcp_isn_gcd']) * self.metadata['tcp_isn_gcd'])
        self.metadata['tcp_isn'] += self.metadata['tcp_isn_delta']
        self.metadata['tcp_isn'] %= 0x100000000
        return result % 0x10000000

    def get_tcp_ts(self):
        # get
        result = int(round(self.metadata['tcp_ts']))
        # update
        self.metadata['tcp_ts'] += self.metadata['tcp_ts_delta']
        self.metadata['tcp_ts'] %= 0x100000000
        return result


class Route(object):
    """
      Defines connections between the devices on the network
    """

    def __init__(self, ip, subnet, entry, latency, loss, connects, links, unreaches):
        self.ip = ip
        self.subnet = subnet

        self.entry = None
        if entry == 'true':
            self.entry = True
        if entry == 'false':
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
        if interface not in netifaces.interfaces():
            logger.error('Error: No valid interface detected for external %s : %s.', ip, interface)
            sys.exit(1)
        self.interface = interface

    def handle_packet(self, ethernet_packet, path, target, tunnels, cb_tunnel=None):
        # update ttl
        ip_packet = ethernet_packet.child()
        delta_ttl = ip_packet.get_ip_ttl() - len(path)
        ip_packet.set_ip_ttl(delta_ttl)
        ip_packet.auto_checksum = 1
        # encapsulate into original ethernet frame
        # eth_frame = ImpactPacket.Ethernet()
        # eth_frame.set_ether_type(0x800)
        # eth_frame.set_ether_shost(ethernet_packet.get_ether_shost())
        # eth_frame.set_ether_dhost(ethernet_packet.get_ether_dhost())
        # eth_frame.contains(ip_packet)
        s = gevent.socket.socket(gevent.socket.AF_PACKET, gevent.socket.SOCK_RAW)
        # s.bind((self.interface, 0))
        # s.send(eth_frame.get_packet())
        s.sendto(ip_packet.get_packet(), (self.interface, 0x0800))
        return None
