#!/usr/bin/env python

import logging

import ipaddress
import subprocess
import re

from impacket import ImpactPacket

import honeyd
from honeyd.protocols.tcp import TCPHandler
from honeyd.protocols.udp import UDPHandler
from honeyd.protocols.icmp import ICMPHandler

logger = logging.getLogger(__name__)

import sys

"""
  Contains elements which build up our network topology
"""
# TODO: investigate IP spoofing over raw packets
class Device(object):
    """
      Defines devices on the network, like machines, routers, switches, etc.
    """
    def __init__(self, name, personality, ethernet, actions, services, binds):
        # possible values are filtered through XSD validation
        self.name = name
        self.personality = personality
        self.ethernet = ethernet

        # TODO: proper ethernet conversion that impacket can handle
        try:
            #self.ethernet = self.ethernet.replace(':','').decode('hex')
            self.ethernet = self.ethernet.replace(':','').decode('hex')
            # self.ethernet = int(self.ethernet, 16)

        except:
            logger.exception('Exception: MAC conversion for device %s failed.', self.name)
            sys.exit(2)

        self.action_dictionary = actions
        self.service_list = services
        self.bind_list = binds
        # TODO: investigate possibility of using one handler for every device -> requires more complex structures and administration
        icmp_handler = ICMPHandler()
        tcp_handler = TCPHandler()
        udp_handler = UDPHandler()
        self.protocol_mapping = (
            ('icmp', 1, icmp_handler), # IP_PROTO_ICMP
            ('tcp', 6, tcp_handler), # IP_PROTO_TCP
            ('udp', 17, udp_handler) # IP_PROTO_UDP
        )
        self.metadata = {
            'ip_id'          : 0, # IP ID
            'ip_id_delta'    : 0,
            'cip_id'         : 0, # CLOSED IP ID
            'cip_id_delta'   : 0,
            'icmp_id'        : 0, # ICMP ID
            'icmp_id_delta'  : 0,
            'tcp_isn'        : 0, # TCP ISN
            'tcp_isn_delta'  : 0,
            'tcp_isn_gcd'    : 0,
            'tcp_isn_dev'    : 0,
            'tcp_ts'         : 0, # TCP TS
            'tcp_ts_delta'   : 0
        }
        self.ip_id_generator()
        self.tcp_isn_generator()
        self.tcp_ts_generator()
        self.decoder = ImpactDecoder.IPDecoder()

    def handle_packet(self, ethernet_packet, path, target):
        """
        Forwards packet to the appropriate protocol handler based on configuration
        """
        reply = None
        ip_packet = ethernet_packet.child()
        ip_protocol, port_number = target

        eth_dst = ethernet_packet.get_ether_shost()

        # TODO: set ethernet address if needed
        for protocol_name, protocol_number, protocol_class in self.protocol_mapping:
            if ip_protocol == protocol_number:
                # search for defined services
                for service in self.service_list:
                    if protocol_name == service[0] and port_number == service[1]:
                        try:
                            if service[2] == 'filtered':
                                reply = protocol_class.filtered(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                            elif service[2] == 'closed':
                                reply = protocol_class.closed(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                            elif service[2] == 'open':
                                reply = protocol_class.opened(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                            elif service[2] == 'block':
                                reply = protocol_class.blocked(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                            elif service[2].startswith('proxy '):
                                # TODO: handle proxy
                                proxy_data = value[len('proxy '):].split(':')
                                proxy_ip = ipaddress.ip_address(unicode(proxy_data[0]))
                                proxy_port = int(proxy_data[1], 10)
                                pass
                            else:
                                # script is excpected to provide proper IP packet as a reply as series of bytes through stdout
                                script = gevent.subprocess.Popen(service[2], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
                                try:
                                    output, error = script.communicate(input=ethernet_packet, timeout=10)
                                    reply = self.decoder.decode(output)
                                    inner_packet = reply.child()
                                    if reply.get_ip_p() == ImpactPacket.TCP.protocol:
                                        inner_packet.set_th_sport(port_number)
                                        packet = ip_packet.child()
                                        inner_packet.set_th_dport(packet.get_th_sport())
                                        reply.contains(inner_packet)
                                    elif ip_packet_protocol == ImpactPacket.UDP.protocol:
                                        inner_packet.set_uh_sport(port_number)
                                        packet = ip_packet.child()
                                        inner_packet.set_uh_dport(packet.get_uh_sport())
                                        reply.contains(inner_packet)
                                    reply.set_ip_id(self.get_ip_id()) # TODO ?
                                    reply.set_ip_src(ip_packet.get_ip_dst())
                                    reply.set_ip_dst(ip_packet.get_ip_src())
                                    reply.auto_checksum = 1
                                except gevent.subprocess.TimeoutExpired:
                                    logger.exception('Exception: script timeout expired.')
                                    script.kill()
                                except gevent.subprocess.SubprocessError:
                                    logger.exception('Exception: script subprocess error.')
                                    script.kill()
                        except Exception as ex:
                            # log exception
                            logger.exception('Exception: Device %s with issue: %s', self.name, ex)
                        # TODO: encapsulate ethernet frame, set mac address
                        if reply is not None:
                            reply_eth = ImpactPacket.Ethernet()
                            reply_eth.set_ether_type(0x800)
                            # reply_eth.set_ether_shost(self.ethernet)
                            reply_eth.set_ether_dhost(eth_dst)
                            
                            reply_eth.contains(reply)
                            return reply_eth
                        return None

                # check default actions
                try:
                    if self.action_dictionary[protocol_name] == 'filtered':
                        reply = protocol_class.filtered(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                    elif self.action_dictionary[protocol_name] == 'closed':
                        reply = protocol_class.closed(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                    elif self.action_dictionary[protocol_name] == 'open':
                        reply = protocol_class.opened(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                    elif self.action_dictionary[protocol_name] == 'block':
                                reply = protocol_class.blocked(ip_packet, path, self.personality, cb_ip_id=self.get_ip_id, cb_cip_id=self.get_cip_id, cb_icmp_id=self.get_icmp_id, cb_tcp_seq=self.get_tcp_seq, cb_tcp_ts=self.get_tcp_ts)
                    elif self.action_dictionary[protocol_name].startswith('proxy '):
                        # TODO: handle proxy
                        proxy_data = value[len('proxy '):].split(':')
                        proxy_ip = ipaddress.ip_address(unicode(proxy_data[0]))
                        proxy_port = int(proxy_data[1], 10)
                        pass
                except Exception as ex:
                    # log exception
                    logger.exception('Exception: Device %s with issue: %s', self.name, ex)
                # TODO: encapsulate ethernet frame, set mac address
                if reply is not None:
                    reply_eth = ImpactPacket.Ethernet()
                    reply_eth.set_ether_type(0x800)
                    # reply_eth.set_ether_shost(self.ethernet)
                    reply_eth.set_ether_dhost(eth_dst)

                    reply_eth.contains(reply)
                    return reply_eth
                return None

    def ip_id_generator(self):
        """
        Responsible for proper IP ID generation in outgoing packets. The numbers used are randomly selected in accordance with the nmap testing algorithm.
        """
        # TI
        if self.personality.fp_seq.has_key('TI'):
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
                except:
                    logger.exception('Exception: Device %s issue with IP ID generation. Possible invalid values in configuration. Check fingerprint section SEQ:TI', self.name)

        # CI
        if self.personality.fp_seq.has_key('CI'):
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
                except:
                    logger.exception('Exception: Device %s issue with IP ID generation. Possible invalid values in configuration. Check fingerprint section SEQ:CI', self.name)

        # SS
        if self.personality.fp_seq.has_key('SS'):
            if self.personality.fp_seq['SS'] == 'S':
                self.metadata['icmp_id'] = None
                self.metadata['icmp_id_delta'] = None
            elif self.personality.fp_seq['SS'] == 'O':
                # II
                if self.personality.fp_seq.has_key('II'):
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
                        except:
                            logger.exception('Exception: Device %s issue with IP ID generation, using value 0. Possible invalid values in configuration. Check fingerprint section SEQ:II', self.name)
        # possible TODO: we can pregenerate a couple IDs, therefore we start at a semi-random number and not zero
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
        avg_ppi = 0.11 # average time interval per packet 150 ms
        if self.personality.fp_seq.has_key('GCD'):
            isn = re.split('[|-]', self.personality.fp_seq['GCD'])
            try:
                self.metadata['tcp_isn_gcd'] = int(isn[0], 16)
            except:
                self.metadata['tcp_isn_gcd'] = 1

        if self.personality.fp_seq.has_key('ISR'):
            isr = self.personality.fp_seq['ISR'].split('-')
            try:
                if len(isr) == 1:
                    isr = int(isr[0], 16)
                else:
                    isr = (int(isr[0], 16) + int(isr[1], 16)) / 2
            except:
                logger.exception('Exception: Device %s issue with TCP ISN generation, using value 0. Possible invalid values in configuration. Check fingerprint section SEQ:ISR', self.name)
                isr = 0

        if self.personality.fp_seq.has_key('SP'):
            sp = self.personality.fp_seq['SP'].split('-')
            try:
                sp = int(sp[0], 16)
            except:
                logger.exception('Exception: Device %s issue with TCP ISN generation, using value 0. Possible invalid values in configuration. Check fingerprint section SEQ:SP', self.name)
                sp = 0

        # TODO: statistics.stdev()
        self.metadata['tcp_isn_dev'] = (2**(sp/8.0))*5/4
        if self.metadata['tcp_isn_gcd'] > 9:
            self.metadata['tcp_isn_dev'] *= self.metadata['tcp_isn_gcd']
        self.metadata['tcp_isn_dev'] *= avg_ppi
        self.metadata['tcp_isn_delta'] = 2**(isr/8.0)*avg_ppi

        for i in range(5):
            self.metadata['tcp_isn_dev'] *= -1
            self.metadata['tcp_isn'] += self.metadata['tcp_isn_delta']
            self.metadata['tcp_isn'] %= 0x100000000

    def tcp_ts_generator(self):
        """
        Responsible for proper TCP Timestamp generation
        """
        avg_ppi = 0.11 # average time interval per packet 150 ms
        if self.personality.fp_seq.has_key('TS'):
            if self.personality.fp_seq['TS'] in ['Z', 'U']:
                self.metadata['tcp_ts_delta'] = 0
            else:
                try:
                    ts = re.split('[|-]', self.personality.fp_seq['TS'])
                    ts = int(ts[0], 16)
                    self.metadata['tcp_ts_delta'] = (2**ts) * avg_ppi
                except:
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
        # get
        result = self.metadata['tcp_isn'] + self.metadata['tcp_isn_dev']
        result = int(int(result/self.metadata['tcp_isn_gcd'])*self.metadata['tcp_isn_gcd'])
        result %= 0x100000000
        # update
        self.metadata['tcp_isn_dev'] *= -1
        self.metadata['tcp_isn'] += self.metadata['tcp_isn_delta']
        self.metadata['tcp_isn_dev'] %= 0x100000000
        return result

    def get_tcp_ts(self):
        # get
        result = int(round(self.metadata['tcp_ts']))
        # update
        self.metadata['tcp_ts'] += self.metadata['tcp_ts_delta']
        self.metadata['tcp_ts'] %= 0x100000000
        return result

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
