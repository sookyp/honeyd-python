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
        self.ethernet = ethernet
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

    def handle_packet(self, ethernet_packet, path):
        """
        Forwards packet to the appropriate protocol handler based on configuration
        """
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
            if ip_packet_protocol == protocol_number:
                # search for defined services
                for service in self.service_list:
                    if protocol_name == service[0] and port == service[1]:
                        try:
                            if service[2] == 'filtered':
                                reply = protocol_class.filtered(ip_packet, path, self.personality, cb_ip_id=get_ip_id, cb_cip_id=get_cip_id, cb_icmp_id=get_icmp_id, cb_tcp_seq=get_tcp_seq, cb_tcp_ts=get_tcp_ts)
                            elif service[2] == 'closed':
                                reply = protocol_class.closed(ip_packet, path, self.personality, cb_ip_id=get_ip_id, cb_cip_id=get_cip_id, cb_icmp_id=get_icmp_id, cb_tcp_seq=get_tcp_seq, cb_tcp_ts=get_tcp_ts)
                            elif service[2] == 'open':
                                reply = protocol_class.opened(ip_packet, path, self.personality, cb_ip_id=get_ip_id, cb_cip_id=get_cip_id, cb_icmp_id=get_icmp_id, cb_tcp_seq=get_tcp_seq, cb_tcp_ts=get_tcp_ts)
                            else:
                                # TODO: execute script
                                pass
                        except Exception as ex:
                            # log exception
                            logger.exception('Exception: Device %s with issue: %s', self.name, exc_info=ex)
                        # TODO: encapsulate ethernet frame, set mac address
                        return reply

                # check default actions
                try:
                    if self.action_dictionary[protocol_name] == 'filtered':
                        reply = protocol_class.filtered(ip_packet, path, self.personality, cb_ip_id=get_ip_id, cb_cip_id=get_cip_id, cb_icmp_id=get_icmp_id, cb_tcp_seq=get_tcp_seq, cb_tcp_ts=get_tcp_ts)
                    elif self.action_dictionary[protocol_name] == 'closed':
                        reply = protocol_class.closed(ip_packet, path, self.personality, cb_ip_id=get_ip_id, cb_cip_id=get_cip_id, cb_icmp_id=get_icmp_id, cb_tcp_seq=get_tcp_seq, cb_tcp_ts=get_tcp_ts)
                    elif self.action_dictionary[protocol_name] == 'open':
                        reply = protocol_class.opened(ip_packet, path, self.personality, cb_ip_id=get_ip_id, cb_cip_id=get_cip_id, cb_icmp_id=get_icmp_id, cb_tcp_seq=get_tcp_seq, cb_tcp_ts=get_tcp_ts)
                except:
                    # log exception
                    logger.exception('Exception: Device %s with issue: %s', self.name, exc_info=ex)
                # TODO: encapsulate ethernet frame, set mac address
                return reply

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
        if self.personality.fp_seq.has_key['SS']:
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
            self.metadata['ip_id'] %= 0x10000L
            self.metadata['cip_id'] += self.metadata['cip_id_delta']
            self.metadata['cip_id'] %= 0x10000L

            # generate ICMP ID
            if self.metadata['icmp_id'] is not None:
                self.metadata['icmp_id'] += self.metadata['icmp_id_delta']
                self.metadata['icmp_id'] %= 0x10000L

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
                sp = int(sp, 16)
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
            self.metadata['tcp_isn'] %= 0x100000000L

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
            self.metadata['tcp_ts'] %= 0x100000000L

    def get_ip_id():
        # get
        result = self.metadata['ip_id']
        # update
        self.metadata['ip_id'] += self.metadata['ip_id_delta']
        self.metadata['ip_id'] %= 0x10000L
        return result

    def get_cip_id():
        # get
        result = self.metadata['cip_id']
        # update
        self.metadata['cip_id'] += self.metadata['cip_id_delta']
        self.metadata['cip_id'] %= 0x10000L
        return result

    def get_icmp_id():
        # get
        if self.metadata['icmp_id'] is None:
            result = get_ip_id()
            return result
        # update
        result = self.metadata['icmp_id']
        self.metadata['icmp_id'] += self.metadata['icmp_id_delta']
        self.metadata['icmp_id'] %= 0x10000L
        return result

    def get_tcp_seq():
        # get
        result = self.metadata['tcp_isn'] + self.metadata['tcp_isn_dev']
        result = int(int(result/self.metadata['tcp_isn_gcd'])*self.metadata['tcp_isn_gcd'])
        result %= 0x100000000L
        # update
        self.metadata['tcp_isn_dev'] *= -1
        self.metadata['tcp_isn'] += self.metadata['tcp_isn_delta']
        self.metadata['tcp_isn_dev'] %= 0x100000000L
        return result

    def get_tcp_ts():
        # get
        result = int(round(self.metadata['tcp_ts']))
        # update
        self.metadata['tcp_ts'] += self.metadata['tcp_ts_delta']
        self.metadata['tcp_ts'] %= 0x100000000L
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
