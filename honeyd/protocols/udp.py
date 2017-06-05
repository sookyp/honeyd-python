#!/usr/bin/env python
"""Udp.py defines the UDP behavior"""
import logging
from impacket import ImpactPacket

logger = logging.getLogger(__name__)


class UDPHandler(object):
    """UDPHandler defines behavior opened, closed, blocked and filtered ports"""

    def opened(self, packet, path, personality, **kwargs):
        """Function defines open port behavior"""
        callback_ipid = kwargs.get('cb_ipid', None)
        # send rUDP
        udp_packet = packet.child()

        # udp datagram
        reply_udp = ImpactPacket.UDP()
        reply_udp.set_uh_sport(udp_packet.get_uh_dport())
        reply_udp.set_uh_dport(udp_packet.get_uh_sport())
        reply_udp.auto_checksum = 1
        reply_udp.calculate_checksum()

        # ip packet
        reply_ip = ImpactPacket.IP()
        reply_ip.set_ip_v(4)
        reply_ip.set_ip_p(17)
        reply_ip.set_ip_rf(False)
        reply_ip.set_ip_df(False)
        reply_ip.set_ip_mf(False)
        reply_ip.set_ip_src(packet.get_ip_dst())
        reply_ip.set_ip_dst(packet.get_ip_src())
        reply_ip.set_ip_id(callback_ipid())
        # check T
        ttl = 0x7f
        if 'T' in personality.fp_u1:
            try:
                ttl = personality.fp_u1['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except BaseException:
                raise Exception('Unsupported U1:T=%s', personality.fp_u1['T'])

        # check TG
        if 'TG' in personality.fp_u1:
            try:
                ttl = int(personality.fp_u1['TG'], 16)
            except BaseException:
                raise Exception('Unsupported U1:TG=%s', personality.fp_u1['TG'])
        delta_ttl = ttl - path
        if delta_ttl < 1:
            logger.debug('Reply packet dropped: TTL reached 0 within virtual network.')
            return None
        reply_ip.set_ip_ttl(delta_ttl)
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_udp)

        return reply_ip

    def closed(self, packet, path, personality, **kwargs):
        """Function defines closed port behavior"""
        callback_cipid = kwargs.get('cb_cipid', None)
        # respond with ICMP error type 3 code 3
        # check R
        if 'R' in personality.fp_u1:
            if personality.fp_u1['R'] == 'N':
                return None
        udp_packet = packet.child()

        # inner udp datagram
        # duplicate incoming UDP header
        inner_udp = ImpactPacket.UDP()
        inner_udp.set_uh_sport(udp_packet.get_uh_sport())
        inner_udp.set_uh_dport(udp_packet.get_uh_dport())
        inner_udp.set_uh_ulen(udp_packet.get_uh_ulen())
        inner_udp.set_uh_sum(udp_packet.get_uh_sum())
        inner_udp.auto_checksum = 0
        l = packet.get_ip_len()
        if l > 1472: # 1500 - 20 - 8 => outer IP and ICMP
            # 1444 = 1500 - 20 - 8 - 20 - 8 => MTU - outer IP - ICMP - inner IP - UDP
            data = udp_packet.get_packet()[:1444]
        else:
            data = udp_packet.get_packet()
        data = data[udp_packet.get_header_size():]  # same slice as [8:]

        # inner ip packet
        # duplicate incoming IP header
        inner_ip = ImpactPacket.IP()
        inner_ip.set_ip_v(packet.get_ip_v())
        inner_ip.set_ip_hl(packet.get_ip_hl())
        inner_ip.set_ip_tos(packet.get_ip_tos())
        inner_ip.set_ip_len(packet.get_ip_len())
        inner_ip.set_ip_p(packet.get_ip_p())
        inner_ip.set_ip_off(packet.get_ip_off())
        inner_ip.set_ip_offmask(packet.get_ip_offmask())
        inner_ip.set_ip_rf(packet.get_ip_rf())
        inner_ip.set_ip_df(packet.get_ip_df())
        inner_ip.set_ip_mf(packet.get_ip_mf())
        inner_ip.set_ip_src(packet.get_ip_src())
        inner_ip.set_ip_dst(packet.get_ip_dst())
        inner_ip.set_ip_id(packet.get_ip_id())
        inner_ip.set_ip_ttl(packet.get_ip_ttl())
        inner_ip.set_ip_sum(packet.get_ip_sum())
        inner_ip.auto_checksum = 0

        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ImpactPacket.ICMP.ICMP_UNREACH)
        reply_icmp.set_icmp_code(ImpactPacket.ICMP.ICMP_UNREACH_PORT)
        reply_icmp.set_icmp_id(0)  # unused field
        reply_icmp.set_icmp_seq(0)  # unused field
        reply_icmp.auto_checksum = 1

        # ip packet
        reply_ip = ImpactPacket.IP()
        reply_ip.set_ip_v(4)
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_rf(False)
        reply_ip.set_ip_df(False)
        reply_ip.set_ip_mf(False)
        reply_ip.set_ip_src(packet.get_ip_dst())
        reply_ip.set_ip_dst(packet.get_ip_src())
        reply_ip.set_ip_id(callback_cipid())
        reply_ip.auto_checksum = 1

        # check DF
        if 'DF' in personality.fp_u1:
            if personality.fp_u1['DF'] == 'N':
                reply_ip.set_ip_df(False)
            elif personality.fp_u1['DF'] == 'Y':
                reply_ip.set_ip_df(True)
            else:
                raise Exception('Unsupported U1:DF=%s', personality.fp_u1['DF'])

        # check T
        ttl = 0x7f
        if 'T' in personality.fp_u1:
            try:
                ttl = personality.fp_u1['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except BaseException:
                raise Exception('Unsupported U1:T=%s', personality.fp_u1['T'])

        # check TG
        if 'TG' in personality.fp_u1:
            try:
                ttl = int(personality.fp_u1['TG'], 16)
            except BaseException:
                raise Exception('Unsupported U1:TG=%s', personality.fp_u1['TG'])
        delta_ttl = ttl - path
        if delta_ttl < 1:
            logger.debug('Reply packet dropped: TTL reached 0 within virtual network.')
            return None
        reply_ip.set_ip_ttl(delta_ttl)

        # check UN
        un = 0
        delta_un = 0
        index = 0
        if 'UN' in personality.fp_u1:
            if personality.fp_u1['UN'].startswith('>'):
                delta_un = 1
                index = 1
            elif personality.fp_u1['UN'].startswith('<'):
                delta_un = -1
                index = 1
            try:
                un = int(personality.fp_u1['UN'][index:], 16)
                un += delta_un
            except BaseException:
                raise Exception('Unsupported U1:UN=%s', personality.fp_u1['UN'])
        reply_icmp.set_icmp_void(un)

        # check RIPL
        ripl = 0x148
        if 'RIPL' in personality.fp_u1:
            if personality.fp_u1['RIPL'] != 'G':
                try:
                    ripl = int(personality.fp_u1['RIPL'], 16)
                except BaseException:
                    raise Exception('Unsupported U1:RIPL=%s', personality.fp_u1['RIPL'])
        inner_ip.set_ip_len(ripl)

        # check RID
        rid = 0x1042
        if 'RID' in personality.fp_u1:
            if personality.fp_u1['RID'] != 'G':
                try:
                    rid = int(personality.fp_u1['RID'], 16)
                except BaseException:
                    raise Exception('Unsupported U1:RID=%s', personality.fp_u1['RID'])
        inner_ip.set_ip_id(rid)

        # check RIPCK
        if 'RIPCK' in personality.fp_u1:
            if personality.fp_u1['RIPCK'] == 'I':
                valid_chksum = packet.get_ip_sum()
                inner_ip.set_ip_sum(valid_chksum + 256)
            elif personality.fp_u1['RIPCK'] == 'Z':
                inner_ip.set_ip_sum(0)
            elif personality.fp_u1['RIPCK'] == 'G':
                # leave it as original
                pass
            else:
                raise Exception('Unsupported U1:RIPCK=%s', personality.fp_u1['RIPCK'])

        # check RUCK
        if 'RUCK' in personality.fp_u1:
            try:
                ruck = int(personality.fp_u1['RUCK'], 16)
                inner_udp.set_uh_sum(ruck)
            except BaseException:
                # leave it as original
                pass

        # check RUD
        # data_len = udp_packet.get_uh_ulen() - udp_packet.get_header_size()
        if 'RUD' in personality.fp_u1:
            if personality.fp_u1['RUD'] == 'I':
                inner_udp.contains('G' * udp_packet.get_uh_ulen())
            elif personality.fp_u1['RUD'] == 'G':
                inner_udp.contains(ImpactPacket.Data(data))
                # truncated to zero OR copy original datagram => 'C'*data_len (0x43)
            else:
                raise Exception('Unsupported U1:RUD=%s', personality.fp_u1['RUD'])

        # check IPL
        if 'IPL' in personality.fp_u1:
            try:
                ipl = int(personality.fp_u1['IPL'], 16)
                reply_ip.set_ip_len(ipl)
                inner_ip.contains(inner_udp)
                reply_icmp.contains(inner_ip)
            except BaseException:
                raise Exception('Unsupported U1:IPL=%s', personality.fp_u1['IPL'])

        reply_icmp.calculate_checksum()
        reply_ip.contains(reply_icmp)

        return reply_ip

    def filtered(self, packet, path, personality, **kwargs):
        """Function defines filtered port behavior - filtered is defined according to nmap"""
        callback_ipid = kwargs.get('cb_ipid', None)
        # respond with ICMP error type 3 code 13 OR ignore
        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ImpactPacket.ICMP.ICMP_UNREACH)
        reply_icmp.set_icmp_code(ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB)
        reply_icmp.set_icmp_void(0)
        reply_icmp.set_icmp_id(0)
        reply_icmp.set_icmp_seq(0)
        hdr = None
        l = packet.get_ip_len()
        if l > 1472: # 1500 - 20 - 8 (MTU - IP - ICMP)
            hdr = packet.get_packet()[:1472]
        else:
            hdr = packet.get_packet()
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
        reply_ip.set_ip_src(packet.get_ip_dst())
        reply_ip.set_ip_dst(packet.get_ip_src())
        reply_ip.set_ip_id(callback_ipid())
        # check T
        ttl = 0x7f
        if 'T' in personality.fp_ie:
            try:
                ttl = personality.fp_ie['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except BaseException:
                raise Exception('Unsupported IE:T=%s', personality.fp_ie['T'])

        # check TG
        if 'TG' in personality.fp_ie:
            try:
                ttl = int(personality.fp_ie['TG'], 16)
            except BaseException:
                raise Exception('Unsupported IE:TG=%s', personality.fp_ie['TG'])

        delta_ttl = ttl - path
        if delta_ttl < 1:
            logger.debug('Reply packet dropped: TTL reached 0 within virtual network.')
            return None
        reply_ip.set_ip_ttl(delta_ttl)
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_icmp)

        return reply_ip

    def blocked(self, packet, path, personality, **kwargs):
        """Function defines blocked port behavior - no response is created for blocked ports"""
        return None
