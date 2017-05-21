#!/usr/bin/env python
"""Icmp.py defines the ICMP behavior"""
import logging
from datetime import datetime, time
from impacket import ImpactPacket

logger = logging.getLogger(__name__)

class ICMPHandler(object):
    """ICMPHandler defines behavior opened, closed, blocked and filtered ports"""

    def opened(self, packet, path, personality, **kwargs):
        """Function defines open port behavior"""
        callback_ipid = kwargs.get('cb_ipid', None)
        # create reply packets
        type_filter = {ImpactPacket.ICMP.ICMP_ECHO: ImpactPacket.ICMP.ICMP_ECHOREPLY,
                       ImpactPacket.ICMP.ICMP_IREQ: ImpactPacket.ICMP.ICMP_IREQREPLY,
                       ImpactPacket.ICMP.ICMP_MASKREQ: ImpactPacket.ICMP.ICMP_MASKREPLY,
                       ImpactPacket.ICMP.ICMP_TSTAMP: ImpactPacket.ICMP.ICMP_TSTAMPREPLY}

        icmp_packet = packet.child()
        if icmp_packet.get_icmp_type() not in type_filter.keys():
            # ignore packet
            return None

        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(type_filter[icmp_packet.get_icmp_type()])
        reply_icmp.set_icmp_code(0)
        reply_icmp.set_icmp_id(icmp_packet.get_icmp_id())
        reply_icmp.set_icmp_seq(icmp_packet.get_icmp_seq())
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
        reply_ip.auto_checksum = 1

        # ICMP ECHO REPLY
        if icmp_packet.get_icmp_type() == ImpactPacket.ICMP.ICMP_ECHO:
            # check R
            if 'R' in personality.fp_ie:
                if personality.fp_ie['R'] == 'N':
                    return None

            # check DFI
            if 'DFI' in personality.fp_ie:
                if personality.fp_ie['DFI'] == 'N':
                    reply_ip.set_ip_df(False)
                elif personality.fp_ie['DFI'] == 'Y':
                    reply_ip.set_ip_df(True)
                elif personality.fp_ie['DFI'] == 'S':
                    reply_ip.set_ip_df(packet.get_ip_df())
                elif personality.fp_ie['DFI'] == 'O':
                    reply_ip.set_ip_df(not packet.get_ip_df())
                else:
                    raise Exception('Unsupported IE:DFI=%s', personality.fp_ie['DFI'])

            # check CD
            if 'CD' in personality.fp_ie:
                if personality.fp_ie['CD'] == 'Z':
                    reply_icmp.set_icmp_code(0)
                elif personality.fp_ie['CD'] == 'S':
                    reply_icmp.set_icmp_code(icmp_packet.get_icmp_code())
                elif personality.fp_ie['CD'] == 'O':
                    reply_icmp.set_icmp_code(icmp_packet.get_icmp_code() + 1)
                else:
                    try:
                        reply_icmp.set_icmp_code(int(personality.fp_ie['CD'], 16))
                    except BaseException:
                        raise Exception('Unsupported IE:CD=%s', personality.fp_ie['CD'])

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

            # include ICMP ECHO data
            data = icmp_packet.child()
            if data.get_size():
                reply_icmp.contains(data)
            reply_icmp.calculate_checksum()
            reply_ip.contains(reply_icmp)

        # ICMP IRQ REPLY
        elif icmp_packet.get_icmp_type() == ImpactPacket.ICMP.ICMP_IREQ:
            # deprecated
            pass

        # ICMP MASK REPLY
        elif icmp_packet.get_icmp_type() == ImpactPacket.ICMP.ICMP_MASKREQ:
            # TODO
            pass

        # ICMP TSTAMP REPLY
        elif icmp_packet.get_icmp_type() == ImpactPacket.ICMP.ICMP_TSTAMP:
            # original time
            reply_icmp.set_icmp_otime(icmp_packet.get_icmp_otime())
            # receive time
            receive_time = datetime.utcnow()
            midnight = datetime.combine(receive_time.date(), time(0))
            delta_receive = receive_time - midnight
            delta_receive = delta_receive.total_seconds() * 1000
            reply_icmp.set_icmp_rtime(delta_receive)
            # transmit time
            transmit_time = datetime.utcnow()
            delta_transmit = transmit_time - midnight
            delta_transmit = delta_transmit.total_seconds() * 1000
            reply_icmp.set_icmp_ttime(delta_transmit)

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

            reply_icmp.calculate_checksum()
            reply_ip.contains(reply_icmp)

        return reply_ip

    def closed(self, packet, path, personality, **kwargs):
        """Function defines closed port behavior"""
        # ICMP closed is ignored
        return None

    def filtered(self, packet, path, personality, **kwargs):
        """Function defines filtered port behavior - filtered is defined according to nmap"""
        # ICMP filtered is ignored
        return None

    def blocked(self, packet, path, personality, **kwargs):
        """Function defines blocked port behavior - no response is created for blocked ports"""
        return None
