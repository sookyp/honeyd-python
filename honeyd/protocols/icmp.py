#!/usr/bin/env python

from datetime import datetime, time
from impacket import ImpactPacket

# TODO: create proper packets
class ICMPHandler(object):
    def opened(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # create reply packets
        type_filter = { ImpactPacket.ICMP.ICMP_ECHO : ImpactPacket.ICMP.ICMP_ECHOREPLY,
                        ImpactPacket.ICMP.ICMP_IREQ : ImpactPacket.ICMP.ICMP_IREQREPLY,
                        ImpactPacket.ICMP.ICMP_MASKREQ : ImpactPacket.ICMP.ICMP_MASKREPLY,
                        ImpactPacket.ICMP.ICMP_TSTAMP : ImpactPacket.ICMP.ICMP_TSTAMPREPLY }

        icmp_pkt = pkt.child()
        if icmp_pkt.get_icmp_type() not in type_filter.keys():
            # ignore packet
            return None

        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(type_filter[icmp_pkt.get_icmp_type()])
        reply_icmp.set_icmp_code(0)
        reply_icmp.set_icmp_id(icmp_pkt.get_icmp_id())
        reply_icmp.set_icmp_seq(icmp_pkt.get_icmp_seq())
        reply_icmp.auto_checksum = 1

        # ip packet
        reply_ip = ImpactPacket.IP()
        reply_ip.set_ip_v(4)
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_rf(False)
        reply_ip.set_ip_df(False)
        reply_ip.set_ip_mf(False)
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.set_ip_id(cb_ip_id())
        reply_ip.auto_checksum = 1

        # ICMP ECHO REPLY
        if icmp_pkt.get_icmp_type() == ImpactPacket.ICMP.ICMP_ECHO:
            # check R
            if personality.fp_ie.has_key('R'):
                if personality.fp_ie['R'] == 'N':
                    return None

            # check DFI
            if personality.fp_ie.has_key('DFI'):
                if personality.fp_ie['DFI'] == 'N':
                    reply_ip.set_ip_df(False)
                elif personality.fp_ie['DFI'] == 'Y':
                    reply_ip.set_ip_df(True)
                elif personality.fp_ie['DFI'] == 'S':
                    reply_ip.set_ip_df(pkt.get_ip_df())
                elif personality.fp_ie['DFI'] == 'O':
                    reply_ip.set_ip_df(not pkt.get_ip_df())
                else:
                    raise Exception('Unsupported IE:DFI=%s', personality.fp_ie['DFI'])

            # check CD
            if personality.fp_ie.has_key('CD'):
                if personality.fp_ie['CD'] == 'Z':
                    reply_icmp.set_icmp_code(0)
                elif personality.fp_ie['CD'] == 'S':
                    reply_icmp.set_icmp_code(icmp_pkt.get_icmp_code())
                elif personality.fp_ie['CD'] == 'O':
                    reply_icmp.set_icmp_code(icmp_pkt.get_icmp_code() + 1)
                else:
                    try:
                        reply_icmp.set_icmp_code(int(personality.fp_ie['CD'], 16))
                    except:
                        raise Exception('Unsupported IE:CD=%s', personality.fp_ie['CD'])

            # check T
            ttl = 0x7f
            if personality.fp_ie.has_key('T'):
                try:
                    ttl = personality.fp_ie['T'].split('-')
                    # using minimum ttl
                    ttl = int(ttl[0], 16)
                except:
                    raise Exception('Unsupported IE:T=%s', personality.fp_ie['T'])

            # check TG
            if personality.fp_ie.has_key('TG'):
                try:
                    ttl = int(personality.fp_ie['TG'], 16)
                except:
                    raise Exception('Unsupported IE:TG=%s', personality.fp_ie['TG'])

            delta_ttl = len(path)
            reply_ip.set_ip_ttl(ttl-delta_ttl)

            # include ICMP ECHO data
            data = icmp_pkt.child()
            if data.get_size():
                reply_icmp.contains(data)
            reply_icmp.calculate_checksum()
            reply_ip.contains(reply_icmp)
            return reply_ip

        # ICMP IRQ REPLY
        elif icmp_pkt.get_icmp_type() == ImpactPacket.ICMP.ICMP_IREQ:
            # deprecated
            pass

        # ICMP MASK REPLY
        elif icmp_pkt.get_icmp_type() == ImpactPacket.ICMP.ICMP_MASKREQ:
            # netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
            """
            reply_icmp.set_icmp_mask()
            
            ttl = 64
            delta_ttl = len(path)
            reply_ip.set_ip_ttl(ttl-delta_ttl)
            
            reply_icmp.calculate_checksum()
            reply_ip.contains(reply_icmp)
            return reply_ip
            """
            pass

        # ICMP TSTAMP REPLY
        elif icmp_pkt.get_icmp_type() == ImpactPacket.ICMP.ICMP_TSTAMP:
            # original time
            reply_icmp.set_icmp_otime(icmp_pkt.get_icmp_otime())
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
            
            ttl = 64
            delta_ttl = len(path)
            reply_ip.set_ip_ttl(ttl-delta_ttl)
            
            reply_icmp.calculate_checksum()
            reply_ip.contains(reply_icmp)
            return reply_ip

        return reply_ip

    def closed(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # ICMP closed is ignored
        return None

    def filtered(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # ICMP filtered is ignored
        return None

    def blocked(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        return None

