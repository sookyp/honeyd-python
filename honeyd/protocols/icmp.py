#!/usr/bin/env python

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
        reply_icmp.set_icmp_id(icmp_pkt.get_icmp_id()) # TODO ? cb_icmp_id
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
            pass

        # ICMP MASK REPLY
        elif icmp_pkt.get_icmp_type() == ImpactPacket.ICMP.ICMP_MASKREQ:
            pass

        # ICMP TSTAMP REPLY
        elif icmp_pkt.get_icmp_type() == ImpactPacket.ICMP.ICMP_TSTAMP:
            pass

        # TODO: encapsulate into ethernet frame if needed
        return reply_ip

    def closed(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # ICMP closed is ignored
        return None

    def filtered(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # ICMP filtered is ignored
        return None

    def blocked(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        return None

    # We won't need these checks
    def is_nmap_icmp_echo_probe_1(pkt):
        # The first one has the IP DF bit set, a type-of-service (TOS)  byte 
        # value of zero, a code of nine (even though it should be zero), 
        # the sequence number 295, a random IP ID and ICMP request identifier, 
        # and a random character repeated 120 times for the data payload.
        if pkt.get_ip_df() is not True:
            return False
        if pkt.get_ip_tos() != 0:
            return False
        icmp = pkt.child()
        if icmp.get_icmp_code() != 9:
            return False
        if icmp.get_icmp_seq() != 295:
            return False

        # TODO: save this for later use
        ip_id = pkt.get_ip_id()
        icmp_id = icmp.get_icmp_id()

        ip_seq = pkt.get_ip_seq()
        icmp_seq = icmp.get_icmp_seq()

        data = icmp.child()
        if data.get_size() != 120:
            # TODO: check all characters are 0x00
            return False
        return True

    def is_nmap_icmp_echo_probe_2(pkt):
        # The second ping query is similar, except a TOS of four 
        # (IP_TOS_RELIABILITY) is used, the code is zero, 150 bytes of data is 
        # sent, and the IP ID, request ID, and sequence numbers are incremented 
        # by one from the previous query values.
        if pkt.get_ip_df() is not False:
            return False
        if pkt.get_ip_tos() != 4:
            return False
        icmp = pkt.child()
        if icmp.get_icmp_code() != 0:
            return False
        if icmp.get_icmp_seq() != 296:
            return False
        if pkt.get_ip_id() != ip_id + 1:
            return False
        if icmp.get_icmp_id() != icmp_id + 1:
            return False
        # TODO: update ids and seqs ?

        data = icmp.child()
        if data.get_size() != 150:
            # TODO: check data
            return False
        return True
