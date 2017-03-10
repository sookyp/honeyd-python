#!/usr/bin/env python

import impacket

# TODO: create proper packets
class ICMPHandler(Protocol):
    type_filter = { impacket.ImpactPacket.ICMP.ICMP_ECHO : impacket.ImpactPacket.ICMP.ICMP_ECHOREPLY,
                    impacket.ImpactPacket.ICMP.ICMP_IREQ : impacket.ImpactPacket.ICMP.ICMP_IREQREPLY,
                    impacket.ImpactPacket.ICMP.ICMP_MASKREQ : impacket.ImpactPacket.ICMP.ICMP_MASKREPLY,
                    impacket.ImpactPacket.ICMP.ICMP_TSTAMP : impacket.ImpactPacket.ICMP.ICMP_TSTAMPREPLY }
    # TODO: seq and id generation
    ip_id = 0
    icmp_id = 0

    ip_seq = 0
    icmp_seq = 0

    def opened(self, pkt, path, personality):
        # create reply packets
        reply_icmp = impacket.ImpactPacket.ICMP()
        reply_ip = impacket.ImpactPacket.IP()

        icmp_pkt = pkt.child()
        if icmp_pkt.get_icmp_type() not in type_filter.keys():
            # ignore packet
            return None

        # TODO: set other fields needed
        reply_icmp.set_icmp_type(type_filter[icmp_pkt.get_icmp_type()])
        reply_icmp.set_icmp_seq(icmp_pkt.get_icmp_seq())
        reply_icmp.set_icmp_tos(icmp_pkt.get_icmp_tos())

        # ICMP ECHO REPLY
        if icmp_pkt.get_icmp_type() == impacket.ImpactPacket.ICMP.ICMP_ECHO:
            # TODO: special log if nmap scan is assumed ?
            """
            # nmap probe 1
            if is_nmap_icmp_echo_probe_1(pkt):
                pass
            # nmap probe 2
            if is_nmap_icmp_echo_probe_2(pkt):
                pass
            """
            # check R
            if personality.fp_ie.has_key('R'):
                if personality.fp_ie['R'] == 'N':
                    return None

            # check DFI
            if personality.fp_ie.has_key('DFI'):
                if personality.fp_ie['DFI'] == 'N':
                    reply_ip.set_ip_df(False)
                elif personality.fp_ie['DFI'] == 'T':
                    reply_ip.set_ip_df(True)
                elif personality.fp_ie['DFI'] == 'S':
                    reply_ip.set_ip_df(pkt.get_ip_df())
                elif personality.fp_ie['DFI'] == 'O':
                    reply_ip.set_ip_df(not pkt.get_ip_df())
                else:
                    # TODO: raise Exception()
                    pass

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
                        # TODO: raise Exception()
                        pass
            # check T
            ttl = 0x7f
            if personality.fp_ie.has_key('T'):
                try:
                    ttl = personality.fp_ie['T'].split('-')
                    # using minimum ttl
                    ttl = int(ttl[0], 16)
                except:
                    # TODO: raise Exception()
                    pass

            # check TG
            if personality.fp_ie.has_key('TG'):
                try:
                    ttl = int(personality.fp_ie['TG'], 16)
                except:
                    # TODO: raise Exception()
                    pass
            # TODO: update TTL according to path length
            delta_ttl = len(path)
            reply_ip.set_ip_ttl(ttl)

            # include ICMP ECHO data
            data = icmp_pkt.child()
            if len(data):
                reply_icmp.contains(data)
            reply_ip.set_ip_src(pkt.get_ip_dst())
            reply_ip.set_ip_dst(pkt.get_ip_src())
            reply_ip.contains(reply_icmp)
            return reply_ip

        # ICMP IRQ REPLY
        elif icmp_pkt.get_icmp_type() == impacket.ImpactPacket.ICMP.ICMP_IREQ:
            pass

        # ICMP MASK REPLY
        elif icmp_pkt.get_icmp_type() == impacket.ImpactPacket.ICMP.ICMP_MASKREQ:
            pass

        # ICMP TSTAMP REPLY
        elif icmp_pkt.get_icmp_type() == impacket.ImpactPacket.ICMP.ICMP_TSTAMP:
            pass

        # TODO: encapsulate into ethernet frame if needed
        return reply_ip

    def closed(self, pkt, path, personality):
        # ICMP closed is ignored
        return None

    def filtered(self, pkt, path, personality):
        # ICMP filtered is ignored
        return None

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
        if icmp.get_icmp_seq() != icmp_seq + 1:
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
