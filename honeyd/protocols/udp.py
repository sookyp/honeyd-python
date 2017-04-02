#!/usr/bin/env python

from impacket import ImpactPacket

class UDPHandler(object):
    def opened(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # ignore UDP datagram OR send rUDP
        udp_pkt = pkt.child()
        # udp datagram
        reply_udp = ImpactPacket.UDP()
        reply_udp.set_uh_sport(udp_pkt.get_uh_dport())
        reply_udp.set_uh_dport(udp_pkt.get_uh_sport())
        reply_udp.auto_checksum = 1
        reply_udp.calculate_checksum()

        # ip packet
        reply_ip = ImpactPacket.IP()
        reply_ip.set_ip_v(4)
        reply_ip.set_ip_p(17)
        reply_ip.set_ip_rf(False)
        reply_ip.set_ip_df(False)
        reply_ip.set_ip_mf(False)
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.set_ip_id(cb_ip_id())
        ttl = 64 # TODO: get from fingerprint ?
        delta_ttl = len(path)
        reply_ip.set_ip_ttl(ttl-delta_ttl)
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_udp)

        return reply_ip
    
    def closed(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # respond with ICMP error type 3 code 3
        # check R
        if personality.fp_u1.has_key('R'):
            if personality.fp_u1['R'] == 'N':
                return None

        udp_pkt = pkt.child()
        
        # inner udp datagram
        # duplicate incoming UDP header
        inner_udp = ImpactPacket.UDP()
        inner_udp.set_uh_sport(udp_pkt.get_uh_sport())
        inner_udp.set_uh_dport(udp_pkt.get_uh_dport())
        inner_udp.set_uh_ulen(udp_pkt.get_uh_ulen())
        inner_udp.set_uh_sum(udp_pkt.get_uh_sum())
        inner_udp.auto_checksum = 0
        data = udp_pkt.get_packet()
        data = data[udp_pkt.get_header_size():] # [8:]

        # inner ip packet
        # duplicate incoming IP header
        inner_ip = ImpactPacket.IP()
        inner_ip.set_ip_v(pkt.get_ip_v())
        inner_ip.set_ip_hl(pkt.get_ip_hl())
        inner_ip.set_ip_tos(pkt.get_ip_tos())
        inner_ip.set_ip_len(pkt.get_ip_len())
        inner_ip.set_ip_p(pkt.get_ip_p())
        inner_ip.set_ip_off(pkt.get_ip_off())
        inner_ip.set_ip_offmask(pkt.get_ip_offmask())
        inner_ip.set_ip_rf(pkt.get_ip_rf())
        inner_ip.set_ip_df(pkt.get_ip_df())
        inner_ip.set_ip_mf(pkt.get_ip_mf())
        inner_ip.set_ip_src(pkt.get_ip_src())
        inner_ip.set_ip_dst(pkt.get_ip_dst())
        inner_ip.set_ip_id(pkt.get_ip_id())
        inner_ip.set_ip_ttl(pkt.get_ip_ttl())
        inner_ip.set_ip_sum(pkt.get_ip_sum())
        inner_ip.auto_checksum = 0


        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ImpactPacket.ICMP.ICMP_UNREACH)
        reply_icmp.set_icmp_code(ImpactPacket.ICMP.ICMP_UNREACH_PORT)
        # reply_icmp.set_icmp_void(0)
        reply_icmp.set_icmp_id(0) # unused field
        reply_icmp.set_icmp_seq(0) # unused filed
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
        reply_ip.set_ip_id(cb_cip_id())
        reply_ip.auto_checksum = 1
       
        # check DF
        if personality.fp_u1.has_key('DF'):
            if personality.fp_u1['DF'] == 'N':
                reply_ip.set_ip_df(False)
            elif personality.fp_u1['DF'] == 'Y':
                reply_ip.set_ip_df(True)
            else:
                raise Exception('Unsupported U1:DF=%s', personality.fp_u1['DF'])

        # check T
        ttl = 0x7f
        if personality.fp_u1.has_key('T'):
            try:
                ttl = personality.fp_u1['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except:
                raise Exception('Unsupported U1:T=%s', personality.fp_u1['T'])

        # check TG
        if personality.fp_u1.has_key('TG'):
            try:
                ttl = int(personality.fp_u1['TG'], 16)
            except:
                raise Exception('Unsupported U1:TG=%s', personality.fp_u1['TG'])
        # TODO: update TTL according to path length
        delta_ttl = len(path)
        reply_ip.set_ip_ttl(ttl-delta_ttl)

        # check UN
        un = 0
        delta_un = 0
        index = 0
        if personality.fp_u1.has_key('UN'):
            if personality.fp_u1['UN'].startswith('>'):
                delta_un = 1
                index = 1
            elif personality.fp_u1['UN'].startswith('<'):
                delta_un = -1
                index = 1
            try:
                un = int(personality.fp_u1['UN'][index:], 16)
                un += delta_un
            except:
                raise Exception('Unsupported U1:UN=%s', personality.fp_u1['UN'])
        reply_icmp.set_icmp_void(un)

        # check RIPL
        ripl = 0x148
        if personality.fp_u1.has_key('RIPL'):
            if personality.fp_u1['RIPL'] != 'G':
                try:
                    ripl = int(personality.fp_u1['RIPL'], 16)
                except:
                    raise Exception('Unsupported U1:RIPL=%s', personality.fp_u1['RIPL'])
        inner_ip.set_ip_len(ripl)

        # check RID
        rid = 0x1042
        if personality.fp_u1.has_key('RID'):
            if personality.fp_u1['RID'] != 'G':
                try:
                    rid = int(personality.fp_u1['RID'], 16)
                except:
                    raise Exception('Unsupported U1:RID=%s', personality.fp_u1['RID'])
        inner_ip.set_ip_id(rid)

        # check RIPCK
        if personality.fp_u1.has_key('RIPCK'):
            if personality.fp_u1['RIPCK'] == 'I':
                valid_chksum = pkt.get_ip_sum()
                inner_ip.set_ip_sum(valid_chksum + 256)
            elif personality.fp_u1['RIPCK'] == 'Z':
                inner_ip.set_ip_sum(0)
            elif personality.fp_u1['RIPCK'] == 'G':
                # leave it as original
                pass
            else:
               raise Exception('Unsupported U1:RIPCK=%s', personality.fp_u1['RIPCK'])

        # check RUCK
        if personality.fp_u1.has_key('RUCK'):
            try:
                ruck = int(personality.fp_u1['RUCK'], 16)
                inner_udp.set_uh_sum(ruck)
            except:
                # leave it as original
                pass

        # check RUD
        # data_len = udp_pkt.get_uh_ulen() - udp_pkt.get_header_size()
        if personality.fp_u1.has_key('RUD'):
            if personality.fp_u1['RUD'] == 'I':
                inner_udp.contains('G'*udp_pkt.get_uh_ulen())
            elif personality.fp_u1['RUD'] == 'G':
                inner_udp.contains(ImpactPacket.Data(data))
                # truncated to zero OR copy original datagram => 'C'*data_len (0x43)
            else:
                raise Exception('Unsupported U1:RUD=%s', personality.fp_u1['RUD'])

        # check IPL
        if personality.fp_u1.has_key('IPL'):
            try:
                ipl = int(personality.fp_u1['IPL'], 16)
                reply_ip.set_ip_len(ipl)

                inner_ip.contains(inner_udp)
                """
                content = inner_ip.get_packet()

                reply_icmp_len = reply_icmp.get_size()
                reply_ip_len = reply_ip.get_size()
                content = content[:ipl - (reply_ip_len + reply_icmp_len)]
                content += '\x00'*(ipl - len(content) - (reply_ip_len + reply_icmp_len))
                reply_icmp.contains(ImpactPacket.Data(content))
                """
                reply_icmp.contains(inner_ip)
            except:
                raise Exception('Unsupported U1:IPL=%s', personality.fp_u1['IPL'])

        reply_icmp.calculate_checksum()
        reply_ip.contains(reply_icmp)

        return reply_ip

    def filtered(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # respond with ICMP error type 3 code 13 OR ignore
        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ImpactPacket.ICMP.ICMP_UNREACH)
        reply_icmp.set_icmp_code(ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB)
        reply_icmp.set_icmp_void(0)
        reply_icmp.set_icmp_id(0)
        reply_icmp.set_icmp_seq(0)
        hdr = pkt.get_packet()
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
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.set_ip_id(cb_ip_id())
        ttl = 64 # TODO: get from fingerprint ?
        delta_ttl = len(path)
        reply_ip.set_ip_ttl(ttl-delta_ttl)
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_icmp)

        return reply_ip

    def blocked(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        return None
