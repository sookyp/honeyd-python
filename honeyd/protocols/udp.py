#!/usr/bin/env python

import impacket

# TODO: create proper packets
class UDPHandler(object):
    def opened(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        reply_udp = impacket.ImpactPacket.UDP()
        reply = impacket.ImpactPacket.IP()
        # TODO: send to application
        return reply

    def closed(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # check R
        if personality.fp_u1.has_key('R'):
            if personality.fp_u1['R'] == 'N':
                return None

        # respond with ICMP error type 3 code 3
        reply_icmp = impacket.ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ICMP_UNREACH)
        reply_icmp.set_icmp_code(ICMP_UNREACH_PORT)
        reply_icmp.set_icmp_id(cb_icmp_id())
        reply_icmp.auto_checksum = 1
        
        reply_udp = impacket.ImpactPacket.UDP()
        reply_udp.auto_checksum = 1

        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_id(cb_ip_id())
        reply_ip.set_ip_p(1)
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
        reply_ip.set_ip_ttl(ttl)

        # check UN
        un = 0
        if personality.fp_u1.has_key('UN'):
            try:
                un = int(personality.fp_u1['UN'], 16)
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
        reply_ip.set_ip_len(ripl)

        # check RID
        rid = 0x1042
        if personality.fp_u1.has_key('RID'):
            if personality.fp_u1['RID'] != 'G':
                try:
                    rid = int(personality.fp_u1['RID'], 16)
                except:
                    raise Exception('Unsupported U1:RID=%s', personality.fp_u1['RID'])
        reply_ip.set_ip_id(rid)

        # check RIPCK
        if personality.fp_u1.has_key('RIPCK'):
            if personality.fp_u1['RIPCK'] == 'I':
                reply_ip.set_ip_sum(0x6765)
                # reply_icmp.set_icmp_cksum(0)
            elif personality.fp_u1['RIPCK'] == 'Z':
                reply_ip.set_ip_sum(0)
                # reply_icmp.set_icmp_cksum(0)
            elif personality.fp_u1['RIPCK'] == 'G':
                reply_ip.auto_checksum = 1
                # reply_icmp.auto_checksum = 1
            else:
               raise Exception('Unsupported U1:RIPCK=%s', personality.fp_u1['RIPCK'])

        # check RUCK
        if personality.fp_u1.has_key('RUCK'):
            try:
                ruck = int(personality.fp_u1['RUCK'], 16)
                reply_udp.set_uh_sum(ruck)
            except:
                reply_udp.auto_checksum = 1

        udp_pkt = pkt.child()
        # check RUD
        if personality,fp_u1.has_key('RUD'):
            if personality.fp_u1['RUD'] == 'I':
                reply_udp.set_data('G'*udp_pkt.get_size())
            elif personality.fp_u1['RUD'] == 'G':
                # truncated to zero OR copy original datagram => udp_data.get_size() * 'C'(0x43)
                pass
            else:
                raise Exception('Unsupported U1:RUD=%s', personality.fp_u1['RUD'])

        # check IPL
        if personality.fp_u1.has_key('IPL'):
            try:
                ipl = int(personality.fp_u1['IPL'], 16)

                # TODO: investigate IPL
                data = reply_udp.get_packet()
                reply_icmp.contains(ImpactPacket.Data())
                reply_pkt_len = reply_ip.get_size()
                data = data[:ipl - reply_pkt_len]
                data += '\x00'*(ipl - len(data) - reply_pkt_len)
                reply_icmp.contains(ImpactPacket.Data(data))

            except:
                raise Exception('Unsupported U1:IPL=%s', personality.fp_u1['IPL'])

        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.contains(reply_icmp)

        # reply_eth = impacket.ImpactPacket.Ethernet()
        # reply_eth.set_ether_type(0x800)
        # reply_eth.contains(reply_ip)

        return reply_ip

    def filtered(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # respond with ICMP error type 3 code 13
        reply_icmp = impacket.ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ICMP_UNREACH)
        reply_icmp.set_icmp_code(ICMP_UNREACH_FILTERPROHIB)
        reply_icmp.set_icmp_id(cb_icmp_id())
        reply_icmp.auto_checksum = 1

        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.set_ip_id(cb_ip_id())
        reply_ip.contains(reply_icmp)

        # reply_eth = impacket.ImpactPacket.Ethernet()
        # reply_eth.set_ether_type(0x800)
        # reply_eth.contains(reply_ip)
        return reply_ip
