#!/usr/bin/env python

import impacket

# TODO: create proper packets
class UDPHandler(object):
    ip_id = 0
    udp_id = 0

    ip_seq = 0
    udp_seq = 0

    def opened(self, pkt, path, personality):
        reply_udp = impacket.ImpactPacket.UDP()
        reply = impacket.ImpactPacket.IP()
        # TODO: send to application
        return reply

    def closed(self, pkt, path, personality):
        # check R
        if personality.fp_u1.has_key('R'):
            if personality.fp_u1['R'] == 'N':
                return None

        # respond with ICMP error type 3 code 3
        reply_icmp = impacket.ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ICMP_UNREACH)
        reply_icmp.set_icmp_code(ICMP_UNREACH_PORT)
        reply_icmp.auto_checksum = 1
        
        reply_udp = impacket.ImpactPacket.UDP()
        reply_udp.auto_checksum = 1

        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_p(1)
        reply_ip.auto_checksum = 1

        # check DF
        if personality.fp_u1.has_key('DF'):
            if personality.fp_u1['DF'] == 'N':
                reply_ip.set_ip_df(False)
            elif personality.fp_u1['DF'] == 'Y':
                reply_ip.set_ip_df(False)
            else:
                # TODO: raise Exception()
                pass        

        # check T
        ttl = 0x7f
        if personality.fp_u1.has_key('T'):
            try:
                ttl = personality.fp_u1['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except:
                # TODO: raise Exception()
                pass

        # check TG
        if personality.fp_u1.has_key('TG'):
            try:
                ttl = int(personality.fp_u1['TG'], 16)
            except:
                # TODO: raise Exception()
                pass
        # TODO: update TTL according to path length
        delta_ttl = len(path)
        reply_ip.set_ip_ttl(ttl)

        # check UN
        un = 0
        if personality.fp_u1.has_key('UN'):
            try:
                un = int(personality.fp_u1['UN'], 16)
            except:
                # raise Exception()
                pass
            reply_icmp.set_icmp_void(un)

        # check RIPL
        if personality.fp_u1.has_key('RIPL'):
            try:
                ripl = int(personality.fp_u1['RIPL'], 16)
            except:
                ripl = 0x148
            reply_ip.set_ip_len(ripl)

        # check RID
        if personality.fp_u1.has_key('RID'):
            try:
                rid = int(personality.fp_u1['RID'], 16)
            except:
                rid = 0x1042
            reply_ip.set_ip_id(rid)

        # TODO: investigate which checksum is needed
        # check RIPCK
        if personality.fp_u1.has_key('RIPCK'):
            if personality.fp_u1['RIPCK'] == 'I':
                reply_ip.set_ip_sum(0)
                reply_icmp.set_icmp_cksum(0)
            elif personality.fp_u1['RIPCK'] == 'Z':
                reply_ip.set_ip_sum(0)
                reply_icmp.set_icmp_cksum(0)
            elif personality.fp_u1['RIPCK'] == 'G':
                reply_ip.auto_checksum = 1
                reply_icmp.auto_checksum = 1
            else:
                # TODO: raise Exception()
                pass

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
                # TODO: raise Exception()
                pass

        # check IPL
        if personality.fp_u1.has_key('IPL'):
            try:
                ipl = int(personality.fp_u1['IPL'], 16)
                
                # TODO: investigate IPL

                
            except:
                # TODO: raise Exception()
                pass

        reply_ip.set_ip_src(pkt.get_ip_dhost())
        reply_ip.set_ip_dst(pkt.get_ip_shost())
        reply_ip.contains(reply_icmp)

        # reply_eth = impacket.ImpactPacket.Ethernet()
        # reply_eth.set_ether_type(0x800)
        # reply_eth.contains(reply_ip)

        return reply_ip

    def filtered(self, pkt, path, personality):
        # respond with ICMP error type 3 code 13
        reply_icmp = impacket.ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ICMP_UNREACH)
        reply_icmp.set_icmp_code(ICMP_UNREACH_FILTERPROHIB)
        reply_icmp.auto_checksum = 1

        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_src(pkt.get_ip_dhost())
        reply_ip.set_ip_dst(pkt.get_ip_shost())
        reply_ip.contains(reply_icmp)

        # reply_eth = impacket.ImpactPacket.Ethernet()
        # reply_eth.set_ether_type(0x800)
        # reply_eth.contains(reply_ip)
        return reply_ip
