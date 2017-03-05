#!/usr/bin/env python

import impacket

# TODO: create proper packets
class TCPHandler(object):
    def opened(self, pkt, path, personality):
        reply = impacket.ImpactPacket.TCP()
        # TODO
        return reply

    def closed(self, pkt, path, personality):
        # respond with RST with 0 window value
        reply = impacket.ImpactPacket.TCP()
        # TODO
        return reply

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
