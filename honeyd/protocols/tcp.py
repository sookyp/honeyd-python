#!/usr/bin/env python

import random

from binascii import crc32
from struct import pack
from impacket import ImpactPacket

class TCPHandler(object):

    def opened(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        tcp_pkt = pkt.child()
        tcp_win = tcp_pkt.get_th_win()

        if tcp_pkt.get_th_flags() == 2: # (SYN)2
            if personality.fp_ti['T1'].has_key('R'):
                if personality.fp_ti['T1']['R'] == 'N':
                    return None
                if tcp_win == 1:
                    # packet 1
                    personality.fp_ti['T1']['W'] = personality.fp_win['W1']
                    personality.fp_ti['T1']['O'] = personality.fp_ops['O1']
                elif tcp_win == 63:
                    # packet 2
                    personality.fp_ti['T1']['W'] = personality.fp_win['W2']
                    personality.fp_ti['T1']['O'] = personality.fp_ops['O2']
                elif tcp_win == 4:
                    # packet 4
                    personality.fp_ti['T1']['W'] = personality.fp_win['W4']
                    personality.fp_ti['T1']['O'] = personality.fp_ops['O4']
                    # packet 3
                    for opt in tcp_pkt.get_options():
                        if opt.get_kind() == ImpactPacket.TCPOption.TCPOPT_MAXSEG:
                            if opt.get_mss() == 640:
                                # in case of match we overwrite the values
                                personality.fp_ti['T1']['W'] = personality.fp_win['W3']
                                personality.fp_ti['T1']['O'] = personality.fp_ops['O3']
                                break
                elif tcp_win == 16:
                    # packet 5
                    personality.fp_ti['T1']['W'] = personality.fp_win['W5']
                    personality.fp_ti['T1']['O'] = personality.fp_ops['O5']
                elif tcp_win == 512:
                    # packet 6
                    personality.fp_ti['T1']['W'] = personality.fp_win['W6']
                    personality.fp_ti['T1']['O'] = personality.fp_ops['O6']
                else:
                    # SYN scan - TODO provide same as T1
                    personality.fp_ti['T1']['W'] = personality.fp_win['W1']
                    personality.fp_ti['T1']['O'] = personality.fp_ops['O1']
                reply_ip = self.build_reply(pkt, path, personality.fp_ti['T1'], cb_ip_id, cb_tcp_seq, cb_tcp_ts)
                return reply_ip

        elif tcp_pkt.get_th_flags() == 0: # (NULL)0
            if pkt.get_ip_df() and tcp_win == 128:
                # T2
                if personality.fp_ti['T2'].has_key('R'):
                    if personality.fp_ti['T2']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T2'], cb_ip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip
            else:
                # NULL scan
                return None

        elif tcp_pkt.get_th_flags() == 43: # (SYN)2 + (FIN)1 + (URG)32 + (PSH)8
            if (not pkt.get_ip_df()) and tcp_win == 256:
                # T3
                if personality.fp_ti['T3'].has_key('R'):
                    if personality.fp_ti['T3']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T3'], cb_ip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip
            else:
                return None

        elif tcp_pkt.get_th_flags() == 16: # (ACK)16
            if pkt.get_ip_df() and tcp_win == 1024:
            # T4
                if personality.fp_ti['T4'].has_key('R'):
                    if personality.fp_ti['T4']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T4'], cb_ip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip
            else:
                # provide same response - TODO
                if personality.fp_ti['T4'].has_key('R'):
                    if personality.fp_ti['T4']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T4'], cb_ip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip
                """
                # WIN scan -> RST response window size positive
                ip_id = cb_ip_id()
                tcp_seq = cb_tcp_seq()
                reply_ip = self.build_rst(pkt, path, 127, ip_id, tcp_seq)
                return reply_ip
                """

        elif tcp_pkt.get_th_flags() == 194: # (SYN)2 + (ECE)64 + (CWR)128
            # ECN
            if personality.fp_ecn.has_key('R'):
                if personality.fp_ecn['R'] == 'N':
                    return None
                reply_ip = self.build_reply(pkt, path, personality.fp_ecn, cb_ip_id, cb_tcp_seq, cb_tcp_ts)
                return reply_ip
        else:
            # NULL(flags=0) / FIN(flags=1) / XMAS(flags=41) scan
            return None

    def closed(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        tcp_pkt = pkt.child()
        tcp_win = tcp_pkt.get_th_win()
        
        if tcp_pkt.get_th_flags() == 2: # (SYN)2
            if (not pkt.get_ip_df()) and tcp_win == 31337:
                # T5
                if personality.fp_ti['T5'].has_key('R'):
                    if personality.fp_ti['T5']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T5'], cb_cip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip
            else:
                # provide same response - TODO
                if personality.fp_ti['T5'].has_key('R'):
                    if personality.fp_ti['T5']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T5'], cb_cip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip

        elif tcp_pkt.get_th_flags() == 16: # (ACK)16
            if pkt.get_ip_df() and tcp_win == 32768:
                # T6
                if personality.fp_ti['T6'].has_key('R'):
                    if personality.fp_ti['T6']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T6'], cb_cip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip
            else:
                # provide same response - TODO
                if personality.fp_ti['T6'].has_key('R'):
                    if personality.fp_ti['T6']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T6'], cb_cip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip

        elif tcp_pkt.get_th_flags() == 41: # (FIN)1 + (PHS)8 + (URG)32
            if (not pkt.get_ip_df()) and tcp_win == 65535:
                # T7
                if personality.fp_ti['T7'].has_key('R'):
                    if personality.fp_ti['T7']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T7'], cb_cip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip
            else:
                # provide same response - TODO
                if personality.fp_ti['T7'].has_key('R'):
                    if personality.fp_ti['T7']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(pkt, path, personality.fp_ti['T7'], cb_cip_id, cb_tcp_seq, cb_tcp_ts)
                    return reply_ip

        # RST default
        # SYN(flags=2) / ACK(flags=16) / XMAS(flags=41) / FIN(flags=1) / NULL(flags=0) scan
        ip_id = cb_cip_id()
        tcp_seq = cb_tcp_seq()
        reply_ip = self.build_rst(pkt, path, 0, ip_id, tcp_seq)
        return reply_ip

    def filtered(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        # respond with ICMP error type 3 code 13 OR ignore
        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ImpactPacket.ICMP.ICMP_UNREACH)
        reply_icmp.set_icmp_code(ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB)
        reply_icmp.set_icmp_id(cb_icmp_id()) # unused field
        reply_icmp.set_icmp_seq(0) # unused field
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
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_icmp)

        return reply_ip

    def blocked(self, pkt, path, personality, cb_ip_id=None, cb_cip_id=None, cb_icmp_id=None, cb_tcp_seq=None, cb_tcp_ts=None):
        return None

    def build_reply(self, pkt, path, personality, cb_ip_id, cb_tcp_seq, cb_tcp_ts):
        # fingerprint fields R, DF, T, TG, W, S, A, F, O, RD, Q & CC

        # tcp packet
        tcp_pkt = pkt.child()
        reply_tcp = ImpactPacket.TCP()
        reply_tcp.set_th_sport(tcp_pkt.get_th_dport())
        reply_tcp.set_th_dport(tcp_pkt.get_th_sport())
        reply_tcp.set_th_flags(0)
        reply_tcp.auto_checksum = 1

        # ip packet
        reply_ip = ImpactPacket.IP()
        reply_ip.set_ip_v(4)
        reply_ip.set_ip_p(6)
        reply_ip.set_ip_rf(False)
        reply_ip.set_ip_df(False)
        reply_ip.set_ip_mf(False)
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.set_ip_id(cb_ip_id()) # TODO ?
        reply_ip.auto_checksum = 1

        # check DF
        if personality.has_key('DF'):
            if personality['DF'] == 'N':
                reply_ip.set_ip_df(False)
            elif personality['DF'] == 'Y':
                reply_ip.set_ip_df(True)
            else:
                raise Exception('Unsupported Ti:DF=%s', personality['DF'])

        # check T
        ttl = 0x7f
        if personality.has_key('T'):
            try:
                ttl = personality['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except:
                raise Exception('Unsupported Ti:T=%s', personality['T'])

        # check TG
        if personality.has_key('TG'):
            try:
                ttl = int(personality['TG'], 16)
            except:
                raise Exception('Unsupported Ti:TG=%s', personality['TG'])

        delta_ttl = len(path)
        reply_ip.set_ip_ttl(ttl-delta_ttl)

        # check W
        win = 0
        if personality.has_key('W'):
            try:
                win = int(personality['W'], 16)
            except:
                raise Exception('Unsupported Ti:W=%s', personality['W'])
        reply_tcp.set_th_win(win)

        # check CC
        if personality.has_key('CC'):
            if personality['CC'] == 'N':
                reply_tcp.reset_ECE()
                reply_tcp.reset_CWR()
            elif personality['CC'] == 'Y':
                reply_tcp.set_ECE()
                reply_tcp.reset_CWR()
            elif personality['CC'] == 'S':
                reply_tcp.set_ECE()
                reply_tcp.set_CWR()
            elif personality['CC'] == 'O':
                reply_tcp.reset_ECE()
                reply_tcp.set_CWR()

        # check S
        if personality.has_key('S'):
            if personality['S'] == 'Z':
                reply_tcp.set_th_seq(0)
            elif personality['S'] == 'A':
                reply_tcp.set_th_seq(tcp_pkt.get_th_ack())
            elif personality['S'] == 'A+':
                reply_tcp.set_th_seq(tcp_pkt.get_th_ack() + 1)
            elif personality['S'] == 'O':
                seq = cb_tcp_seq()
                reply_tcp.set_th_seq(seq)
            else:
                raise Exception('Unsupported Ti:S=%s', personality['S'])

        # check A
        if personality.has_key('A'):
            if personality['A'] == 'Z':
                reply_tcp.set_th_ack(0)
            elif personality['A'] == 'S':
                reply_tcp.set_th_ack(tcp_pkt.get_th_seq())
            elif personality['A'] == 'S+':
                reply_tcp.set_th_ack(tcp_pkt.get_th_seq() + 1)
            elif personality['A'] == 'O':
                temp = random.randint(1, 10)
                reply_tcp.set_th_ack(temp)
            else:
                try:
                    temp = int(personality['A'], 16)
                    reply_tcp.set_th_ack(temp)
                except:
                    raise Exception('Unsupported Ti:A=%s', personality['A'])

        # check O
        if personality.has_key('O'):
            options = personality['O']
            i = 0
            while i < len(options):
                opt = options[i]
                i += 1
                if opt == 'L':
                    reply_tcp.add_option(ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_EOL))
                if opt == 'N':
                    reply_tcp.add_option(ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_NOP))
                if opt == 'S':
                    reply_tcp.add_option(ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED))
                if opt == 'T':
                    opt = ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_TIMESTAMP)
                    if options[i] == '1':
                        ts = cb_tcp_ts()
                        opt.set_ts(ts)
                    if options[i+1] == '1':
                        opt.set_ts_echo(0xffffffff)
                    reply_tcp.add_option(opt)
                    i += 2
                if opt == 'M':
                    maxseg, i = self.get_value(options, i)
                    reply_tcp.add_option(ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_MAXSEG, maxseg))
                if opt == 'W':
                    window, i = self.get_value(options, i)
                    reply_tcp.add_option(ImpactPacket.TCPOption(ImpactPacket.TCPOption.TCPOPT_WINDOW, window))

        # check F
        if personality.has_key('F'):
            if 'E' in personality['F']:
                reply_tcp.set_ECE()
            if 'U' in personality['F']:
                reply_tcp.set_URG()
            if 'A' in personality['F']:
                reply_tcp.set_ACK()
            if 'P' in personality['F']:
                reply_tcp.set_PSH()
            if 'R' in personality['F']:
                reply_tcp.set_RST()
            if 'S' in personality['F']:
                reply_tcp.set_SYN()
            if 'F' in personality['F']:
                reply_tcp.set_FIN()

        # check Q
        if personality.has_key('Q'):
            if 'R' in personality['Q']:
                reply_tcp.set_flags(0x800)
            if 'U' in personality['Q']:
                reply_tcp.set_th_urp(0xffff)

        # check RD
        if personality.has_key('RD'):
            try:
                crc = int(personality['RD'], 16)
                if crc != 0:
                    data = 'TCP Port is closed\x00'
                    data += self.compensate(data, crc)
                    data = ImpactPacket.Data(data)
                    reply_tcp.contains(data)
            except:
                raise Exception('Unsupported Ti:RD=%s', personality['RD'])

        reply_tcp.calculate_checksum()
        reply_ip.contains(reply_tcp)
        return reply_ip

    def compensate(b, w):
        w ^= 0xffffffff
        nb = 0
        for i in range(32):
            if nb & 1:
                nb >>= 1
                nb ^= 0xedb88320
            else:
                nb >>= 1
            if w & 1:
                nb ^= 0x5b358fd3
            w >>= 1
        nb ^= crc32(b) ^ 0xffffffff
        return pack('<L', nb)

    def build_rst(self, pkt, path, win, ip_id, tcp_seq):
        tcp_pkt = pkt.child()

        # tcp packet
        reply_tcp = ImpactPacket.TCP()
        reply_tcp.set_th_sport(tcp_pkt.get_th_dport())
        reply_tcp.set_th_dport(tcp_pkt.get_th_sport())
        # reply_tcp.set_th_flags(20) # RST + ACK
        reply_tcp.set_RST()
        reply_tcp.set_ACK()
        reply_tcp.set_th_ack(tcp_pkt.get_th_seq() + 1)
        reply_tcp.set_th_seq(tcp_seq)
        reply_tcp.set_th_win(win)
        reply_tcp.auto_checksum = 1
        reply_tcp.calculate_checksum()

        # ip packet
        reply_ip = ImpactPacket.IP()
        reply_ip.set_ip_v(4)
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_rf(True)
        reply_ip.set_ip_df(False)
        reply_ip.set_ip_mf(False)
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.set_ip_id(ip_id) # TODO 
        ttl = 64 # TODO: get from fingerprint ?
        delta_ttl = len(path)
        reply_ip.set_ip_ttl(ttl-delta_ttl)
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_tcp)

        return reply_ip

    def get_value(self, o, i):
        v = 0
        idx = i
        for c in o[i:]:
            try:
                v = v * 0x10 + int(c, 16)
            except:
                break
            idx += 1
        return v, idx
