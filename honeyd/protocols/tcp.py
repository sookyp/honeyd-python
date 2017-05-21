#!/usr/bin/env python
"""Tcp.py defines the TCP behavior"""
import logging
import random
from binascii import crc32
from struct import pack
from impacket import ImpactPacket

logger = logging.getLogger(__name__)

class TCPHandler(object):
    """TCPHandler defines behavior opened, closed, blocked and filtered ports"""

    def opened(self, packet, path, personality, **kwargs):
        """Function defines open port behavior"""
        callback_ipid = kwargs.get('cb_ipid', None)
        callback_tcpseq = kwargs.get('cb_tcpseq', None)
        callback_tcpts = kwargs.get('cb_tcpts', None)

        tcp_pkt = packet.child()
        tcp_win = tcp_pkt.get_th_win()

        if tcp_pkt.get_th_flags() == 2:  # (SYN)2
            if 'R' in personality.fp_ti['T1']:
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
                    # SYN scan
                    personality.fp_ti['T1']['W'] = personality.fp_win['W1']
                    personality.fp_ti['T1']['O'] = personality.fp_ops['O1']
                reply_ip = self.build_reply(
                    packet,
                    path,
                    personality.fp_ti['T1'],
                    callback_ipid,
                    callback_tcpseq,
                    callback_tcpts)
                return reply_ip

        elif tcp_pkt.get_th_flags() == 0:  # (NULL)0
            if packet.get_ip_df() and tcp_win == 128:
                # T2
                if 'R' in personality.fp_ti['T2']:
                    if personality.fp_ti['T2']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(
                        packet,
                        path,
                        personality.fp_ti['T2'],
                        callback_ipid,
                        callback_tcpseq,
                        callback_tcpts)
                    return reply_ip
            else:
                # NULL scan
                return None

        elif tcp_pkt.get_th_flags() == 43:  # (SYN)2 + (FIN)1 + (URG)32 + (PSH)8
            if (not packet.get_ip_df()) and tcp_win == 256:
                # T3
                if 'R' in personality.fp_ti['T3']:
                    if personality.fp_ti['T3']['R'] == 'N':
                        return None
                    reply_ip = self.build_reply(
                        packet,
                        path,
                        personality.fp_ti['T3'],
                        callback_ipid,
                        callback_tcpseq,
                        callback_tcpts)
                    return reply_ip
            else:
                return None

        elif tcp_pkt.get_th_flags() == 16:  # (ACK)16
            # if packet.get_ip_df() and tcp_win == 1024:
            # T4
            if 'R' in personality.fp_ti['T4']:
                if personality.fp_ti['T4']['R'] == 'N':
                    return None
                reply_ip = self.build_reply(
                    packet,
                    path,
                    personality.fp_ti['T4'],
                    callback_ipid,
                    callback_tcpseq,
                    callback_tcpts)
                return reply_ip

        elif tcp_pkt.get_th_flags() == 194:  # (SYN)2 + (ECE)64 + (CWR)128
            # ECN
            if 'R' in personality.fp_ecn:
                if personality.fp_ecn['R'] == 'N':
                    return None
                reply_ip = self.build_reply(
                    packet,
                    path,
                    personality.fp_ecn,
                    callback_ipid,
                    callback_tcpseq,
                    callback_tcpts)
                return reply_ip
        else:
            # NULL(flags=0) / FIN(flags=1) / XMAS(flags=41) scan
            return None

    def closed(self, packet, path, personality, **kwargs):
        """Function defines closed port behavior"""
        callback_cipid = kwargs.get('cb_cipid', None)
        callback_tcpseq = kwargs.get('cb_tcpseq', None)
        callback_tcpts = kwargs.get('cb_tcpts', None)

        tcp_pkt = packet.child()
        # tcp_win = tcp_pkt.get_th_win()

        if tcp_pkt.get_th_flags() == 2:  # (SYN)2
            # if (not packet.get_ip_df()) and tcp_win == 31337:
            # T5
            if 'R' in personality.fp_ti['T5']:
                if personality.fp_ti['T5']['R'] == 'N':
                    return None
                reply_ip = self.build_reply(
                    packet,
                    path,
                    personality.fp_ti['T5'],
                    callback_cipid,
                    callback_tcpseq,
                    callback_tcpts)
                return reply_ip

        elif tcp_pkt.get_th_flags() == 16:  # (ACK)16
            # if packet.get_ip_df() and tcp_win == 32768:
            # T6
            if 'R' in personality.fp_ti['T6']:
                if personality.fp_ti['T6']['R'] == 'N':
                    return None
                reply_ip = self.build_reply(
                    packet,
                    path,
                    personality.fp_ti['T6'],
                    callback_cipid,
                    callback_tcpseq,
                    callback_tcpts)
                return reply_ip

        elif tcp_pkt.get_th_flags() == 41:  # (FIN)1 + (PHS)8 + (URG)32
            # if (not packet.get_ip_df()) and tcp_win == 65535:
            # T7
            if 'R' in personality.fp_ti['T7']:
                if personality.fp_ti['T7']['R'] == 'N':
                    return None
                reply_ip = self.build_reply(
                    packet,
                    path,
                    personality.fp_ti['T7'],
                    callback_cipid,
                    callback_tcpseq,
                    callback_tcpts)
                return reply_ip

        # RST default
        # SYN(flags=2) / ACK(flags=16) / XMAS(flags=41) / FIN(flags=1) / NULL(flags=0) scan
        reply_ip = self.build_rst(packet, path, personality.fp_ti['T5'], 0, callback_cipid, callback_tcpseq)
        return reply_ip

    def filtered(self, packet, path, personality, **kwargs):
        """Function defines filtered port behavior - filtered is defined according to nmap"""
        callback_ipid = kwargs.get('cb_ipid', None)
        callback_icmpid = kwargs.get('cb_icmpid', None)

        # respond with ICMP error type 3 code 13 OR ignore
        # icmp packet
        reply_icmp = ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ImpactPacket.ICMP.ICMP_UNREACH)
        reply_icmp.set_icmp_code(ImpactPacket.ICMP.ICMP_UNREACH_FILTERPROHIB)
        reply_icmp.set_icmp_id(callback_icmpid())  # unused field
        reply_icmp.set_icmp_seq(0)  # unused field
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
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_icmp)

        return reply_ip

    def blocked(self, packet, path, personality, **kwargs):
        """Function defines blocked port behavior - no response is created for blocked ports"""
        return None

    def build_reply(self, packet, path, personality, cb_ip_id, cb_tcp_seq, cb_tcp_ts):
        """Function creates a reply according to the personality of the device
        Args:
            packet : intercepted packet
            path : length of path in the virtual network
            personality : personality description of the device
            cb_ipid, cb_tcp_seq, cb_tcp_ts : callback functions for IP ID, TCP SEQ and TCP TS generation
        Return
            reply ip packet
        """
        # fingerprint fields R, DF, T, TG, W, S, A, F, O, RD, Q & CC

        # tcp packet
        tcp_pkt = packet.child()
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
        reply_ip.set_ip_src(packet.get_ip_dst())
        reply_ip.set_ip_dst(packet.get_ip_src())
        reply_ip.set_ip_id(cb_ip_id())
        reply_ip.auto_checksum = 1

        # check DF
        if 'DF' in personality:
            if personality['DF'] == 'N':
                reply_ip.set_ip_df(False)
            elif personality['DF'] == 'Y':
                reply_ip.set_ip_df(True)
            else:
                raise Exception('Unsupported Ti:DF=%s', personality['DF'])

        # check T
        ttl = 0x7f
        if 'T' in personality:
            try:
                ttl = personality['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except BaseException:
                raise Exception('Unsupported Ti:T=%s', personality['T'])

        # check TG
        if 'TG' in personality:
            try:
                ttl = int(personality['TG'], 16)
            except BaseException:
                raise Exception('Unsupported Ti:TG=%s', personality['TG'])

        delta_ttl = ttl - path
        if delta_ttl < 1:
            logger.debug('Reply packet dropped: TTL reached 0 within virtual network.')
            return None
        reply_ip.set_ip_ttl(delta_ttl)

        # check W
        win = 0
        if 'W' in personality:
            try:
                win = int(personality['W'], 16)
            except BaseException:
                raise Exception('Unsupported Ti:W=%s', personality['W'])
        reply_tcp.set_th_win(win)

        # check CC
        if 'CC' in personality:
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
        if 'S' in personality:
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
        if 'A' in personality:
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
                except BaseException:
                    raise Exception('Unsupported Ti:A=%s', personality['A'])

        # check O
        if 'O' in personality:
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
                    if options[i + 1] == '1':
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
        if 'F' in personality:
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
        if 'Q' in personality:
            if 'R' in personality['Q']:
                reply_tcp.set_flags(0x800)
            if 'U' in personality['Q']:
                reply_tcp.set_th_urp(0xffff)

        # check RD
        if 'RD' in personality:
            try:
                crc = int(personality['RD'], 16)
                if crc != 0:
                    data = 'TCP Port is closed\x00'
                    data += self.compensate(data, crc)
                    pkt_data = ImpactPacket.Data(data)
                    reply_tcp.contains(pkt_data)
            except BaseException:
                raise Exception('Unsupported Ti:RD=%s', personality['RD'])

        reply_tcp.calculate_checksum()
        reply_ip.contains(reply_tcp)
        return reply_ip

    def build_rst(self, packet, path, personality, win, ip_id, tcp_seq):
        """Function creates a response RST packet according to personality of the device
        Args:
            packet : intercepted packet
            path : length of path in the virtual network
            personality : personality description of the device
            win : window size used in the RST packet
            ip_id : IP ID used in the RST packet
            tcp_seq : TCP SEQ number used in the RST packet
        Return:
            reply ip packet
        """
        tcp_pkt = packet.child()

        # tcp packet
        reply_tcp = ImpactPacket.TCP()
        reply_tcp.set_th_sport(tcp_pkt.get_th_dport())
        reply_tcp.set_th_dport(tcp_pkt.get_th_sport())
        # reply_tcp.set_th_flags(20) # RST + ACK
        reply_tcp.set_RST()
        reply_tcp.set_ACK()
        reply_tcp.set_th_ack(tcp_pkt.get_th_seq() + 1)
        reply_tcp.set_th_seq(tcp_seq())
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
        reply_ip.set_ip_src(packet.get_ip_dst())
        reply_ip.set_ip_dst(packet.get_ip_src())
        reply_ip.set_ip_id(ip_id())
        # check T
        ttl = 0x7f
        if 'T' in personality:
            try:
                ttl = personality['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except BaseException:
                raise Exception('Unsupported Ti:T=%s', personality['T'])

        # check TG
        if 'TG' in personality:
            try:
                ttl = int(personality['TG'], 16)
            except BaseException:
                raise Exception('Unsupported Ti:TG=%s', personality['TG'])

        delta_ttl = ttl - path
        if delta_ttl < 1:
            logger.debug('Reply packet dropped: TTL reached 0 within virtual network.')
            return None
        reply_ip.set_ip_ttl(delta_ttl)
        reply_ip.auto_checksum = 1
        reply_ip.contains(reply_tcp)

        return reply_ip

    # Reversing CRC according to:
    # https://github.com/StalkR/misc/blob/master/crypto/crc32.py
    # https://github.com/CoreSecurity/impacket/blob/master/examples/uncrc32.py
    def compensate(self, b, w):
        w ^= 0xffffffff
        nb = 0
        for i in range(32):
            if nb & 1:
                nb = (nb >> 1) ^ 0xedb88320
            else:
                nb >>= 1
            if w & 1:
                nb ^= 0x5b358fd3
            w >>= 1
        nb ^= crc32(b) ^ 0xffffffff
        return pack('<L', nb)

    def get_value(self, o, i):
        v = 0
        idx = i
        for c in o[i:]:
            try:
                v = v * 0x10 + int(c, 16)
            except BaseException:
                break
            idx += 1
        return v, idx
