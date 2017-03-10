#!/usr/bin/env python

import impacket

class TCPHandler(Protocol):
    # TODO: check states
    valid_states = ['syn_rcvd', 'ack_rcvd', 'fin_rcvd']

    # dictionary = source IP : FSM state
    open_connections = dict()
    closed_conncetions = dict()

    # TODO: id and seq generation
    def opened(self, pkt, path, personality):
        # SEQ OPS WIN T1 ? ECN
        # T2 T3 T4
        return

    def closed(self, pkt, path, personality):
        # T5, T6, T7
        tcp_pkt = pkt.child()
        if not (tcp_pkt.get_SYN() or tcp_pkt.get_ACK() or tcp_pkt.get_RST() or tcp_pkt.get_FIN()):
            # respond with RST with 0 window value - incoming packet not containing SYN, RST, FIN or ACK
            reply = send_rst(pkt, path)
            return reply

        # TODO: handle too many open connections, like syn flood -> socket timeout & dict cleanup
        # fingerprint fields R, DF, T, TG, W, S, A, F, O, RD, Q
        source_ip = tcp_pkt.get_ip_src()
        if source_ip not in closed_conncetions.keys():
            if not tcp_pkt.get_SYN():
                return None
            if personality.fp_ti['T5'].has_key('R'):
                if personality.fp_ti['T5']['R'] == 'N':
                    return None
                # reply to T5 - SYN
                reply = build_reply(pkt, path, personality.fp_ti['T5'])
                closed_conncetions[source_ip] = 'syn_rcvd'
                return reply

        elif closed_conncetions[source_ip] == 'syn_rcvd':
            if not tcp_pkt.get_ACK():
                return None
            if personality.fp_ti['T6'].has_key('R'):
                if personality.fp_ti['T6']['R'] == 'N':
                    return None
                # reply to T6 - ACK
                reply = build_reply(pkt, path, personality.fp_ti['T6'])
                closed_conncetions[source_ip] = 'ack_rcvd'
                return reply

        elif closed_conncetions[source_ip] == 'ack_rcvd':
            if not tcp_pkt.get_FIN():
                return None
            # TODO: continuous transmission  -> multiple acks ?
            if personality.fp_ti['T7'].has_key('R'):
                if personality.fp_ti['T7']['R'] == 'N':
                    return None
                # reply to T7 - FIN, PSH, URG
                reply = build_reply(pkt, path, personality.fp_ti['T7'])
                # closed_conncetions[source_ip] = 'fin_rcvd'
                del closed_conncetions[source_ip]
                return reply

        # If we arrive at this location we deal with invalids -> send reset packet
        else:
            reply = send_rst(pkt, path)
            return reply


    def filtered(self, pkt, path, personality):
        # respond with ICMP error type 3 code 13
        reply_icmp = impacket.ImpactPacket.ICMP()
        reply_icmp.set_icmp_type(ICMP_UNREACH)
        reply_icmp.set_icmp_code(ICMP_UNREACH_FILTERPROHIB)
        reply_icmp.auto_checksum = 1

        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.contains(reply_icmp)

        # reply_eth = impacket.ImpactPacket.Ethernet()
        # reply_eth.set_ether_type(0x800)
        # reply_eth.contains(reply_ip)
        return reply_ip

    def build_reply(pkt, path, personality):
        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())

        tcp_pkt = pkt.child()
        reply_tcp = impacket.ImpactPacket.TCP()
        reply_tcp.set_th_sport(tcp_pkt.get_th_dport())
        reply_tcp.set_th_dport(tcp_pkt.get_th_sport())

        # check DF
        if personality.has_key('DF'):
            if personality['DF'] == 'N':
                reply_ip.set_ip_df(False)
            elif personality.fp_u1['DF'] == 'Y':
                reply_ip.set_ip_df(True)
            else:
                # TODO: raise Exception()
                pass

        # check T
        ttl = 0x7f
        if personality.has_key('T'):
            try:
                ttl = personality['T'].split('-')
                # using minimum ttl
                ttl = int(ttl[0], 16)
            except:
                # TODO: raise Exception()
                pass

        # check TG
        if personality.has_key('TG'):
            try:
                ttl = int(personality['TG'], 16)
            except:
                # TODO: raise Exception()
                pass
        # TODO: update TTL according to path length
        delta_ttl = len(path)
        reply_ip.set_ip_ttl(ttl)

        # check W
        win = 0
        if personality.has_key('W'):
            try:
                win = int(personality['W'], 16)
            except:
                # raise Exception()
                pass
        reply_tcp.set_th_win(win)

        # check S
        if personality.has_key('S'):
            if personality['S'] == 'Z':
                reply_tcp.set_th_seq(0)
            elif personality['S'] == 'A':
                reply_tcp.set_th_seq(tcp_pkt.get_th_ack())
            elif personality['S'] == 'A+':
                reply_tcp.set_th_seq(tcp_pkt.get_th_ack() + 1)
            elif personality['S'] == 'O':
                # TODO: sequence generation
                seq = get_tcp_seq()
                reply_tcp.set_th_seq(seq)
            else:
                # raise Exception()
                pass

        # check A
        if personality.has_key('A'):
            if personality['A'] == 'Z':
                reply_tcp.set_th_ack(0)
            elif personality['A'] == 'S':
                reply_tcp.set_th_ack(tcp_pkt.get_th_seq())
            elif personality['A'] == 'S+':
                reply_tcp.set_th_ack(tcp_pkt.get_th_seq() + 1)
            elif personality['A'] == 'O':
                # TODO: ack generation
                ack = get_tcp_ack()
                reply_tcp.set_th_ack(ack)
            else:
                # raise Exception()
                pass

        # check O
        if personality.has_key('O'):
            options = personality['O']
            i = 0
            while i < len(options):
                opt = options[i]
                i += 1
                if opt == 'L':
                    reply_tcp.add_option(impacket.ImpactPacket.TCPOption(impacket.ImpactPacket.TCPOption.TCPOPT_EOL))
                if opt == 'N':
                    reply_tcp.add_option(impacket.ImpactPacket.TCPOption(impacket.ImpactPacket.TCPOption.TCPOPT_NOP))
                if opt == 'S':
                    reply_tcp.add_option(impacket.ImpactPacket.TCPOption(impacket.ImpactPacket.TCPOption.TCPOPT_SACK_PERMITTED))
                if opt == 'T':
                    opt = impacket.ImpactPacket.TCPOption(impacket.ImpactPacket.TCPOption.TCPOPT_TIMESTAMP)
                    if options[i] == '1':
                        # TODO: generate ts
                        opt.set_ts(get_tcp_ts())
                    if options[i+1] == '1':
                        opt.set_ts_echo(0xffffffffL)
                    reply_tcp.add_option(opt)
                    i += 2
                if opt == 'M':
                    maxseg, i = get_value(options, i)
                    reply_tcp.add_option(impacket.ImpactPacket.TCPOption(impacket.ImpactPacket.TCPOption.TCPOPT_MAXSEG, maxseg))
                if opt == 'W':
                    window, i = get_value(options, i)
                    reply_tcp.add_option(impacket.ImpactPacket.TCPOption(impacket.ImpactPacket.TCPOption.TCPOPT_WINDOW, window))

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
                    data += uncrc32.compensate(data, crc)
                    data = ImpactPacket.Data(data)
                    reply_tcp.contains(data)
            except:
                # raise Exception()
                pass

        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.contains(reply_icmp)

        # reply_eth = impacket.ImpactPacket.Ethernet()
        # reply_eth.set_ether_type(0x800)
        # reply_eth.contains(reply_ip)

    def send_rst(pkt, path):
        # TODO: set seq and id if needed & set ttl
        tcp_pkt = pkt.child()

        reply_tcp = impacket.ImpactPacket.TCP()
        reply_tcp.set_th_sport(tcp_pkt.get_th_dport())
        reply_tcp.set_th_dport(tcp_pkt.get_th_sport())
        reply_tcp.set_RST()
        reply_tcp.set_ACK()
        reply_tcp.set_th_ack(tcp_pkt.get_th_seq() + 1)
        reply_tcp.set_th_seq(get_tcp_seq())
        reply_tcp.set_th_win(0)

        reply_ip = impacket.ImpactPacket.IP()
        reply_ip.set_ip_p(1)
        reply_ip.set_ip_src(pkt.get_ip_dst())
        reply_ip.set_ip_dst(pkt.get_ip_src())
        reply_ip.contains(reply_tcp)

        return reply_ip

    def get_value(o, i):
        v = 0
        idx = i
        for c in o[i:]:
            try:
                v = v * 0x10 + int(c, 16)
            except:
                break
            idx += 1
        return v, idx

    # TODO
    def get_tcp_seq():
        pass

    # TODO
    def get_tcp_ack():
        pass

    # TODO
    def get_tcp_ts():
        pass
