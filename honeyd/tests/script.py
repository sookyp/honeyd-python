#!/usr/bin/env python

"""
Basic testing script: for every incoming connection generates the same reply and passes to the framework
Framework sends data for input as bytestream via stdin
Framework expects data for output as bytestream via stdout
"""

from impacket import ImpactPacket

# message
msg = """Connected to server-name.com.\nEscape character is '^]'.\n SSH-2.0-OpenSSH_4.6 Debian-4"""

"""
    The honeypot sets the outer IP ID and inner TCP SEQ number based on the defined personality. Also sets the source and destination addresses and ports.
    Finally it alters the TTL and recalculates the checksum. Other values are left for the script author to set.
"""
# tcp datagram
reply_tcp = ImpactPacket.TCP() # set reply packet type
reply_tcp.contains(ImpactPacket.Data(msg)) # set message
reply_tcp.set_th_sport(22) # this is also set by the honeypot, however might be reasonable to leave it for the script
reply_tcp.set_th_win(29200)
reply_tcp.auto_checksum = 1
reply_tcp.calculate_checksum()

# ip packet
reply_ip = ImpactPacket.IP() # create carrier IP packet and set 
reply_ip.set_ip_v(4)
reply_ip.set_ip_p(6)
reply_ip.set_ip_rf(False)
reply_ip.set_ip_df(False)
reply_ip.set_ip_mf(False)
reply_ip.set_ip_id(0)
ttl = 64
reply_ip.set_ip_ttl(ttl)
reply_ip.auto_checksum = 1
reply_ip.contains(reply_tcp)

print reply_ip.get_packet()
