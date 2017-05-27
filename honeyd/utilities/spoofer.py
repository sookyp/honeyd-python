#!/usr/bin/env python
# TODO: initial work on spoofer
import sys
import argparse
import signal
import ipaddress
import pcapy
import netifaces

from impacket import ImpactPacket

def signal_termination_handler(signal, frame):
    sys.exit(0)

def arp_req(host, mac, interface, pcapy_object):
    v = host.version

    req_arp = ImpactPacket.ARP()
    req_arp.set_ar_hln(6)  # Ethernet size 6
    req_arp.set_ar_hrd(1)  # 1:'ARPHRD ETHER', 6:'ARPHRD IEEE802', 15:'ARPHRD FRELAY'
    req_arp.set_ar_op(1)  # 1:'REQUEST', 2:'REPLY', 3:'REVREQUEST', 4:'REVREPLY', 8:'INVREQUEST', 9:'INVREPLY'
    if v == 4:
        req_arp.set_ar_pln(4)
        req_arp.set_ar_pro(0x800)  # IPv4 0x800
    elif v == 6:
        req_arp.set_ar_pln(16)  # IPv6 size 16
        req_arp.set_ar_pro(0x86dd)  # IPv6 0x86dd

    mac = [int(i, 16) for i in mac.split(':')]
    req_arp.set_ar_sha(mac)
    sip = map(int, netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'].split('.'))
    req_arp.set_ar_spa(sip)
    tip = [int(i, 10) for i in str(host).split('.')]
    req_arp.set_ar_tpa(tip)

    # ethernet frame
    req_eth = ImpactPacket.Ethernet()
    if v == 4:
        req_eth.set_ether_type(0x800)
    elif v == 6:
        req_eth.set_ether_type(0x86dd)
    req_eth.set_ether_shost(mac)
    req_eth.contains(req_arp)

    # send raw frame
    try:
        pcapy_object.sendpacket(req_eth.get_packet())
    except pcapy.PcapError as ex:
        pass
    
def callback(ts, pkt):
    # TODO
    pass

parser = argparse.ArgumentParser(description='ARP Spoofer')
parser.add_argument(
    "-i", "--interface", help="Listen on interface", default=None)
parser.add_argument(
    "-a", "--address", action="append", help="Reply to ARP requests matching address", default=[])
args = parser.parse_args()

# check for valid invocation
if args.interface is None or len(args.address) == 0:
    sys.exit(0)
# check for valid interface
if args.interface not in netifaces.interfaces():
    sys.exit(1)
# check for valid address format
host = list()
for address in args.address:
    if len(address.split(" ")) >= 2:
        # ignore configuration containing whitespace
        continue
    a = None
    # format IP range
    h = address.split("-")
    if len(h) == 2:
        start, end = h
        try:
            s = ipaddress.ip_address(unicode(start))
            e = ipaddress.ip_address(unicode(end))
        except ValueError:
            pass
        while s <= e:
            host.append(s)
            s += 1
        continue
    # format IPv4 and IPv6    
    if a is None:
        try:
            a = ipaddress.ip_address(unicode(address))
            host.append(a)
        except ValueError:
            pass
        
    # format CIDR subnet
    if a is None:
        try:
            n = ipaddress.ip_network(unicode(address))
            a = n.hosts()
            host.extend(a)
        except ValueError:
            pass
# catch signal
signal.signal(signal.SIGINT, signal_termination_handler)
signal.signal(signal.SIGTERM, signal_termination_handler)
# set up sniffer
pcapy_object = pcapy.open_live(args.interface, 65535, 1, 10)
mac = netifaces.ifaddresses(args.interface)[netifaces.AF_LINK][0]['addr']
for h in host:
    # send out ARP requests
    arp_req(h, mac, args.interface, pcapy_object)
# TODO: build list of unused IPs and periodically send out fake ARP messages
while True:
  try:
      (hdr, pkt) = pcapy_object.next()
      callback(hdr, pkt)
  except KeyboardInterrupt:
      sys.exit(0)