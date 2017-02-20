#!/usr/bin/env python

import logging

import sys
import pcapy
import dpkt
import socket
import networkx

logger = logging.getLogger(__name__)

def mac_2_str(mac):
    return ':'.join('%02' % ord(b) for b in mac)

def inet_2_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
    
        
class Dispatcher(object):
    """
    Dispatcher starts live capturing on interfaces, extracts and classifies the incoming packet information, finds the path to the target in the network
    """
    def __init__(self, interface, network, default, elements):
        self.pcapy_object = None
        self.interface = interface
        self.network = network
        self.default = default
        self.devices, self.routes, self.externals = elements
        self.entry_points = list()
        for r in self.routes:
            if r.entry:
                self.entry_points.append(r)

        self.start()

        
    def start(self):
        # TODO: check if all packets are captured - known bug: pcap misses packets
        # TODO: use tshark-python wrapper in case of packet misses
        self.pcapy_object = pcapy.open_live(self.interface, 65536, 1, 0)
        logger.info('Started dispatcher listening on interface %s', self.interface)

        while True:
            (header, payload) = self.pcapy_object.next()
            # unpack Ethernet frame
            eth = dpkt.ethernet.Ethernet(str(payload))

            # TODO: log extracted packet information
            
            # TODO: filter out our own outgoing packets
            
            # ignore non-IP packet for now: eth.type != dpkt.ethernet.ETH_TYPE_IP
            if not isinstance(eth.data, dpkt.ip.IP):
                # TODO: more verbose logging
                logger.info('Not supported non-IP packet type %s', eth.data.__class__.__name__)
                continue

            ip = eth.data
            logger.info('IP src=%s -> dst=%s proto=%s tos=%s ttl=%s data=%s', inet_2_str(ip.src), inet_2_str(ip.dst), ip.p, ip.tos, ip.ttl, list())

            # send packet to entry OR target routers depending on our network implementation
            for r in self.entry_points:
                if networkx.has_path(self.network, r.ip, eth.data.dst):
                    pass
                    # TODO: there is known path to destination
                    # path = networkx.shortest_path(self.network, router.ip, eth.data.dst)
                else:
                    pass
                    # TODO: there is NO direct path to destination
                    # add reachable subnet 
