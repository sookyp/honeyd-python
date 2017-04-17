#!/usr/bin/env python

import logging

import sys
import multiprocessing
import pcapy
import impacket
from impacket import ImpactPacket, ImpactDecoder

import honeyd

# from collections import deque

logger = logging.getLogger(__name__)


class Listener(multiprocessing.Process):
    def __init__(self, tunnel_information, queue):
        super(Listener, self).__init__()
        self.daemon = True
        self.interface, self.remote_ip, self.tunnel_mode = tunnel_information
        self.pcapy_object = pcapy.open_live(self.interface, 65535, 1, 1000)
        # self.decoder = ImpactDecoder.EthDecoder()
        self.decoder = ImpactDecoder.LinuxSLLDecoder()
        self.packet_queue = queue
        logger.info('Started listener on virtual interface %s', self.interface)

    def run(self):
        while True:
            try:
                hdr, pkt = self.pcapy_object.next()
                if len(pkt) != 0:
                    self.packet_queue.put(pkt)
            except BaseException:
                return None
