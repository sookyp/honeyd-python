#!/usr/bin/env python
"""Attack_event.py describes the data structure used to store attack-related information"""
from datetime import datetime
import uuid


class AttackEvent(object):
    """Definition dictionary containing attack-related information"""
    def __init__(self):
        """Function initializes the attributes for attack information storage"""
        self.id = str(uuid.uuid4())
        self.eth_src = None
        self.eth_dst = None
        self.eth_type = None
        self.ip_src = None
        self.ip_dst = None
        self.proto = None
        self.port_src = None
        self.port_dst = None
        self.info = None
        self.raw_pkt = None
        self.event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def event_dict(self):
        """Function creates the dictionary for information storage
        Return:
            dictionary of attack information
        """
        event_dict = {
            "time": self.event_time,
            "ethernet_src": self.eth_src,
            "ethernet_dst": self.eth_dst,
            "ethernet_type": self.eth_type,
            "ip_src": self.ip_src,
            "ip_dst": self.ip_dst,
            "port_src": self.port_src,
            "port_dst": self.port_dst,
            "protocol": self.proto,
            "info": self.info,
            "raw_pkt": self.raw_pkt
        }
        return event_dict
