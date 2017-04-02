#!/usr/bin/env python

import logging

import os
import gevent
import socket
from ConfigParser import ConfigParser, NoSectionError, NoOptionError

import hpfeeds
from hpfeeds import FeedException

logger = logging.getLogger(__name__)

class HPFeedsLogger(object):
    def __init__(self, config_file):
        parser = ConfigParser()
        self.enabled = False
        self.reconnect = True
        parser.read(config_file)
        self._initial_connection_happened = False
        try:
            if parser.getboolean("hpfeeds", "enabled"):
                self.host = parser.get("hpfeeds", "host")
                self.port = int(parser.getint("hpfeeds", "port"))
                self.ident = parser.get("hpfeeds", "ident")
                self.timeout = int(parser.get("hpfeeds", "timeout"))
                self.secret = parser.get("hpfeeds", "secret")
                self.channels = parser.get("hpfeeds", "channels")
                self.max_retries = 5
                self.enabled = True
                self.hpc = None
                gevent.spawn(self._start_connection, self.host, self.port, self.ident, self.secret, self.timeout, self.reconnect)
        except (NoSectionError, NoOptionError):
            logger.info('Incomplete honeyd.cfg configuration. Hpfeeds logging is disabled.')
            self.enabled = False

    def _start_connection(self, host, port, ident, secret, timeout, reconnect):
        try:
            self.hpc = hpfeeds.new(host, port, ident, secret, timeout, reconnect)
            self._initial_connection_happened = True
        except hpfeeds.FeedException:
            logger.exception('Exception: cannot connect to hpfeeds service.')

    def publish(self, attack_event):
        retries = 0
        if self._initial_connection_happened:
            while True:
                if retries >= self.max_retries:
                    break
                try:
                    if attack_event is not None:
                        self.hpc.publish(self.channels, attack_event)
                except socket.error:
                    retries += 1
                    gevent.spawn(self._start_connection, self.host, self.port, self.ident, self.secret, self.timeout, self.reconnect)
                    gevent.sleep(0.5)
                else:
                    break
            error_msg = self.hpc.wait()
            logger.warning(error_msg)
        else:
            logger.warning('Not logging event because initial hpfeeds connect has not happend yet')
