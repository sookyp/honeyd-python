#!/usr/bin/env python

import logging

import hpfeeds
import os
import gevent
import socket
from ConfigParser import ConfigParser, NoSectionError, NoOptionError

logger = logging.getLogger(__name__)

# TODO
class HPFeedsLogger(object):
    def __init__(self, work_dir, config="honeyd.cfg", reconnect=True):
        parser = ConfigParser()
        config = os.path.join(work_dir, config)
        self.enabled = False
        if not os.path.isfile(config):
            logger.info('No honeyd.cfg configuration file found for hpfeeds. Hpfeeds logging is disabled.')
            return
        parser.read(config)
        self._initial_connection_happened = False
        try:
            if self.parser.getboolean("hpfeed", "enabled"):
                self.host = self.parser.get("hpfeed", "host")
                self.port = int(self.parser.getint("hpfeed", "port"))
                self.ident = self.parser.get("hpfeed", "ident")
                self.timeout = int(self.parser.get("hpfeed", "timeout"))
                self.secret = self.parser.get("hpfeed", "secret")
                self.channels = self.parser.get("hpfeed", "channels")
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
            self._initial_connection_happend = True
        except hpfeeds.FeedException:
            logger.exception('Exception: cannot connect to hpfeeds service.')

    def publish(self, attack_event):
        retries = 0
        if self._initial_connection_happend:
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
