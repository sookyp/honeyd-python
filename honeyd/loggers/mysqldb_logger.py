#!/usr/bin/env python
"""Mysqldb_logger.py is responsible for creating and inserting data into the database."""
import logging
from ConfigParser import ConfigParser, NoSectionError, NoOptionError
from warnings import filterwarnings

import gevent
import MySQLdb
filterwarnings('ignore', category=MySQLdb.Warning)

logger = logging.getLogger(__name__)


class DatabaseLogger(object):
    """DatabaseLogger creates tables for logging, inserts the attack-related data into the tables"""
    def __init__(self, config_file):
        """Function initializes the logger
        Args:
            config_file : name of the honeypot configuration file
        """
        logger.debug('Initializing database logger.')
        parser = ConfigParser()
        parser.read(config_file)
        self.enabled = False
        self.connection = None
        self.max_retries = 5
        try:
            if parser.getboolean("mysql", "enabled"):
                self.host = parser.get("mysql", "host")
                self.port = int(parser.getint("mysql", "port"))
                self.db = parser.get("mysql", "db")
                self.username = parser.get("mysql", "username")
                self.passphrase = parser.get("mysql", "passphrase")
                self.logdevice = parser.get("mysql", "logdevice")
                self.logsocket = parser.get("mysql", "logsocket")
                self.enabled = True
                gevent.spawn(self._connect)
        except (NoSectionError, NoOptionError):
            logger.exception('Exception: Incomplete honeyd.cfg configuration. MySQL logging is disabled.')
            self.enabled = False

    def _connect(self):
        """Function connects to the database"""
        logger.debug('Connecting to MySQL database.')
        try:
            if str(self.logsocket).lower() == 'tcp':
                self.connection = MySQLdb.connect(
                    host=self.host,
                    port=self.port,
                    user=self.username,
                    passwd=self.passphrase,
                    db=self.db)
            elif str(self.logsocket).lower() == 'dev':
                self.connection = MySQLdb.connect(
                    unix_socket=self.logdevice,
                    user=self.username,
                    passwd=self.passphrase,
                    db=self.db)
            self._create_database()
        except (AttributeError, MySQLdb.OperationalError):
            logger.exception('Exception: Cannot connect to database.')

    def _create_database(self):
        """Function creates the tables in the database"""
        logger.debug('Creating MySQL database.')
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT count(*)
            FROM information_schema.tables
            WHERE table_name = %s and table_schema=%s
            """, ("events", self.db))
        if (cursor.fetchone()[0]) == 0:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `events` (
                `id` bigint(20) NOT NULL AUTO_INCREMENT,
                `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `ethernet_source` text NOT NULL,
                `ip_source` text NOT NULL,
                `port_source` text NOT NULL,
                `ethernet_destination` text NOT NULL,
                `ip_destination` text NOT NULL,
                `port_destination` text NOT NULL,
                `ethernet_type` text NOT NULL,
                `protocol` text NOT NULL,
                `info` text NOT NULL,
                `raw_packet` text NOT NULL,
                PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=latin1;
                """)

    def insert(self, attack_event):
        """Function inserts attack-related data into the database
        Args:
            attack_event : dictionary containing attack-related information
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute("""
                INSERT INTO events (ethernet_source, ip_source, port_source, ethernet_destination, ip_destination, port_destination, ethernet_type, protocol, info, raw_packet)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""", (
                    str(attack_event["ethernet_src"]),
                    str(attack_event["ip_src"]),
                    str(attack_event["port_src"]),
                    str(attack_event["ethernet_dst"]),
                    str(attack_event["ip_dst"]),
                    str(attack_event["port_dst"]),
                    str(attack_event["ethernet_type"]),
                    str(attack_event["protocol"]),
                    str(attack_event["info"]),
                    str(attack_event["raw_pkt"])
                    ))
            self.connection.commit()
        except (AttributeError, MySQLdb.OperationalError):
            logger.error('Error: Cannot insert attack event into database.')
