#!/usr/bin/env python
"""Honeyd.py is the main script that controls the execution of the honeypot. This script is responsible for overseeing
the setup process and invoking the required modules for certain functionalities."""
import sys
import os
import logging
import argparse
import urllib
import re
import netifaces

import gevent
from gevent import monkey
monkey.patch_all()

import honeyd
from honeyd.core.builder import Builder
from honeyd.core.dispatcher import Dispatcher
from honeyd.loggers.hpfeeds_logger import HPFeedsLogger
from honeyd.loggers.mysqldb_logger import DatabaseLogger

logger = logging.getLogger()
package_directory = os.path.dirname(os.path.abspath(honeyd.__file__))


def logo():
    """Function prints out logo and version number."""
    print """\
 _                     _
| |_ ___ ___ ___ _ _ _| |
|   | . |   | -_| | | . |
|_|_|___|_|_|___|_  |___|
                |___|
    """
    print 'Author: Peter Sooky <448291@mail.muni.cz>'
    print 'Honeyd-python {0}'.format(honeyd.__version__)


def setup_logging(log_file, verbose):
    """Function configures console and file loggers.
    Args:
        log_file : name of the logfile
        verbose : boolean value determining use of verbose logging
    """
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logger.setLevel(log_level)

    log_format = logging.Formatter('%(asctime)-15s %(message)s')

    console_log = logging.StreamHandler()
    console_log.setLevel(log_level)
    console_log.setFormatter(log_format)

    file_log = logging.FileHandler(log_file)
    file_log.setFormatter(log_format)
    file_log.setLevel(log_level)

    root_logger = logging.getLogger()
    root_logger.addHandler(console_log)
    root_logger.addHandler(file_log)


def parse_arguments():
    """Function handles commandline argument logging
    Return:
        args : structure containing argument names and values
    """
    parser = argparse.ArgumentParser(description='Honeyd')
    parser.add_argument(
        "--version", action="store_true", default=False, help="Print Honeyd version and exit")
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="Enables logging of debug messages")
    parser.add_argument(
        "-l", "--logfile", help="Set logfile path and name", default="honeyd.log")
    parser.add_argument(
        "-n", "--network", help="Set configuration file path and name", default=os.path.join(package_directory, "templates/network.xml"))
    parser.add_argument(
        "-c", "--config", help="Set database and hpfeeds configuration file", default=os.path.join(package_directory, "templates/honeyd.cfg"))
    parser.add_argument(
        "-i", "--interface", help="Listen on interface", default=None)
    parser.add_argument(
        "-a", "--address", action="append", help="Reply to ARP requests matching address", default=[])
    parser.add_argument(
        "-o", "--os-fingerprint", help="Set nmap-style fingerprints file location", default=os.path.join(package_directory, "templates/nmap-os-db"))
    parser.add_argument(
        "-m", "--mac-prefix", help="Set nmap-mac-prefixes file location", default=os.path.join(package_directory, "templates/nmap-mac-prefixes"))
    args = parser.parse_args()

    if args.version:
        logo()
        sys.exit(0)

    return args


def setup_os_fingerprints(os_file):
    """Function downloads nmap-os-db from internet if not found at given location
    Args:
        os_file : location of nmap-os-db file
    """
    if not os.path.isfile(os_file):
        try:
            logger.info('Retrieving Nmap fingerprint database')
            urllib.urlretrieve(
                "https://svn.nmap.org/nmap/nmap-os-db",
                os.path.join(
                    package_directory,
                    "templates/nmap-os-db"))
        except urllib.ContentTooShortError:
            logger.exception('Connection interupted: nmap-os-db retrieval failed')
            sys.exit(1)


def setup_mac_prefix(mac_file):
    """Function downloads nmap-mac-prefixes from internet if not found at given location
    Args:
        mac_file : location of nmap-mac_prefixes file
    """
    if not os.path.isfile(mac_file):
        try:
            logger.info('Retrieving Nmap MAC prefix database')
            urllib.urlretrieve(
                "https://svn.nmap.org/nmap/nmap-mac-prefixes",
                os.path.join(
                    package_directory,
                    "templates/nmap-mac-prefixes"))
        except urllib.ContentTooShortError:
            logger.exception('Connection interupted: nmap-mac-prefixes retrieval failed')
            sys.exit(1)


def unhandled_exception(greenlet, expected_args):
    """Function cleans up after a greenlet dies unexpectedly
    Args:
        greenlet : object that died
        expected_args : list of arguments required for clean up
    """
    tunnels, config, arp_daemon, web_server = expected_args
    logger.error('Error: Stopping honeypot: %s is dead: %s', greenlet, greenlet.exception)
    logger.info('Closing tunnel interfaces: %s', tunnels)
    Builder().teardown_tunnels(tunnels, package_directory, config)
    if arp_daemon:
        logging.info('Terminating arpd daemon.')
        arp_daemon.kill()
    if web_server:
        logging.info('Terminating web server.')
        web_server.kill()
    sys.exit(1)


def main():
    """Function controlling honeypot execution"""
    args = parse_arguments()

    setup_logging(args.logfile, args.verbose)

    logger.info('Initializing honeypot...')
    if not os.path.isfile(args.network):
        args.network = os.path.join(package_directory, 'templates/network.xml')
        logger.warning(
            'No network configuration file found in directory, using default configuration: %s',
            args.network)

    setup_os_fingerprints(args.os_fingerprint)
    setup_mac_prefix(args.mac_prefix)

    if not os.path.isfile(args.config):
        args.config = os.path.join(package_directory, "templates/honeyd.cfg")
        logger.warning(
            'No logging configuration file found in directory, using default configuration: %s',
            args.config)
    hpfeeds = HPFeedsLogger(args.config)
    dblogger = DatabaseLogger(args.config)

    try:
        logging.info('Starting honeyd web server on localhost:8080')
        devnull = open(os.devnull, 'w')
        server_path = os.path.join(package_directory, 'utilities/web_server.py')
        web_server = gevent.subprocess.Popen(
            ['python2.7', server_path], stdout=devnull, stderr=gevent.subprocess.STDOUT)
        gevent.sleep(2)
    except Exception as ex:
        logger.error('Cannot start honeyd web server: %s', ex)
        sys.exit(1)

    network, default, devices, routes, externals, tunnels = Builder().build_network(
        package_directory, args.config, args.network, args.os_fingerprint, args.mac_prefix)

    if args.interface not in netifaces.interfaces():
        logger.error(
            'Error: No valid interface detected for %s, ignoring configuration',
            args.interface)
        sys.exit(1)

    cidr_address = list()
    # filter IPv4 address | IPv4 address range | IPv4 subnet
    cidr_pattern = re.compile(
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(([/](3[01]|[0-2]?[0-9]))|([-]((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))?')
    for address in args.address:
        cidr = cidr_pattern.match(address)
        if cidr is not None:
            cidr_address.append(cidr.string)

    if len(cidr_address):
        try:
            logger.info(
                'Starting farpd daemon with flags: -d | -i %s | %s',
                args.interface,
                cidr_address)
            devnull = open(os.devnull, 'w')
            arp_daemon = gevent.subprocess.Popen(['farpd',
                                                  '-d',
                                                  '-i',
                                                  args.interface,
                                                  ' '.join(cidr_address)],
                                                 stdout=devnull,
                                                 stderr=gevent.subprocess.STDOUT)
            gevent.sleep(2)
        except Exception as ex:
            logger.error(
                'Error: Cannot invoke arpd process on interface %s with address range %s: %s',
                args.interface,
                cidr_address,
                ex)
            sys.exit(1)

    logger.debug('Starting live capture on interface: %s', args.interface)
    greenlet = gevent.spawn(Dispatcher, args.interface, network, default,
                            (devices, routes, externals), (hpfeeds, dblogger), tunnels)
    greenlet.link_exception(lambda: unhandled_exception(
        greenlet, (tunnels, args.config, arp_daemon, web_server)))

    try:
        greenlet.join()
    except KeyboardInterrupt:
        logging.info('Received keyboard interrupt...')

    logging.info('Stopping Honeyd.')
    logger.info('Terminating greenlet: %s', greenlet)
    greenlet.kill()
    logger.info('Closing tunnel interfaces: %s', tunnels)
    Builder().teardown_tunnels(tunnels, package_directory, args.config)
    if arp_daemon:
        logging.info('Terminating arpd daemon.')
        arp_daemon.kill()
    if web_server:
        logging.info('Terminating web server.')
        web_server.kill()


if __name__ == "__main__":
    main()
