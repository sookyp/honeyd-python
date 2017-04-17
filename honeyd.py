#!/usr/bin/env python

import gevent.monkey
gevent.monkey.patch_all()

import sys
import os
import pwd
import grp
import logging
import argparse
import gevent
import urllib
import netifaces
import re

import honeyd
from honeyd.core.builder import Builder
from honeyd.core.dispatcher import Dispatcher
from honeyd.loggers.hpfeeds_logger import HPFeedsLogger
from honeyd.loggers.mysqldb_logger import DatabaseLogger

# import threading
# from honeyd.core.listener import Listener

logger = logging.getLogger()
package_directory = os.path.dirname(os.path.abspath(honeyd.__file__))


def logo():
    print """\
 _                     _
| |_ ___ ___ ___ _ _ _| |
|   | . |   | -_| | | . |
|_|_|___|_|_|___|_  |___|
                |___|
    """
    print "Author: Peter Sooky <448291@mail.muni.cz>"
    print('Honeyd-python {0}'.format(honeyd.__version__))


def setup_logging(log_file, verbose):
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
        # sys.tracebacklimit = 0

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

"""
def drop_privileges(uid_name=None, gid_name=None):
    if uid_name is None:
        uid_name = 'nobody'
    try:
        wanted_user = pwd.getpwnam(uid_name)
    except KeyError:
        logger.exception(
            'Cannot drop privileges: user "%s" does not exist.',
            uid_name)
        sys.exit(1)
    if gid_name is None:
        gid_name = grp.getgrgid(wanted_user.pw_gid).gr_name
    try:
        wanted_group = grp.getgrnam(gid_name)
    except KeyError:
        logger.exception(
            'Cannot drop privileges: group "%s" does not exist.',
            gid_name)
        sys.exit(1)
    logger.debug('Attempting to drop privileges to "%s:%s"',
                 wanted_user.pw_name, wanted_group.gr_name)
    try:
        os.setgid(wanted_group.gr_gid)
    except OSError:
        logger.exception(
            'Cannot drop privileges: set GID operation not permitted.'
        )
    try:
        os.setuid(wanted_user.pw_uid)
    except OSError:
        logger.exception(
            'Cannot drop privileges: set UID operation not permitted'
            )
    new_user = pwd.getpwuid(os.getuid())
    new_group = grp.getgrgid(os.getgid())
    logger.info('Privileges set, running as "%s:%s"',
                new_user.pw_name, new_group.gr_name)
"""

def parse_arguments():
    parser = argparse.ArgumentParser(description='Honeyd')
    parser.add_argument("--version", action="store_true", default=False, help="Print Honeyd version and exit")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Enables logging of debug messages")
    parser.add_argument("-l", "--logfile", help="Set logfile path and name", default="honeyd.log")
    parser.add_argument("-n", "--network", help="Set configuration file path and name",
                        default=os.path.join(package_directory, "templates/network.xml"))
    parser.add_argument("-c", "--config", help="Set database and hpfeeds configuration file",
                        default=os.path.join(package_directory, "templates/honeyd.cfg"))
    # parser.add_argument("-u", "--uid", help="Set the user id Honeyd should run as", default=None)
    # parser.add_argument("-g", "--gid", help="Set the group id Honeyd should run as", default=None)
    parser.add_argument("-i", "--interface", help="Listen on interface", default=None)
    parser.add_argument("-a", "--address", action="append", help="Reply to ARP requests matching address", default=[])
    parser.add_argument("-o", "--os-fingerprint", help="Set nmap-style fingerprints file location",
                        default=os.path.join(package_directory, "templates/nmap-os-db"))
    parser.add_argument("-m", "--mac-prefix", help="Set nmap-mac-prefixes file location",
                        default=os.path.join(package_directory, "templates/nmap-mac-prefixes"))

    args = parser.parse_args()

    if args.version:
        logo()
        sys.exit(0)

    return args


def setup_os_fingerprints(file):
    if not os.path.isfile(file):
        try:
            logger.info('Retrieving Nmap fingerprint database')
            urllib.urlretrieve(
                "https://svn.nmap.org/nmap/nmap-os-db",
                os.path.join(
                    package_directory,
                    "templates/nmap-os-db"))
        except ContentTooShortError:
            logger.exception('Connection interupted: nmap-os-db retrieval failed')
            sys.exit(1)


def setup_mac_prefix(file):
    if not os.path.isfile(file):
        try:
            logger.info('Retrieving Nmap MAC prefix database')
            urllib.urlretrieve(
                "https://svn.nmap.org/nmap/nmap-mac-prefixes",
                os.path.join(
                    package_directory,
                    "templates/nmap-mac-prefixes"))
        except ContentTooShortError:
            logger.exception('Connection interupted: nmap-mac-prefixes retrieval failed')
            sys.exit(1)


def unhandled_exception(greenlet, expected_args):
    tunnels, config, arp_daemon = expected_args
    logger.error('Error: Stopping honeypot: %s is dead: %s', greenlet, greenlet.exception)
    logger.info('Closing tunnel interfaces: %s', tunnels)
    Builder().teardown_tunnels(tunnels, package_directory, config)
    if arp_daemon:
        logging.info('Terminating arpd daemon.')
        arp_daemon.kill()
    sys.exit(1)


def main():
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
        logger.warning('No logging configuration file found in directory, using default configuration: %s', args.config)
    hpfeeds = HPFeedsLogger(args.config)
    dblogger = DatabaseLogger(args.config)

    network, default, devices, routes, externals, tunnels = Builder().build_network(
        package_directory, args.config, args.network, args.os_fingerprint, args.mac_prefix)

    if args.interface not in netifaces.interfaces():
        logger.error('Error: No valid interface detected for %s, ignoring configuration', args.interface)
        sys.exit(1)

    # filter out non-CIDR notation
    cidr_address = list()
    cidr_pattern = re.compile(
        '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(([/](3[01]|[0-2]?[0-9]))|([-]((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))?')
    for address in args.address:
        cidr = cidr_pattern.match(address)
        if cidr is not None:
            cidr_address.append(cidr.string)

    if len(cidr_address):
        try:
            # call(['arpd', arpd_interfaces])
            logger.info('Starting farpd daemon with flags: -d | -i %s | %s', args.interface, cidr_address)
            DEVNULL = open(os.devnull, 'w')
            arp_daemon = gevent.subprocess.Popen(['farpd',
                                                  '-d',
                                                  '-i',
                                                  args.interface,
                                                  ' '.join(cidr_address)],
                                                 stdout=DEVNULL,
                                                 stderr=gevent.subprocess.STDOUT)
            gevent.sleep(1)
        except Exception as ex:
            logger.error(
                'Error: Cannot invoke arpd process on interface %s with address range %s: %s',
                args.interface,
                cidr_address,
                ex)
            sys.exit(1)

    # in case we want multithreaded listening -> we not need it currently
    # we are required to use processes to bypass the GIL
    # FIX: find some way to use threads
    """
    listener = list()
    for tunnel in tunnels:
        # spawn listener for each tunnel
        # l = Listener(tunnel)
        try:
            # l = threading.Thread(target=Listener, args=(tunnel, ))
            q = multiprocessing.Queue()
            l = Listener(tunnel, q)
            l.daemon = True
            l.start()
            # l.run()
        except RuntimeError:
            logger.exception('Exception: Listener thread %s already running.', l)
            continue
        listener.append((l, q))
    """

    logger.debug('Starting live capture on interface: %s', args.interface)
    # spawn dispatcher for interface
    greenlet = gevent.spawn(Dispatcher, args.interface, network, default,
                            (devices, routes, externals), (hpfeeds, dblogger), tunnels)
    greenlet.link_exception(lambda: unhandled_exception(greenlet, (tunnels, args.config, arp_daemon)))

    # FIX: we might not be able to drop privileges as we are using raw sockets
    """
    drop_privileges(args.uid, args.gid)
    """

    try:
        greenlet.join()
        """
        for l in listener:
            try:
                l[0].join()
            except RuntimeError:
                logger.exception('Exception: Listener thread %s possible deadlock or thread is not running')
        """
    except KeyboardInterrupt:
        logging.info('Received keyboard interrupt...')

    logging.info('Stopping Honeyd.')
    logger.info('Terminating greenlet: %s', greenlet)
    greenlet.kill()
    """
    for l in listener:
        l[0].terminate()
    """
    logger.info('Closing tunnel interfaces: %s', tunnels)
    Builder().teardown_tunnels(tunnels, package_directory, args.config)
    if arp_daemon:
        logging.info('Terminating arpd daemon.')
        arp_daemon.kill()


if __name__ == "__main__":
    main()
