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

# import ipaddress
# import netaddr

import honeyd
from honeyd.core.builder import Builder
from honeyd.core.dispatcher import Dispatcher

from honeyd.utilities.hpfeeds import HPFeedsLogger

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
    # print('Honeyd {0}'.format(honeyd.__version__))

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


def parse_arguments():
    parser = argparse.ArgumentParser(description='Honeyd')
    parser.add_argument("--version", action="store_true", default=False, help="Print Honeyd version and exit")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Enables logging of debug messages")
    parser.add_argument("-w", "--workdir", help="Set Honeyd working directory", dest="workdir", default=os.getcwd())
    parser.add_argument("-l", "--logfile", help="Set logfile path and name", default="honeyd.log")
    parser.add_argument("-c", "--config", help="Set configuration file path and name", default=os.path.join(package_directory, "templates/honeyd.xml"))
    parser.add_argument("-u", "--uid", help="Set the user id Honeyd should run as", default=None)
    parser.add_argument("-g", "--gid", help="Set the group id Honeyd should run as", default=None)
    parser.add_argument("-i", "--interface", action="append", help="Listen on interface", default=[])
    parser.add_argument("-a", "--address", action="append", help="Reply to ARP requests matching address", default=[])
    parser.add_argument("-o", "--os-fingerprint", help="Set nmap-style fingerprints file location", default=os.path.join(package_directory, "templates/nmap-os-db"))
    parser.add_argument("-m", "--mac-prefix", help="Set nmap-mac-prefixes file location", default=os.path.join(package_directory, "templates/nmap-mac-prefixes"))

    args = parser.parse_args()

    if args.version:
        logo()
        sys.exit(0)

    return args

def prepare_environment(work_directory):
    # TODO: set up database environment
    pass

def setup_os_fingerprints(file):
    if not os.path.isfile(file):
      try:
          logger.info('Retrieving Nmap fingerprint database')
          urllib.urlretrieve("https://svn.nmap.org/nmap/nmap-os-db", os.path.join(package_directory, "templates/nmap-os-db"))
      except ContentTooShortError:
          logger.exception('Connection interupted: nmap-os-db retrieval failed')

def setup_mac_prefix(file):
    if not os.path.isfile(file):
      try:
          logger.info('Retrieving Nmap MAC prefix database')
          urllib.urlretrieve("https://svn.nmap.org/nmap/nmap-mac-prefixes", os.path.join(package_directory, "templates/nmap-mac-prefixes"))
      except ContentTooShortError:
          logger.exception('Connection interupted: nmap-mac-prefixes retrieval failed')

def unhandled_exception(greenlet):
    logger.error('Stopping honeypot: %s is dead: %s', greenlet, greenlet.exception)
    sys.exit(1)

def main():

    args = parse_arguments()

    setup_logging(args.logfile, args.verbose)

    # set up database environment
    if os.path.isdir(os.path.join(args.workdir, 'honeyd_data/')):
        prepare_environment(args.workdir)

    if not os.path.isfile(args.config):
        args.config = os.path.join(package_directory, 'templates/honeyd.conf')
        logger.info('No honeyd.conf found in current directory, using default configuration: %s', args.config)

    setup_os_fingerprints(args.os_fingerprint)
    setup_mac_prefix(args.mac_prefix)
    
    # TODO: handle arguments
    hpfeeds = HPFeedsLogger(args.workdir)

    network, default, devices, routes, externals = Builder().build_network(args.config, args.os_fingerprint, args.mac_prefix)

    valid_interfaces = netifaces.interfaces()
    # ensure only valid interfaces are listed - safe call of system shell
    arpd_interfaces = list()
    dispatcher = list()
    for interface in args.interface:
        if interface in valid_interfaces:
            arpd_interfaces.append(interface)
             # dispatcher.append(Dispatcher(interface, network, default, (devices, routes, externals), hpfeeds))
        else:
            logger.info('No valid interface detected for %s, ignoring configuration', interface)

    # filter out non-CIDR notation
    arpd_address = list()
    for address in args.address:
        # matches ddd.ddd.ddd.ddd, ddd.ddd.ddd.ddd/dd, ddd.ddd.ddd.ddd-ddd.ddd.ddd.ddd
        # ((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(([/](3[01]|[0-2]?[0-9]))|([-]((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))?
        is_cidr = re.match('((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(([/](3[01]|[0-2]?[0-9]))|([-]((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))?', address)
        if is_cidr is not None:
            arpd_address.append(address)
    # call farpd for all interfaces
    try:
        # call(['arpd', arpd_interfaces])
        arp_daemon = gevent.subprocess.Popen(['farpd', '-d', '-i', ' '.join(arpd_interfaces), ' '.join(arpd_address)], stdout=None, stderr=None)
    except Exception as ex:
        logger.error('Cannot invoke arpd process on interfaces %s => %s', arpd_interfaces, ex)
        sys.exit(1)
    greenlet = list()
    for interface in arpd_interfaces:
        # spawn dispatcher for each interface
        greenlet.append(gevent.spawn(Dispatcher, interface, network, default, (devices, routes, externals), hpfeeds))
        # greenlet.append(gevent.spawn(listener.start))
        # greenlest.link_exception(unhandled_exception)

    # we might not be able to drop privileges as we are using raw sockets
    # drop_privileges(args.uid, args.gid)
    
    try:
        gevent.joinall(greenlet)
    except KeyboardInterrupt:
        logging.info('Stopping Honeyd.')
        logging.info('Terminating arpd daemon.')
        arp_daemon.kill()
    
    if arp_daemon:
        logging.info('Terminating arpd daemon.')
        arp_daemon.kill()

if __name__ == "__main__":
    main()

