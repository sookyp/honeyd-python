#!/usr/bin/env python
"""Utility for obtaining public facing IP address of machine"""
import logging
import ipaddress

import requests
from requests.exceptions import Timeout, ConnectionError

logger = logging.getLogger(__name__)


def _verify_address(addr):
    """Function verifies that address is valid IPv4 address
    Args:
        addr : address of machine
    Return:
        boolean value defining validity of address
    """
    try:
        ipaddress.ip_address(unicode(addr))
        return True
    except ValueError:
        return False


def _fetch_data(urls):
    """Function obtains ip address by query
    Args:
        urls : list of urls used for query
    Return:
        ip address of machine
    """
    logging.getLogger("requests").setLevel(logging.WARNING)
    for url in urls:
        try:
            req = requests.get(url, timeout=3)
            if req.status_code == 200:
                data = req.text.strip()
                if data is None or not _verify_address(data):
                    continue
                else:
                    return data
            else:
                raise ConnectionError
        except (Timeout, ConnectionError):
            logger.warning('Could not fetch public ip from %s', url)
    return None


def get_ext_ip(urls=None):
    """Function oversees the ip address fetching process"""
    public_ip = _fetch_data(urls)
    if public_ip:
        logger.info('Fetched %s as external ip.', public_ip)
    else:
        logger.warning('Could not fetch public ip: %s', public_ip)
    return public_ip
