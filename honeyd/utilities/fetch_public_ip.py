#!/usr/bin/env python

import logging
import ipaddress

import requests
from requests.exceptions import Timeout, ConnectionError

logger = logging.getLogger(__name__)


def _verify_address(addr):
    try:
        ipaddress.ip_address(unicode(addr))
        return True
    except ValueError:
        return False


def _fetch_data(urls):
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
        except (Timeout, ConnectionError) as e:
            logger.warning('Could not fetch public ip from %s', url)
    return None


def get_ext_ip(urls=None):
    public_ip = _fetch_data(urls)
    if public_ip:
        logger.info('Fetched %s as external ip.', public_ip)
    else:
        logger.warning('Could not fetch public ip: %s', public_ip)
    return public_ip
