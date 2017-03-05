#!/usr/bin/env python

import logging

import sys
import os
import mmap
import re

logger = logging.getLogger(__name__)

class Parser(object):
    """
    Responsible for parsing the nmap-os-db and nmap-mac-prefixes files and creating the approrpiate personality structure.
    """
    def __init__(self, fingerprint_file, mac_file):
        fd_fingerprint_file = open(fingerprint_file)
        self.fingerprint_file = mmap.mmap(fd_fingerprint_file.fileno(), 0, access=mmap.ACCESS_READ)

        fd_mac_file = open(mac_file)
        self.mac_file = mmap.mmap(fd_mac_file.fileno(), 0, access=mmap.ACCESS_READ)

    def parse(self, personality):
        logger.debug('Initializing personality for device %s', personality)
        # first occurence of fingerprint name and empty line delimiter
        start_index = self.fingerprint_file.find('Fingerprint ' + personality)
        end_index = self.fingerprint_file.find('\n\n', start_index)

        try:
            self.fingerprint_file.seek(start_index, os.SEEK_SET)
            fingerprint_section = self.fingerprint_file.read(end_index - start_index).splitlines()
        except ValueError:
            logger.exception('Personality %s not found.', personality)
            sys.exit(1)

        p = Personality()

        # File contents defined at https://nmap.org/book/osdetect-methods.html
        for line in fingerprint_section:
            if line.startswith('Fingerprint'):
                # free text description
                p.fp_name = line[len('Fingerprint '):]
                continue
            if line.startswith('Class '):
                # vendor | OS family | OS generation | device type
                p.fp_class.append(dict(zip(['vendor', 'family', 'generation', 'type'], line[len('Class '):].split('|'))))
                continue
            if line.startswith('CPE '):
                # cpe:/(a|h|o):vendor:product:version:update:edition:language auto
                fp_cpe = line[len('CPE cpe:/'):].split(':')
                # strip the section indicating the generation method
                index = fp_cpe[-1].find(' ')
                if index != -1:
                    fp_cpe[-1] = fp_cpe[-1][:index]
                p.fp_cpe.append(dict(zip(['part', 'vendor', 'product', 'version', 'update', 'edition', 'language'], fp_cpe)))
                continue
            if line.startswith('SEQ('):
                # GCD % SP % ISR % TI % II % TS
                p.fp_seq = { key:value for (key, value) in (item.split('=') for item in line[len('SEQ('):-1].split('%'))}
                continue
            if line.startswith('OPS('):
                # O1 % O2 % O3 % O4 % O5 % O6
                p.fp_ops = { key:value for (key, value) in (item.split('=') for item in line[len('OPS('):-1].split('%'))}
                continue
            if line.startswith('WIN('):
                # W1 % W2 % W3 % W4 % W5 % W6
                p.fp_win = { key:value for (key, value) in (item.split('=') for item in line[len('WIN('):-1].split('%'))}
                continue
            if line.startswith('ECN('):
                # R % DF % T % TG % W % O % CC % Q
                p.fp_ecn = { key:value for (key, value) in (item.split('=') for item in line[len('ECN('):-1].split('%'))}
                continue
            if line.startswith('T'):
                # R % DF % T % TG % W % S % A % F % O % RD % Q
                fp_ti = { key:value for (key, value) in (item.split('=') for item in line[len('Ti('):-1].split('%'))}
                p.fp_ti.update({line[:2] : fp_ti})
                continue
            if line.startswith('U1('):
                # R % DF % T % TG % IPL & UN % RIPL % RID % RUCK % RUD
                p.fp_u1 = { key:value for (key, value) in (item.split('=') for item in line[len('U1('):-1].split('%'))}
                continue
            if line.startswith('IE('):
                # R % DFI % T % TG % CD
                p.fp_ie = { key:value for (key, value) in (item.split('=') for item in line[len('IE('):-1].split('%'))}
                continue
        # fingerprint parsing is done

        # TODO: remove if not necessary
        logger.debug('Initializing MAC OUI for device %s', personality)
        # TODO: find something we can use as mapping from fingerprint file to mac prefix file
        vendor_list = [item['vendor'] for item in p.fp_class]
        while p.mac_oui is None:
            if len(vendor_list):
                current_vendor = vendor_list.pop()
                # looking for exact matches
                match = re.match('^([0-9A-F]{6})\s' + current_vendor + '$', self.mac_file, re.MULTILINE)
                if match is not None:
                    p.mac_oui = match.group(1)
            else:
                # TODO: generate one randomly
                logger.warning('No MAC OUI found for given vendors. Personality: %s', p.fp_name)
                p.mac_oui = "000000"
        # mac parsing is done

        return p

    def close_files(self):
        self.fingerprint_file.close()
        self.mac_file.close()

class Personality(object):
    """
    Defines structure of device personalities, containing device MAC OUI and response requirements to nmap scans
    """
    def __init__(self):
        self.mac_oui = None

        self.fp_name = None

        self.fp_class = list()
        self.fp_cpe = list()

        self.fp_seq = dict()
        self.fp_ops = dict()
        self.fp_win = dict()
        self.fp_ecn = dict()
        self.fp_ti = dict()
        self.fp_u1 = dict()
        self.fp_ie = dict()
