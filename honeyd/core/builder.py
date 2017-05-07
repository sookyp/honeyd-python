#!/usr/bin/env python

import logging
import os
import sys
import re
import random
import networkx
import ipaddress
import netifaces
import subprocess

from json import loads
from lxml import etree
from ConfigParser import ConfigParser, NoSectionError, NoOptionError

from honeyd.core.parser import Parser
from honeyd.core.element import Device, Route, External
from honeyd.utilities.fetch_public_ip import get_ext_ip

logger = logging.getLogger(__name__)


class Builder(object):
    """
      Network builder is responsible for validating and parsing the configuration and creating the structure of objects representing the network
    """

    def build_network(self, work_dir, config_file, network_file, fp_file, mac_file):
        logger.debug('Validating configuration file %s', network_file)
        xsd_file_location = os.path.join(work_dir, "templates/honeyd.xsd")
        config_file_location = os.path.join(work_dir, config_file)
        self.validate_template(network_file, xsd_file_location)
        logger.debug('Parsing configuration file %s', network_file)
        devices, routes, externals, tunnels = self.parse_configuration(
            network_file, fp_file, mac_file, config_file_location)

        # get default template
        default = None
        for device in devices:
            if device.name.lower() == 'default':
                default = device
                devices.remove(default)
                break

        # build default template
        if default is None:
            personality_parser = Parser(fp_file, mac_file)
            default_personality = personality_parser.parse('Linux 2.6.31')
            default = Device('default', default_personality, '00:08:c7:1b:8c:02', {
                             'tcp': 'closed', 'udp': 'closed', 'icmp': 'closed'}, list(), list())

        logger.info('Building virtual network.')
        # TODO: ensure user cannot configure bad network
        # implement a structure defining the network
        network = networkx.Graph()
        # add routers as nodes
        for route in routes:
            network.add_node(route.ip)
            network.add_nodes_from(route.link_list)

        # add connections as edges
        for route in routes:
            # add edges between routers
            edge_list = [(route.ip, connect, {'latency': route.latency, 'loss': route.loss})
                         for connect in route.connect_list]
            network.add_edges_from(edge_list)
            # add edges between link subnets and routers
            edge_list = [(route.ip, link, {'latency': route.latency, 'loss': route.loss}) for link in route.link_list]
            network.add_edges_from(edge_list)

        return (network, default, devices, routes, externals, tunnels)

    def parse_configuration(self, network_file, fp_file, mac_file, config_file):
        dom_template = etree.parse(network_file)
        device_template = dom_template.xpath('//network_configuration/device_information/*')
        routing_template = dom_template.xpath('//network_configuration/routing_information/*')
        external_template = dom_template.xpath('//network_configuration/external/*')

        device_list = list()
        route_list = list()
        external_list = list()
        tunnel_dict = dict()

        personality_parser = Parser(fp_file, mac_file)
        if device_template:
            for entry in device_template:

                # name
                name = entry.xpath('./name/text()')[0]

                # personality
                personality_name = entry.xpath('./personality/text()')[0]
                personality = personality_parser.parse(personality_name)

                # ethernet
                ethernet = entry.xpath('./ethernet/text()')
                if len(ethernet):
                    # extract for valid mac address format
                    match = re.match('((?:[0-9a-fA-F]{2}:){5}(?:[0-9a-fA-F]){2})', ethernet[0])
                    if match is not None:
                        ethernet = match.group(1)
                        logger.debug('Using defined MAC address %s for device %s', ethernet, name)
                    else:
                        # treat as vendor list
                        vendors = [e.strip() for e in ethernet[0].split(',')]
                        personality_parser.get_mac_oui(personality, vendor_list=vendors)
                        addr = personality.mac_oui + hex(random.randrange(16**6))[2:]
                        ethernet = ':'.join(addr[i:i + 2] for i in range(0, len(addr), 2))
                        logger.debug('Using vendor generated MAC address %s for device %s', ethernet, name)
                else:
                    # randomly generate
                    personality_parser.get_mac_oui(personality)
                    addr = personality.mac_oui + hex(random.randrange(16**6))[2:]
                    ethernet = ':'.join(addr[i:i + 2] for i in range(0, len(addr), 2))
                    logger.debug('Using randomly generated MAC address %s for device %s', ethernet, name)

                # actions
                action = dict()
                action['tcp'] = entry.xpath('./action/@tcp')[0]
                action['udp'] = entry.xpath('./action/@udp')[0]
                action['icmp'] = entry.xpath('./action/@icmp')[0]
                for key, value in action.items():
                    if not (value.lower() in ['block', 'open', 'closed', 'filtered']
                            or value.lower().startswith('proxy ')):
                        logger.error(
                            'Error: Invalid action defined in configuration at Name: %s Protocol: %s Value: %s.',
                            personality_name,
                            key,
                            value)
                        sys.exit(1)
                    if value.lower().startswith('proxy '):
                        proxy_data = value[len('proxy '):].split(':')
                        if len(proxy_data) != 2:
                            logger.error(
                                'Error: Invalid proxy defined in configuration at Name: %s Protocol: %s Value: %s.',
                                personality_name,
                                key,
                                value)
                            sys.exit(1)
                        try:
                            remote_ip = ipaddress.ip_address(unicode(proxy_data[0]))
                            if proxy_data[1].lower() in ['gre', 'ipip']:
                                remote_mode = proxy_data[1].lower()
                            else:
                                logger.error(
                                    'Error: Invalid tunnel mode defined in configuration at Name: %s Protocol: %s Value: %s. Possible values are \"gre\" and \"ipip\".',
                                    personality_name,
                                    protocol,
                                    execute)
                                sys.exit(1)
                            if remote_ip not in tunnel_dict.keys():
                                tunnel_dict[remote_ip] = remote_mode
                        except ValueError:
                            logger.error(
                                'Error: Invalid IP address or tunnel mode defined in configuration at Name: %s Protocol: %s Value: %s.',
                                personality_name,
                                key,
                                value)
                            sys.exit(1)

                # services
                service_list = list()
                service_template = entry.xpath('./service_list/*')
                if service_template:
                    for service in service_template:

                        # protocol
                        protocol = service.xpath('./@protocol')[0]

                        # port
                        port = service.xpath('./@port')[0]
                        try:
                            port = int(port, 10)
                        except ValueError:
                            logger.error(
                                'Error: Invalid port number defined in configuration at Name: %s Protocol: %s Value: %s.',
                                personality_name,
                                protocol,
                                port)
                            sys.exit(1)

                        # execute action
                        execute = service.xpath('./@execute')[0]
                        if execute.lower().startswith('proxy '):
                            proxy_data = execute[len('proxy '):].split(':')
                            if len(proxy_data) != 2:
                                logger.error(
                                    'Error: Invalid proxy defined in configuration at Name: %s Protocol: %s Value: %s.',
                                    personality_name,
                                    protocol,
                                    execute)
                                sys.exit(1)
                            try:
                                remote_ip = ipaddress.ip_address(unicode(proxy_data[0]))
                                if proxy_data[1].lower() in ['gre', 'ipip']:
                                    remote_mode = proxy_data[1].lower()
                                else:
                                    logger.error(
                                        'Error: Invalid tunnel mode defined in configuration at Name: %s Protocol: %s Value: %s. Possible values are \"gre\" and \"ipip\".',
                                        personality_name,
                                        protocol,
                                        execute)
                                    sys.exit(1)
                                if remote_ip not in tunnel_dict.keys():
                                    tunnel_dict[remote_ip] = remote_mode
                            except ValueError:
                                logger.error(
                                    'Error: Invalid IP address or tunnel mode defined in configuration at Name: %s Protocol: %s Value: %s.',
                                    personality_name,
                                    protocol,
                                    execute)
                                sys.exit(1)

                        service_list.append((protocol, port, execute))

                # binds
                bind_list = list()
                bind_template = entry.xpath('./bind_list/*')
                if bind_template:
                    for bind in bind_template:

                        # ip address
                        ip = bind.xpath('./@ip')[0]
                        bind_list.append(unicode(ip))

                # build network devices
                device_list.append(Device(name, personality, ethernet, action, service_list, bind_list))

        # create tunnels
        assignment_list = self.setup_tunnels(tunnel_dict, config_file)

        personality_parser.close_files()
        # routing section of the configuration
        if routing_template:
            for entry in routing_template:

                # ip
                ip = entry.xpath('./@ip')[0]
                ip = unicode(ip)

                # subnet address
                subnet = entry.xpath('./@subnet')[0]
                subnet = unicode(subnet)

                entry_point = entry.xpath('./@entry')
                if len(entry_point):
                    entry_point = entry_point[0]
                else:
                    entry_point = "false"

                latency = entry.xpath('./@latency')
                if len(latency):
                    try:
                        latency = int(latency[0], 10)
                    except BaseException:
                        logger.exception('Exception: Invalid latency value given %s', latency[0])
                        latency = 0
                else:
                    latency = 0

                loss = entry.xpath('./@loss')
                if len(loss):
                    try:
                        loss = int(loss[0], 10)
                    except BaseException:
                        logger.exception('Exception: Invalid loss value given %s', loss[0])
                        loss = 0
                else:
                    loss = 0

                connect_list = [unicode(child.text) for child in entry.iter('connect')]
                link_list = [unicode(child.text) for child in entry.iter('link')]
                unreach_list = [unicode(child.text) for child in entry.iter('unreach')]

                # build network routes
                route_list.append(Route(ip, subnet, entry_point, latency, loss, connect_list, link_list, unreach_list))

        if external_template:
            for entry in external_template:

                # ip address
                ip = entry.xpath('./@ip')[0]
                ip = unicode(ip)

                # interface
                interface = entry.xpath('./@interface')[0]

                # build externals
                external_list.append(External(ip, interface))

        return device_list, route_list, external_list, assignment_list

    def validate_template(self, xml_file, xsd_file):
        xml_schema = etree.parse(xsd_file)
        xsd = etree.XMLSchema(xml_schema)
        xml = etree.parse(xml_file)
        xsd.validate(xml)
        if xsd.error_log:
            logger.error('Error: Problem with parsing configuration template: %s', xsd.error_log)
            sys.exit(1)

    def setup_tunnels(self, tunnels, config):
        logging.debug('Creating tunnel interfaces.')
        """
        ### modprobe tun
        ### lsmod |grep tun
        ### ip tunnel add tun0 mode ipip remote 202.182.ab.cd local 203.153.xxx.xx
        ### ifconfig tun0 202.182.ab.254 netmask 255.255.255.252 pointopoint 202.182.ab.253
        ### ifconfig tun0 mtu 1500 up
        ### ip link set tun0 up

            HOST A
        $ sudo modprobe ip_gre
        $ lsmod | grep gre
        $ sudo ip tunnel add gre0 mode gre remote 172.168.10.25 local 192.168.233.204 ttl 255
        $ sudo ip link set gre0 up
        $ sudo ip addr add 10.10.10.1/24 dev gre0
        $ ip route show

            HOST B
        $ sudo ip tunnel add gre0 mode gre remote 192.168.233.204 local 172.168.10.25 ttl 255
        $ sudo ip link set gre0 up
        $ sudo ip addr add 10.10.10.2/24 dev gre0
        """

        assignments = list()
        parser = ConfigParser()
        parser.read(config)
        try:
            urls = loads(parser.get('tunnel', 'urls'))
            iface = parser.get("tunnel", "interface")
            tunnel_id = int(parser.getint("tunnel", "startid"))
            subnet = parser.get("tunnel", "subnet")
            public_ip = parser.getboolean("tunnel", "use_public")
        except (NoSectionError, NoOptionError):
            logger.error('Error: Incomplete honeyd.cfg configuration.')
            sys.exit(1)

        if public_ip:
            local_ip = get_ext_ip(urls)
            if not local_ip:
                sys.exit(1)
        else:
            if iface not in netifaces.interfaces():
                logger.error('Error: Interface does not exist on local machine.')
                sys.exit(1)
            local_ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            logger.info('Using local IP %s from configured interface %s', local_ip, iface)

        try:
            iface_ip = ipaddress.ip_network(unicode(subnet))
        except ValueError:
            logger.error('Error: Invalid IP subnet in tunnel configuration: %s.', subnet)
            sys.exit(1)

        hosts = list(iface_ip.hosts())
        if len(hosts) < len(tunnels.keys()):
            logger.error('Error: Not enough IPs in configured subnet for all proxies.')
            sys.exit(1)

        # check module
        for mode in ['ipip', 'ip_gre']:
            code = subprocess.call(['modprobe', mode])
            if code:
                logger.error('Error: Cannot load kernel module: %s', mode)
                subprocess.Popen(['modprobe', '-r', 'ipip'])
                subprocess.Popen(['modprobe', '-r', 'ip_gre'])
                sys.exit(1)

        for i in range(0, len(tunnels.keys())):
            tunnel_id += 1
            remote_ip = tunnels.keys()[i]
            remote_mode = tunnels.values()[i]
            name = 'tun' + str(tunnel_id)
            subprocess.Popen(['ip', 'tunnel', 'add', name, 'mode', remote_mode, 'remote', str(
                remote_ip), 'local', local_ip, 'ttl', '255'], stdout=subprocess.PIPE)
            subprocess.Popen(['ip', 'link', 'set', name, 'up'], stdout=subprocess.PIPE)
            subprocess.Popen(['ip', 'addr', 'add', str(hosts[i]), 'dev', name], stdout=subprocess.PIPE)
            assignments.append((name, remote_ip, remote_mode))

        return assignments

    def teardown_tunnels(self, tunnels, work_dir, config_file):
        logging.debug('Destroying tunnel interfaces.')
        """
        $ sudo ip link set gre0 down
        $ sudo ip tunnel del gre0
        """

        config_file_location = os.path.join(work_dir, config_file)
        parser = ConfigParser()
        parser.read(config_file)
        try:
            tunnel_id = int(parser.getint("tunnel", "startid"))
        except (NoSectionError, NoOptionError):
            logger.error('Error: Incomplete honeyd.cfg configuration.')
            sys.exit(1)

        # for t in tunnels:
        for i in range(0, len(tunnels)):
            tunnel_id += 1
            name = 'tun' + str(tunnel_id)
            subprocess.Popen(['ip', 'link', 'set', name, 'down'])
            subprocess.Popen(['ip', 'tunnel', 'del', name])
        for mode in ['ipip', 'ip_gre']:
            subprocess.Popen(['modprobe', '-r', mode])
