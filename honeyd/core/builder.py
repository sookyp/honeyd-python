#!/usr/bin/env python

import sys
import logging
import networkx
import ipaddress

from lxml import etree

from honeyd.core.parser import Parser
from honeyd.core.element import Device, Route, External

logger = logging.getLogger(__name__)

class Builder(object):
    """
      Network builder is responsible for validating and parsing the configuration and creating the structure of objects representing the network
    """

    def build_network(self, config_file, fp_file, mac_file):
        logger.debug('Validating configuration file %s', config_file)
        self.validate_template(config_file, "honeyd/templates/honeyd.xsd")
        logger.debug('Parsing configuration file %s', config_file)
        devices, routes, externals = self.parse_configuration(config_file, fp_file, mac_file)

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
            default = Device('default', default_personality, '00:08:c7:1b:8c:02', {'tcp':'closed', 'udp':'closed', 'icmp':'closed'}, list(), list())

        logger.info('Building virtual network')
        # TODO: ensure user cannot configure bad network
        # implement a structure defining the network
        network = networkx.Graph()
        # add routers as nodes
        for route in routes:
           network.add_node(route.ip)
           network.add_nodes_from(route.link_list)

        # for device in devices:
        #     network.add_nodes_from(device.bind_list)
        # for external in externals:
        #     network.add_node(external.ip)

        # add connections as edges
        for route in routes:
            # add edges between routers
            edge_list = [(route.ip, connect, { 'latency':route.latency, 'loss':route.loss } ) for connect in route.connect_list]
            network.add_edges_from(edge_list)
            # add edges between link subnets and routers
            edge_list = [(route.ip, link, { 'latency':route.latency, 'loss':route.loss } ) for link in route.link_list]
            network.add_edges_from(edge_list)

        return (network, default, devices, routes, externals)

    def parse_configuration(self, config_file, fp_file, mac_file):
        dom_template = etree.parse(config_file)
        device_template = dom_template.xpath('//network_configuration/device_information/*')
        routing_template = dom_template.xpath('//network_configuration/routing_information/*')
        external_template = dom_template.xpath('//network_configuration/external/*')

        device_list = list()
        route_list = list()
        external_list = list()

        personality_parser = Parser(fp_file, mac_file)

        # device section of the configuration
        if device_template:
            for entry in device_template:

                # name
                name = entry.xpath('./name/text()')[0]

                # personality
                personality_name = entry.xpath('./personality/text()')[0]
                personality = personality_parser.parse(personality_name)

                #ethernet
                ethernet = entry.xpath('./ethernet/text()')
                if len(ethernet):
                    ethernet = ethernet[0]
                else:
                    # TODO: random generation according to personality OUI
                    ethernet = '00:00:00:00:00:00'

                # actions
                action = dict()
                action['tcp'] = entry.xpath('./action/@tcp')[0]
                action['udp'] = entry.xpath('./action/@udp')[0]
                action['icmp'] = entry.xpath('./action/@icmp')[0]
                for key, value in action.items():
                    if value.lower() not in ['block', 'open', 'closed', 'filtered'] or not value.lower().startswith('proxy '):
                        logger.error('Error invalid action defined in configuration at Name: %s Protocol: %s Value: %s.', personality_name, key, value)
                        sys.exit(1)
                    if value.lower().startswith('proxy '):
                        proxy_data = value[len('proxy '):].split(':')
                        if len(proxy_data) != 2:
                            logger.error('Error invalid proxy defined in configuration at Name: %s Protocol: %s Value: %s.', personality_name, key, value)
                            sys.exit(1)
                        try:
                            ipaddress.ip_address(unicode(proxy_data[0]))
                            int(proxy_data[1], 10)
                        except ValueError:
                            logger.error('Error invalid IP address or port number defined in configuration at Name: %s Protocol: %s Value: %s.', personality_name, key, value)
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

                        # execute action
                        execute = service.xpath('./@execute')[0]

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
                    latency = latency[0]
                else:
                    latency = 0

                loss = entry.xpath('./@loss')
                if len(loss):
                    loss = loss[0]
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

        return device_list, route_list, external_list

    def validate_template(self, xml_file, xsd_file):
        xml_schema = etree.parse(xsd_file)
        xsd = etree.XMLSchema(xml_schema)
        xml = etree.parse(xml_file)
        xsd.validate(xml)
        if xsd.error_log:
            logger.error('Error parsing configuration template: %s', xsd.error_log)
            sys.exit(1)
