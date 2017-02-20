#!/usr/bin/env python

import sys
import logging
import networkx

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
            default = Device('default', 'Linux 2.6.31', {'tcp':'closed', 'udp':'closed', 'icmp':'closed'}, list(), list())

        logger.info('Building virtual network')
        # implement a structure defining the network
        network = networkx.Graph()
        # add devices and externals as nodes
        for device in devices:
            network.add_nodes_from(device.bind_list)
        for external in externals:
            network.add_node(external.ip)

        # add connections as edges
        for route in routes:
            edge_list = [(route.ip, link) for link in route.link_list]
            network.add_edges_from(edge_list)
            # (?) maybe add the reachable subnets as well with default templates (?)

        # all others are considered to be handled by the default template
        # we can use has_path() to find out if we have to use the default template or not - we have to check the reachable subnets though !
        # we can use shortest_path() to find the route from entry to target

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

                # actions
                action = dict()
                action['tcp'] = entry.xpath('./action/@tcp')[0]
                action['udp'] = entry.xpath('./action/@udp')[0]
                action['icmp'] = entry.xpath('./action/@icmp')[0]

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

                        bind_list.append(ip)

                # build network devices
                device_list.append(Device(name, personality, action, service_list, bind_list))

        personality_parser.close_files()
        # routing section of the configuration
        if routing_template:
            for entry in routing_template:

                # ip
                ip = entry.xpath('./@ip')[0]

                # subnet address
                subnet = entry.xpath('./@subnet')[0]

                entry_point = entry.xpath('./@entry')
                if len(entry_point):
                    entry_point = entry_point[0]
                else:
                    entry_point = "false"

                link_list = [child.text for child in entry.iter('link')]
                unreach_list = [child.text for child in entry.iter('unreach')]

                # build network routes
                route_list.append(Route(ip, subnet, entry_point, link_list, unreach_list))


        if external_template:
            for entry in external_template:

                # ip address
                ip = entry.xpath('./@ip')[0]

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
