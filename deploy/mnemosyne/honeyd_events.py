import json

from normalizer.modules.basenormalizer import BaseNormalizer


class Honeyd(BaseNormalizer):
    channels = ('honeyd.events',)

    def normalize(self, data, channel, submission_timestamp, ignore_rfc1918=True):
        o_data = self.parse_record_data(data)

        if ignore_rfc1918 and self.is_RFC1918_addr(o_data['ip_src']):
            return []

        session = {
            'timestamp': submission_timestamp,
            'source_ip': o_data['ip_src'],
            'source_port': o_data['port_src'],
            'destination_ip': o_data['ip_dst'],
            'destination_port': o_data['port_dst'],
            'honeypot': 'honeyd',
            'protocol': o_data['protocol']
            }
        relations = {'session': session}

return [relations]