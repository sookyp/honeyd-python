#!/usr/bin/env python
"""Web server for visualizing attack related information"""
# In order to be able to inject HTML code, we disable character escaping - XSS vulnerable
import sys
import signal

from gevent import monkey
monkey.patch_all()
from bottle import run, get, route, error, request, static_file, template
from json import loads, dumps
from datetime import datetime

import networkx
from networkx.readwrite import json_graph

# requirements for graphs
import matplotlib.pyplot as plt
from io import BytesIO
import base64

global_cnt = 0
global_src_ip = dict()
global_dst_ip = dict()
global_proto = dict()
network_graph = None
start_time = datetime.utcnow()


@route('/post', method='POST')
def post_data():
    global global_cnt
    global global_src_ip
    global global_dst_ip
    global global_proto
    try:
        post = request.json
    except IndexError:
        pass
    # overall received packets
    global_cnt += 1

    data = loads(post)

    # src ip distribution
    if data[u'ip_src'] in global_src_ip.keys():
        global_src_ip[data[u'ip_src']] += 1
    else:
        global_src_ip[data[u'ip_src']] = 1

    # dst ip distribution
    if data[u'ip_dst'] in global_dst_ip.keys():
        global_dst_ip[data[u'ip_dst']] += 1
    else:
        global_dst_ip[data[u'ip_dst']] = 1

    # proto distribution
    if data[u'protocol'] in global_proto.keys():
        global_proto[data[u'protocol']] += 1
    else:
        global_proto[data[u'protocol']] = 1


@route('/network', method='POST')
def network():
    global network_graph
    try:
        graph_json = request.json
    except IndexError:
        pass

    # some network nodes could be removed from the graph to avoid confusing the user
    # the graph contains 
    network_json = loads(graph_json)
    G = json_graph.node_link_graph(network_json)
    fig = plt.figure()
    plt.axis('off')
    networkx.draw_networkx(G, node_size=80, node_color='c', font_size=8)
    network_graph = BytesIO()
    fig.savefig(network_graph, format='png')

# redirect any attempts to non-existing pages to the main page


@error(404)
def error404(error):
    msg = """Non-existent page"""
    return template('honeyd/utilities/http/index.html', data=msg)

# css declaration


@get(r'/css/<filepath:re:.*\.css>')
def css(filepath):
    return static_file(filepath, root='honeyd/utilities/http/css/')

# main page


@get('/')
@get('/index.html')
def index():
    global network_graph
    if network_graph is not None:
        content = """\
            Network configuration map : Routers and their reachable subnets<br>
            <img src="data:image/png;base64,
            """ + base64.b64encode(network_graph.getvalue()).decode('utf-8') + """\
                    "></img>"""
    else:
        content = "Honeyd server homepage."
    return template('honeyd/utilities/http/index.html', data=content)

# statistics page


@get('/statistics.html')
def statistics():
    global global_cnt
    global global_src_ip
    global global_dst_ip
    global global_proto
    # received table
    overall_table = """\
        <table border="1">
          <tr>
            <td>Overall received packets</td>
            <td>""" + str(global_cnt) + """</td>
          </tr>
        </table><br>
        """
    # source ip table
    overall_src_ip = """\
        <table border="1">
          <tr>
            <th>Source IPs</th>
            <th>Amount #</th>
          </tr>"""
    for k, v in global_src_ip.items():
        overall_src_ip += """\
          <tr>
            <td>""" + str(k) + """</td>
            <td>""" + str(v) + """</td>
          </tr>
        """
    overall_src_ip += """\
          </table><br>
        """
    # destination ip table
    overall_dst_ip = """\
        <table border="1">
          <tr>
            <th>Destination IPs</th>
            <th>Amount #</th>
          </tr>"""
    for k, v in global_dst_ip.items():
        overall_dst_ip += """\
          <tr>
            <td>""" + str(k) + """</td>
            <td>""" + str(v) + """</td>
          </tr>
        """
    overall_dst_ip += """\
          </table><br>
        """
    # protocol table
    overall_proto = """\
        <table border="1">
          <tr>
            <th>Protocol number</th>
            <th>Amount #</th>
          </tr>"""
    for k, v in global_proto.items():
        overall_proto += """\
          <tr>
            <td>""" + str(k) + """</td>
            <td>""" + str(v) + """</td>
          </tr>
        """
    overall_proto += """\
          </table>
        """
    content = overall_table + overall_src_ip + overall_dst_ip + overall_proto
    return template('honeyd/utilities/http/index.html', data=content)

# charts page


@get('/charts.html')
def charts():
    # basic pie chart, distribution of protocols - concept for placing images
    global global_proto
    fig = plt.figure()
    labels = global_proto.keys()
    sizes = global_proto.values()
    plt.pie(sizes, labels=labels)
    plt.axis('equal')
    figdata = BytesIO()
    fig.savefig(figdata, format='png')
    content = """\
            <img src="data:image/png;base64,
            """ + base64.b64encode(figdata.getvalue()).decode('utf-8') + """\
                    "></img>"""
    return template('honeyd/utilities/http/index.html', data=content)


def signal_termination_handler(signal, frame):
    end_time = datetime.utcnow()
    uptime = abs(end_time - start_time)
    stats = """\
STATISTICS LOG
--------------------------------------------------
Server uptime = {0} ({1}\t--\t{2})
Overall received packets = {3}
Source IP address distribution :
{4}
Destination IP address distribution :
{5}
Protocol distribution :
{6}
--------------------------------------------------
""".format(
    uptime,
    start_time.strftime("%Y-%m-%d %H:%M:%S"),
    end_time.strftime("%Y-%m-%d %H:%M:%S"),
    global_cnt,
    dumps(global_src_ip, indent=2),
    dumps(global_dst_ip, indent=2),
    dumps(global_proto, indent=2)
    )
    with open('statistics.log', 'w') as f:
        f.write(stats)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_termination_handler)
signal.signal(signal.SIGTERM, signal_termination_handler)

run(host='localhost', port=8080, server='gevent')
