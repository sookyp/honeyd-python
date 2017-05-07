#!/usr/bin/env python2.7

from gevent import monkey; monkey.patch_all()
from bottle import run, get, route, redirect, error, request, static_file, template
from json import loads

"""
    In order to be able to inject HTML code, we disable character escaping - XSS vulnerable
"""
# TODO: remove globals
global_cnt=0
global_src_ip=dict()
global_dst_ip=dict()
global_proto=dict()

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
    # overall recevied packets
    global_cnt += 1

    data = loads(post)
    # print data

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

# redirect any attempts to non-existing pages to the main page
@error(404)
def error404(error):
    msg = """Non-existent page"""
    return template('honeyd/utilities/http/index.html', data=msg)

# css declaration
@get('/css/<filepath:re:.*\.css>')
def css(filepath):
    return static_file(filepath, root='honeyd/utilities/http/css/')

# main page
@get('/')
@get('/index.html')
def index():
    test = "<b>Honeyd-python web server testing home page.</b>"
    return template('honeyd/utilities/http/index.html', data=test)

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
            <td>Overall recevied packets</td>
            <td>""" + str(global_cnt) + """</td>
          </tr>
        </table>
        """
    # source ip table
    overall_src_ip = """\
        <table border="1">
          <tr>
            <th>Source IPs</th>
            <th>Amount #</th>
          </tr>"""
    for k,v in global_src_ip.items():
      overall_src_ip += """\
          <tr>
            <td>""" + str(k) + """</td>
            <td>""" + str(v) + """</td>
          </tr>
        """
    overall_src_ip += """\
          </table>
        """
    # destination ip table
    overall_dst_ip = """\
        <table border="1">
          <tr>
            <th>Destination IPs</th>
            <th>Amount #</th>
          </tr>"""
    for k,v in global_dst_ip.items():
      overall_dst_ip += """\
          <tr>
            <td>""" + str(k) + """</td>
            <td>""" + str(v) + """</td>
          </tr>
        """
    overall_dst_ip += """\
          </table>
        """
    # protocol table
    overall_proto = """\
        <table border="1">
          <tr>
            <th>Protocol number</th>
            <th>Amount #</th>
          </tr>"""
    for k,v in global_proto.items():
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
    test = "Not implemented."
    return template('honeyd/utilities/http/index.html', data=test)

# TODO: catch exceptions -> KeyboardInterrupt, other possible values
run(host='localhost', port=8080, server='gevent')
