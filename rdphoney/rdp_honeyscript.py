#!/usr/bin/env python

'''
Based on SendMeSpamIDS.py/standalone/rdp.py, work of Joerg Stephan
'''
__author__ = 'Alexander Merck<alexander.t.merck@gmail.com>, ' \
             'Jesse Bowling<jesse.bowling@duke.edu>, ' \
             'Joerg Stephan<https://github.com/johestephan>'

import argparse
import datetime
import getpass
import logging.handlers
import re
import socket
import sys
import os
from ConfigParser import ConfigParser

from output.hpfeeds import Output

# Configure logging to syslog and file
username = getpass.getuser()
logger = logging.getLogger(username)
logger.setLevel(logging.INFO)

console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
console_f = logging.Formatter('%(asctime)s %(name)s: %(levelname)s %(message)s')
console.setFormatter(console_f)

logger.addHandler(console)


def extract_username(data):
    match = re.search(r'mstshash=(?P<username>[a-zA-Z0-9-_@]+)', data)
    if match:
        return match.group('username')
    return None


def invoke_honeypot(addr, port, config):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveaddy = (addr, port)
    sock.bind(serveaddy)
    sock.listen(1)
    print
    config
    output = Output(config['server'], config['port'],
                    config['ident'], config['secret'],
                    config['debug'])
    output.start()

    while True:
        try:
            con, addy = sock.accept()
            data = con.recv(1024)  # receive maximum 1K data
            st = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            user = extract_username(data)
            entry = {"timestamp": st,
                     "src_ip": addy[0].strip(),
                     "src_port": addy[1],
                     "dst_ip": addr,
                     "dst_port": 3389,
                     "username": user,
                     }
            output.write(entry)
            logger.info("ip=%s, username=%s, datalen=%s", addy[0].strip(), user, str((len(data))))
            con.send("0x00000004 RDP_NEG_FAILURE")
            con.close()
        except Exception, e:
            logger.warning("EXCEPTION: %s", e)


def parse_config(config_file):
    if not os.path.isfile(config_file):
        sys.exit("Could not find configuration file: {0}".format(config_file))

    parser = ConfigParser()
    parser.read(config_file)

    config = dict()
    config['server'] = parser.get('output_hpfeeds', 'server')
    config['port'] = parser.get('output_hpfeeds', 'port')
    config['ident'] = parser.get('output_hpfeeds', 'identifier')
    config['secret'] = parser.get('output_hpfeeds', 'secret')
    config['debug'] = parser.get('output_hpfeeds', 'debug')
    return config


def main():
    oparser = argparse.ArgumentParser(description='Instantiate a simple RDP honeypot',
                                      epilog='http://xkcd.com/353/')
    oparser.add_argument('-p', '--port',
                         required=False,
                         default=3389,
                         type=int,
                         help='Port to start "RDP" listener on')
    oparser.add_argument('-i', '--ip',
                         required=False,
                         default='0.0.0.0',
                         help='IP address to bind to, defaults to 0.0.0.0')
    oparser.add_argument('-c', '--config',
                         required=True,
                         default="/opt/rdphoney.cfg",
                         help='Configuration file for rdphoney')
    options = oparser.parse_args()

    config = parse_config(options.config)
    invoke_honeypot(options.ip, options.port, config)


if __name__ == '__main__':
    main()
