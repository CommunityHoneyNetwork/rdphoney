#!/usr/bin/env python

'''Based on SendMeSpamIDS.py/standalone/rdp.py, work of Joerg Stephan'''
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
from base64 import b64encode
from output.hpfeeds import Output

if sys.version_info[0] == 2:
    from ConfigParser import ConfigParser
elif sys.version_info[0] == 3:
    from configparser import ConfigParser
else:
    exit("What year is it, man?")

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
    """Extract username via regex or return None"""
    match = re.search(r'mstshash=(?P<username>[a-zA-Z0-9-_@]+)', data)
    if match:
        uname = match.group('username')
        logger.info("Found username in data: {0}".format(uname))
        return uname
    return None


def invoke_honeypot(addr, port, config):
    """Open listen, start hpfeeds, listen for attackers, repeat"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    serveaddy = (addr, port)
    sock.bind(serveaddy)
    sock.listen(1)
    logger.info("Starting hpfeeds configuration...")
    output = Output(config['server'], config['port'],
                    config['ident'], config['secret'],
                    config['debug'])
    output.start()
    logger.info("Finished hpfeeds configuration and started hpfeeds...")

    while True:
        try:
            logger.info("Starting socket accept...")
            con, addy = sock.accept()
            address = addy[0].strip()
            logger.info("Connection from: {0}".format(address))

            # receive max 4K data, calculate length, then base64encode it for
            # transfer
            data = con.recv(4096)
            length = str(len(data))
            edata = b64encode(data)

            st = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.info("Received data from {0} at {1}".format(address, st))
            user = extract_username(data)
            entry = {"timestamp": st,
                     "src_ip": address,
                     "src_port": addy[1],
                     "dst_ip": addr,
                     "dst_port": port,
                     "username": user,
                     "data": edata
                     }
            logger.info("Starting hpfeeds submission...")
            output.write(entry)
            logger.info(
                "ip={0}, username={1}, datalen={2}".format(
                    address, user, length
                )
            )
            con.send("0x00000004 RDP_NEG_FAILURE")
            con.shutdown(socket.SHUT_RDWR)
            con.close()
            logger.info("Shutdown connection and closed...")
        except Exception as e:
            logger.warning("EXCEPTION: {0}".format(repr(e)))


def parse_config(config_file):
    """Parse config file for hpfeeds config information"""
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
    oparser = argparse.ArgumentParser(description='Instantiate a simple RDP '
                                                  'honeypot',
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
