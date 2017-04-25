#!/usr/bin/env python
# Quick and dirty twisted conch test program to help with finding the best way
# to peel this onion

import pprint
import argparse
# import os
# from ncclient import manager, xml_, capabilities
# from lxml import etree
from twisted.internet import reactor, defer


def pp(value):
    pprint.PrettyPrinter(indent=2).pprint(value)


def ssh_ls():
    d = defer.Deferred()
    d.addCallback(output_data)

    reactor.callLater(2, d.callback, 'Hello World')
    return d


def output_data(result):
    pp(result)


def main(ip_address, port, username, password):

    reactor.callLater(0, ssh_ls)

    reactor.callLater(20, reactor.stop)
    reactor.run()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Conch Test App')
    parser.add_argument('--ip_address', '-i', action='store', default=None, help='IP Address of NETCONF server')
    parser.add_argument('--username', '-u', action='store', default='mininet', help='Username')
    parser.add_argument('--password', '-p', action='store', default='mininet', help='Password')
    # parser.add_argument('--port', '-P', action='store', default=22, help='TCP Port')
    parser.add_argument('--port', '-P', action='store', default=830, help='TCP Port')

    args = parser.parse_args()

    main(args.ip_address,
         port=args.port,
         username=args.username,
         password=args.password)
