#!/usr/bin/env python
# Quick and dirty twisted conch test program to help with finding the best way
# to peel this onion

import pprint
import argparse
# import os
# from ncclient import manager, xml_, capabilities
# from lxml import etree
from twisted.internet import reactor, defer
from twisted.python.filepath import FilePath
from twisted.python.usage import Options
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.conch.ssh.keys import EncryptedKeyError, Key
from twisted.conch.client.knownhosts import KnownHostsFile
from twisted.conch.endpoints import SSHCommandClientEndpoint


def pp(value):
    pprint.PrettyPrinter(indent=2).pprint(value)


def hello_world():
    d = defer.Deferred()
    d.addCallback(output_data)
    reactor.callLater(2, d.callback, 'Hello World')
    return d

def ssh_setup(args, command):
    endpoint = get_endpoint(args, command)
    factory = Factory()
    factory.protocol = Protocol
    d = endpoint.connect(factory)

class PrinterProtocol(Protocol):
    def dataReceived(self, data):
        print("Got some data:", data, end=' ')

    def connectionLost(self, reason):
        print("Lost my connection")
        self.factory.done.callback(None)


def ssh_ls(args):
    endpoint = ssh_setup(args, b'ls -a')

    d = defer.Deferred()
    d.addCallback(output_data)

    reactor.callLater(2, d.callback, 'Hello World')
    return d

    # def newConnection(cls, reactor, command, username, hostname, port=None,
    #                   keys=None, password=None, agentEndpoint=None,
    #                   knownHosts=None, ui=None):

def output_data(result):
    pp(result)


def get_endpoint(args, command):
    return SSHCommandClientEndpoint.newConnection(reactor, command,
                                                  username=args.username,
                                                  password=args.password,
                                                  port=args.port)


def main(ip_address, port, username, password):

    reactor.callLater(0, hello_world)
    reactor.callLater(1, ssh_ls, args)

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
