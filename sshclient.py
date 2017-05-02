#!/usr/bin/env python
from sys import stdout

from twisted.python._oldstyle import _oldStyle
from twisted.python import log

from twisted.internet import reactor
from twisted.internet.defer import Deferred

from twisted.conch.ssh.common import NS
from twisted.conch.scripts.cftp import ClientOptions
from twisted.conch.client.connect import connect
from twisted.conch.client.default import SSHUserAuthClient, verifyHostKey
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.transport import SSHClientTransport

CLIENT_CAPABILITIES = '<?xml version="1.0" encoding="UTF-8"?>'\
                      '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'\
                      '<capabilities>'\
                      '<capability>urn:ietf:params:netconf:base:1.0</capability>'\
                      '<capability>urn:ietf:params:netconf:base:1.1</capability>'\
                      '</capabilities>'\
                      '<session-id>1</session-id>'\
                      '</hello>'\
                      ']]>]]>'

@_oldStyle
class NetconfClientTransport(SSHClientTransport):
    pass


class NetconfSession(SSHChannel):
    name = 'session'

    def channelOpen(self, whatever):
        d = self.conn.sendRequest(self, 'subsystem', NS('netconf'), wantReply=True)
        d.addCallbacks(self._cb_netconf_subsystem)

    def _cb_netconf_subsystem(self, result):
        client = NetconfClientTransport()
        client.makeConnection(self)
        # self.dataReceived = client.dataReceived
        self.conn.netconf.callback(client)

    def dataReceived(self, data):
        """
        Called when we receive data.

        @type data: L{bytes}
        """
        log.msg('got server data %s'%repr(data))


@_oldStyle
class NetConfConnection(SSHConnection):
    def __init__(self):
        SSHConnection.__init__(self)
        self._netconf = Deferred()

    def serviceStarted(self):
        self.openChannel(NetconfSession())

    @property
    def netconf(self):
        return self._netconf


def netconf(user, host, port):
    options = ClientOptions()
    options['host'] = host
    options['port'] = port
    conn = NetConfConnection()
    auth = SSHUserAuthClient(user, options, conn)
    connect(host, port, options, verifyHostKey, auth)
    return conn.netconf


def send_capabilities(client):
    log.msg('Sending client Capabilities to server')
    #d = client.makeDirectory('/tmp/foobarbaz', {})
    #d = client.
    print 'Scheduling stop'
    #d = reactor.callLater(10, reactor.stop)

    def cbDir(ignored):
        print 'Sent request'
    #d.addCallback(cbDir)
    #return d


def main():
    log.startLogging(stdout)

    user = 'mininet'
    host = '172.22.12.241'
    port = 830

    d = netconf(user, host, port)
    d.addCallback(send_capabilities)
    d.addErrback(log.err, "Problem with NETCONF Connection")

    reactor.callLater(3, reactor.stop)
    reactor.run()


if __name__ == '__main__':
    main()
