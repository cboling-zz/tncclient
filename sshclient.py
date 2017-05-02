#!/usr/bin/env python
from sys import stdout

from twisted.python.log import startLogging, err

from twisted.internet import reactor
from twisted.internet.defer import Deferred

from twisted.conch.ssh.common import NS
from twisted.conch.scripts.cftp import ClientOptions
from twisted.conch.ssh.filetransfer import FileTransferClient
from twisted.conch.client.connect import connect
from twisted.conch.client.default import SSHUserAuthClient, verifyHostKey
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.transport import SSHClientTransport

data = '<?xml version="1.0" encoding="UTF-8"?>'\
       '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'\
       '<capabilities>'\
       '<capability>urn:ietf:params:netconf:base:1.0</capability>'\
       '<capability>urn:ietf:params:netconf:base:1.1</capability>'\
       '</capabilities>'\
       '<session-id>1</session-id>'\
       '</hello>'\
       ']]>]]>'

class NetconfSession(SSHChannel):
    name = 'session'

    def channelOpen(self, whatever):
        # d = self.conn.sendRequest(self, 'subsystem', NS('sftp'), wantReply=True)
        d = self.conn.sendRequest(self, 'subsystem', NS('netconf'), wantReply=True)
        d.addCallbacks(self._cbSFTP)

    def _cbSFTP(self, result):
        #client = FileTransferClient()
        client = SSHClientTransport()
        client.makeConnection(self)
        # self.dataReceived = client.dataReceived
        self.conn._sftp.callback(client)


class NetConfConnection(SSHConnection):
    def serviceStarted(self):
        self.openChannel(NetconfSession())


def sftp(user, host, port):
    options = ClientOptions()
    options['host'] = host
    options['port'] = port
    conn = NetConfConnection()
    conn._sftp = Deferred()
    auth = SSHUserAuthClient(user, options, conn)
    connect(host, port, options, verifyHostKey, auth)
    return conn._sftp


def transfer(client):
    #d = client.makeDirectory('/tmp/foobarbaz', {})
    #d = client.
    print 'Scheduling stop'
    #d = reactor.callLater(10, reactor.stop)

    def cbDir(ignored):
        print 'Sent request'
    #d.addCallback(cbDir)
    #return d


def main():
    startLogging(stdout)

    user = 'mininet'
    host = '172.22.12.241'
    port = 830
    d = sftp(user, host, port)
    d.addCallback(transfer)
    d.addErrback(err, "Problem with SFTP transfer")
    #d.addCallback(lambda ignored: reactor.stop())
    reactor.run()


if __name__ == '__main__':
    main()
