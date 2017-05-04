#!/usr/bin/env python
import struct

from sys import stdout
from os import linesep

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

CLIENT_CAPABILITIES = '<?xml version="1.0" encoding="UTF-8"?><nc:hello xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><nc:capabilities><nc:capability>urn:ietf:params:netconf:capability:writable-running:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:rollback-on-error:1.0</nc:capability><nc:capability>urn:liberouter:params:netconf:capability:power-control:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:validate:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:confirmed-commit:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file,https,sftp</nc:capability><nc:capability>urn:ietf:params:netconf:base:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:base:1.1</nc:capability><nc:capability>urn:ietf:params:netconf:capability:candidate:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:notification:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:xpath:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:startup:1.0</nc:capability><nc:capability>urn:ietf:params:netconf:capability:interleave:1.0</nc:capability></nc:capabilities></nc:hello>]]>]]>'

GET_RUNNING_CONFIG = b'<?xml version="1.0" encoding="UTF-8"?>'\
                     b'<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:uuid:c1a4753b-ae78-41d4-909b-7a8b1f69798c">'\
                     b'  <nc:get-config>'\
                     b'    <nc:source>'\
                     b'      <nc:running/>'\
                     b'    </nc:source>'\
                     b'  </nc:get-config>'\
                     b'</nc:rpc>'

exit_status = 0


class NetconfChannel(SSHChannel):
    name = 'session'

    def channelOpen(self, _):
        d = self.conn.sendRequest(self, 'subsystem', NS('netconf'), wantReply=True)
        d.addCallbacks(self._cb_netconf_subsystem)

    def _cb_netconf_subsystem(self, _):
        transport = SSHClientTransport()
        transport.makeConnection(self)
        # self.dataReceived = transport.dataReceived

        # Run the success callbacks for this connection
        self.conn.netconf_deferred.callback(transport)

    def dataReceived(self, data):
        """
        Called when we receive data.

        @type data: L{bytes}
        """
        assert False             # Client should rx the data
        log.msg('got server data %s' % repr(data))

    def request_exit_status(self, data):
        global exit_status
        exit_status = int(struct.unpack('>L', data)[0])
        log.msg('My exit status: %s' % exit_status)


@_oldStyle
class NetConfConnection(SSHConnection):
    def __init__(self, channel=None):
        SSHConnection.__init__(self)
        self._netconf = Deferred()
        self._channel = channel or NetconfChannel()

    def serviceStarted(self):
        self.openChannel(self._channel)

    @property
    def netconf_deferred(self):
        return self._netconf

    @property
    def channel(self):
        return self._channel


class NetConfClient(object):
    def __init__(self, user, host, port):
        self._host = host
        self._user = user
        self._port = port

        self._options = ClientOptions()
        self._options['host'] = host
        self._options['port'] = port

        self._channel = NetconfChannel()
        self._connection = NetConfConnection(channel=self._channel)
        self._auth = SSHUserAuthClient(user, self._options, self._connection)

        # Route the channel received data to this object
        self._channel.dataReceived = self.data_received

    def __str__(self):
        return 'NetconfClient: {}@{}.{}'.format(self._user, self._host, self._port)

    def connect(self):
        try:
            connect(self._host, self._port, self._options, verifyHostKey, self._auth)
            return self._connection.netconf_deferred

        except Exception as e:
            log.msg(e.message)
            raise

    def write(self, data, chunk_it=True):
        try:
            log.msg('Sending {} octets of {}data'.
                    format(len(data), 'chunked ' if chunk_it else ''))
            if chunk_it:
                self.channel.write(NS('\n#{}\n'.format(len(data))))

            self.channel.write(data)

        except Exception as e:
            log.msg(e.message)
            raise

    def data_received(self, data):
        """
        Called when we receive data.

        @type data: L{bytes}
        """
        log.msg('Client {}: got server data{}{}'.format(self, linesep, repr(data)))

    def close(self):
        log.msg('Sending close')
        self.connection.sendClose(self.channel)

    @property
    def connection(self):
        return self._connection

    @property
    def channel(self):
        return self._channel

# def netconf(user, host, port):
#     options = ClientOptions()
#     options['host'] = host
#     options['port'] = port
#
#     conn = NetConfConnection()
#     auth = SSHUserAuthClient(user, options, conn)
#
#     connect(host, port, options, verifyHostKey, auth)
#
#     return conn.netconf


def send_capabilities(transport, client):
    """
    Send our client capabilities
    
    :param transport: (t.c.s.transport.SSHClientTransport) client transport
    :param client: (NetConfClient) client
    
    :return: (deferred) Tx request deferred object
    """
    # import pprint
    # log.msg('Sending client Capabilities to server. transport is {}'.format(type(transport)))
    # log.msg('{}'.format(repr(transport)))
    # log.msg('{}'.format(pprint.PrettyPrinter().pformat(dir(transport))))
    # log.msg('transport.transport is a {} and has {}'.
    #         format(repr(transport.transport),
    #                pprint.PrettyPrinter().pformat(dir(transport.transport))))
    #
    # log.msg('transport.transport.conn is a {} and has {}'.
    #         format(repr(transport.transport.conn),
    #                pprint.PrettyPrinter().pformat(dir(transport.transport.conn))))

    try:
        log.msg('Sending client capabilities')

        x = client.channel.getPeer()
        y = client.channel.getHost()
        client.write(CLIENT_CAPABILITIES, chunk_it=False)

    except Exception as e:
        log.msg(e.message)
        raise


def get_running_config(transport, client):
    try:
        log.msg('Requesting the running config')
        client.write(GET_RUNNING_CONFIG)

    except Exception as e:
        log.msg(e.message)
        raise

def connect_failed(msg):
    log.err(msg)

def main():
    log.startLogging(stdout)

    user = 'mininet'
    host = '172.22.12.241'
    port = 830

    #d = netconf(user, host, port)
    client = NetConfClient(user, host, port)
    d = client.connect()
    d.addCallback(send_capabilities, client)
    d.addErrback(log.err, "Problem with NETCONF Connection Establishment")

    #d.addCallback(get_running_config, client)
    #d.addErrback(connect_failed, "Problem with NETCONF get-running-config request")

    d = reactor.callLater(2, send_capabilities, None, client)
    d = reactor.callLater(4, get_running_config, None, client)


    reactor.callLater(9, client.close)
    reactor.callLater(10, reactor.stop)
    reactor.run()


if __name__ == '__main__':
    main()
