#!/usr/bin/env python
# Quick and dirty twisted conch test program to help with finding the best way
# to peel this onion

import pprint
import argparse
# import os
# from ncclient import manager, xml_, capabilities
# from lxml import etree
from twisted.internet import reactor, defer, task
from twisted.python.filepath import FilePath
from twisted.python.usage import Options
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.conch.ssh.keys import EncryptedKeyError, Key
from twisted.conch.client.knownhosts import KnownHostsFile
from twisted.conch.endpoints import SSHCommandClientEndpoint
from twisted.conch.ssh import transport, userauth, connection, common, keys, channel

from twisted.conch.ssh import transport, userauth, connection, common, keys, channel
from twisted.internet import defer, protocol, reactor
from twisted.python import log
import struct, sys, getpass, os

# Replace this with your username.
# Default username and password will match the sshsimpleserver.py
USER = 'mininet'
HOST = '172.22.12.241'
# PORT = 5022
PORT = 22
# SERVER_FINGERPRINT = 'pu:t:se:rv:er:fi:ng:er:pr:in:t:he:re'
SERVER_FINGERPRINT = '6e:b6:48:0b:55:c4:ef:76:5b:a3:95:29:2a:c5:81:27'

# Path to RSA SSH keys accepted by the server.
CLIENT_RSA_PUBLIC = 'ssh-keys/client_rsa.pub'
# Set CLIENT_RSA_PUBLIC to empty to not use SSH key auth.
# CLIENT_RSA_PUBLIC = ''
CLIENT_RSA_PRIVATE = 'ssh-keys/client_rsa'


def pp(value):
    pprint.PrettyPrinter(indent=2).pprint(value)


class NetconfTransport(object, transport.SSHClientTransport):
    """
    NetconfTransport implements the client side of the NETCONF SSH protocol.

    This class must, at a minimum, implement the verifyHostKey() and the
    connectionSecure() methods of transport.SSHClientTransport.
    """
    def __init__(self, expectedFingerPrint=None):
        """
        Initialize our transport
        
        :param expectedFingerPrint: (str) if not NONE, we expect the server SSH fingerprint to match
                                          ie) '6e:b6:48:0b:55:c4:ef:76:5b:a3:95:29:2a:c5:81:27'
        """
        try:
            super(NetconfTransport, self).__init__()

        except AttributeError:
            # At the time this was written, the SSHClientTransport class did not have
            # an __init__ function
            pass

        self._peer_expected_fingerprint = expectedFingerPrint            # Expected
        self._peer_fingerprint = {'hostKey': None, 'fingerprint': None}  # Actual

    def verifyHostKey(self, hostKey, fingerprint):
        """
        Returns a Deferred that gets a callback if it is a valid key, or
        an errback if not.

        @type hostKey: L{bytes}
        @param hostKey: The host key to verify.

        @type fingerprint: L{bytes}
        @param fingerprint: The fingerprint of the key.

        @return: A deferred firing with C{True} if the key is valid.
        """
        log.msg('Server host key fingerprint: {}'.format(fingerprint))

        self._peer_fingerprint['hostKey'] = hostKey
        self._peer_fingerprint['fingerprint'] = fingerprint

        if self._peer_expected_fingerprint is None:
            return defer.succeed(True)

        elif self._peer_expected_fingerprint == self._peer_fingerprint['fingerprint']:
            return defer.succeed(True)

        else:
            print('Bad host key. Expecting: {}'.format(self._peer_fingerprint['fingerprint']))
            return defer.fail(Exception('Bad server key: {}'.
                                        format(self._peer_fingerprint['fingerprint'])))

    def connectionSecure(self):
        """
        Called when the encryption has been set up.  Generally,
        requestService() is called to run another service over the transport.
        """
        log.msg('connectionSecure: entry')

        self.requestService(SimpleUserAuth(USER, SimpleConnection()))

    def connectionLost(self, reason):
        """
        When the underlying connection is closed, stop the running service (if
        any), and log out the avatar (if any).

        @type reason: L{twisted.python.failure.Failure}
        @param reason: The cause of the connection being closed.
        """
        log.msg('NetconfTransport: Connection lost: {}'.format(reason))
        #
        # Call base class which will perform the logout operation
        super(NetconfTransport, self).connectionLost(reason)

    def connectionMade(self):
        """
        Called when the connection is made to the other side.  We sent our
        version and the MSG_KEXINIT packet.
        """
        log.msg('connectionMade: entry')
        # Just call into base class for now
        super(NetconfTransport, self).connectionMade()
        
    ########################################################
    # TODO: Lots of other methods we may want to investigate from the base SSHTransportBase class
    #       class
    # def loseConnection(self):
    # def receiveError(self, reasonCode, description):
    # def receiveUnimplemented(self, seqnum):
    # def receiveDebug(self, alwaysDisplay, message, lang):
    #
    # TODO: From the Protocol base class, here are a few others as well
    # def logPrefix(self):
    # def dataReceived(self, data):


class SimpleUserAuth(userauth.SSHUserAuthClient):
    def getPassword(self):
        return defer.succeed(getpass.getpass("%s@%s's password: " % (USER, HOST)))

    def getGenericAnswers(self, name, instruction, questions):
        print(name)
        print(instruction)
        answers = []
        for prompt, echo in questions:
            if echo:
                answer = raw_input(prompt)
            else:
                answer = getpass.getpass(prompt)
            answers.append(answer)
        return defer.succeed(answers)

    def getPublicKey(self):
        if (
            not CLIENT_RSA_PUBLIC or
            not os.path.exists(CLIENT_RSA_PUBLIC) or
            self.lastPublicKey
                ):
            # the file doesn't exist, or we've tried a public key
            return
        return keys.Key.fromFile(filename=CLIENT_RSA_PUBLIC)

    def getPrivateKey(self):
        """
        A deferred can also be returned.
        """
        return defer.succeed(keys.Key.fromFile(CLIENT_RSA_PRIVATE))


class SimpleConnection(connection.SSHConnection):
    def serviceStarted(self):
        self.openChannel(TrueChannel(2**16, 2**15, self))
        self.openChannel(FalseChannel(2**16, 2**15, self))
        self.openChannel(CatChannel(2**16, 2**15, self))


class TrueChannel(channel.SSHChannel):
    name = 'session' # needed for commands

    def openFailed(self, reason):
        print('true failed', reason)

    def channelOpen(self, ignoredData):
        self.conn.sendRequest(self, 'exec', common.NS('true'))

    def request_exit_status(self, data):
        status = struct.unpack('>L', data)[0]
        print('true status was: %s' % status)
        self.loseConnection()


class FalseChannel(channel.SSHChannel):
    name = 'session'

    def openFailed(self, reason):
        print('false failed', reason)

    def channelOpen(self, ignoredData):
        self.conn.sendRequest(self, 'exec', common.NS('false'))

    def request_exit_status(self, data):
        status = struct.unpack('>L', data)[0]
        print('false status was: %s' % status)
        self.loseConnection()


class CatChannel(channel.SSHChannel):
    name = 'session'

    def openFailed(self, reason):
        print('echo failed', reason)

    def channelOpen(self, ignoredData):
        self.data = ''
        d = self.conn.sendRequest(self, 'exec', common.NS('cat'), wantReply = 1)
        d.addCallback(self._cbRequest)

    def _cbRequest(self, ignored):
        self.write('hello conch\n')
        self.conn.sendEOF(self)

    def dataReceived(self, data):
        self.data += data

    def closed(self):
        print('got data from cat: %s' % repr(self.data))
        self.loseConnection()
        reactor.stop()


def ssh_test(args):
    client = protocol.ClientCreator(reactor,
                                    NetconfTransport
                                    # , expectedFingerPrint=SERVER_FINGERPRINT
                                    )

    # client.connectTCP(host=args.ip_address, port=args.port)
    client.connectTCP(host=args.ip_address, port=22)
    print 'Connect has been issued'


def output_data(result):
    pp(result)


def hello_world():
    d = defer.Deferred()
    d.addCallback(output_data)
    reactor.callLater(2, d.callback, 'Hello World')
    return d


def get_endpoint(args, command):
    return SSHCommandClientEndpoint.newConnection(reactor, command,
                                                  username=args.username,
                                                  password=args.password,
                                                  port=args.port)


def main(args, ip_address, port, username, password):
    # So we know that things are at least set up properly
    reactor.callLater(0, hello_world)

    # In case we hang....
    reactor.callLater(600, reactor.stop)

    # Run the SSH 'ls' command 1 second from now and set up
    # shutdown on success or an error

    try:
        d = task.deferLater(reactor, 1, ssh_test, args)
        # d.addBoth(lambda x: reactor.stop())

        reactor.run()

    except Exception as e:
        print 'Had an exception while running: {}'.format(e.message)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Conch Test App')
    parser.add_argument('--ip_address', '-i', action='store', default='172.22.12.241', help='IP Address of NETCONF server')
    parser.add_argument('--username', '-u', action='store', default='mininet', help='Username')
    parser.add_argument('--password', '-p', action='store', default='mininet', help='Password')
    # parser.add_argument('--port', '-P', action='store', default=22, help='TCP Port')
    parser.add_argument('--port', '-P', action='store', default=830, help='TCP Port')

    args = parser.parse_args()

    log.startLogging(sys.stdout)

    main(args,
         ip_address=args.ip_address,
         port=args.port,
         username=args.username,
         password=args.password)
