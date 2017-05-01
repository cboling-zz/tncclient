#!/usr/bin/env python
# Quick and dirty twisted conch test program to help with finding the best way
# to peel this onion

import argparse
import getpass
import os
import pprint
import struct
import sys

from twisted.conch.endpoints import SSHCommandClientEndpoint
from twisted.conch.ssh import common, keys
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.keys import Key
from twisted.conch.ssh.transport import SSHClientTransport
from twisted.conch.ssh.userauth import SSHUserAuthClient
from twisted.internet import defer, protocol, reactor
from twisted.internet import task
from twisted.internet.protocol import connectionDone
from twisted.python import log
# import os
# from ncclient import manager, xml_, capabilities
# from lxml import etree
from twisted.python._oldstyle import _oldStyle

from twisted.conch.client import connect, default, options

SERVER_FINGERPRINT = '6e:b6:48:0b:55:c4:ef:76:5b:a3:95:29:2a:c5:81:27'

# Set CLIENT_RSA_PUBLIC to empty to not use SSH key auth.
# CLIENT_RSA_PUBLIC = 'ssh-keys/client_rsa.pub'  # Path to RSA SSH keys accepted by the server.
CLIENT_RSA_PUBLIC = ''
CLIENT_RSA_PRIVATE = 'ssh-keys/client_rsa'


def pp(value):
    pprint.PrettyPrinter(indent=2).pprint(value)


class NetconfTransport(object, SSHClientTransport):
    """
    NetconfTransport implements the client side of the NETCONF SSH protocol.

    This class must, at a minimum, implement the verifyHostKey() and the
    connectionSecure() methods of transport.SSHClientTransport.
    """

    def __init__(self, username, password=None, expected_finger_print=None):
        """
        Initialize our transport

        :param expected_finger_print: (str) if not NONE, we expect the server SSH fingerprint to match
                                            ie) '6e:b6:48:0b:55:c4:ef:76:5b:a3:95:29:2a:c5:81:27'
        """
        try:
            super(NetconfTransport, self).__init__()

        except AttributeError:
            # At the time this was written, the SSHClientTransport class did not have
            # an __init__ function
            pass

        except Exception as e:
            log.msg(e)
            raise

        self._username = username
        self._password = password
        self._peer_expected_fingerprint = expected_finger_print  # Expected
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

        if self.transport.addressFamily == 2:
            host = self.transport.addr[0]
        else:
            raise NotImplementedError('TODO: Currently do not support address type {}'.
                                      format(self.transport.addressFamily))

        self.requestService(SimpleUserAuth(user=self._username,
                                           password=self._password,
                                           host=host,
                                           instance=SimpleConnection()))

    def connectionLost(self, reason=connectionDone):
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


@_oldStyle
class SimpleUserAuth(SSHUserAuthClient):
    """
    A service implementing the client side of 'ssh-userauth'.

    This service will try all authentication methods provided by the server,
    making callbacks for more information when necessary.
    """

    def __init__(self, user, instance, host=None, password=None):
        self._host = host
        self._password = password

        SSHUserAuthClient.__init__(self, user, instance)

    def getPassword(self):
        """
        Return a L{Deferred} that will be called back with a password.
        prompt is a string to display for the password, or None for a generic
        'user@hostname's password: '.

        @type prompt: L{bytes}/L{None}
        @rtype: L{defer.Deferred}
        """
        if self._password is None:
            self._password = getpass.getpass("%s@%s's password: " % (self.user, self._host))

        return defer.succeed(self._password)

    def getGenericAnswers(self, name, instruction, questions):
        """
        Returns a L{Deferred} with the responses to the promopts.

        @param name: The name of the authentication currently in progress.
        @param instruction: Describes what the authentication wants.
        @param prompts: A list of (prompt, echo) pairs, where prompt is a
        string to display and echo is a boolean indicating whether the
        user's response should be echoed as they type it.
        """
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
        """
        Return a public key for the user.  If no more public keys are
        available, return L{None}.

        This implementation always returns L{None}.  Override it in a
        subclass to actually find and return a public key object.

        @rtype: L{Key} or L{None}
        """
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
        Return a L{Deferred} that will be called back with the private key
        object corresponding to the last public key from getPublicKey().
        If the private key is not available, errback on the Deferred.

        @rtype: L{Deferred} called back with L{Key}
        """
        return defer.succeed(keys.Key.fromFile(CLIENT_RSA_PRIVATE))

        # TODO Other base class methods include


class SimpleConnection(SSHConnection):
    #name = 'netconf'
    name = b'ssh-connection'

    def serviceStarted(self):
        """
        called when the service is active on the transport.
        """
        # Open a new channel on this connection.
        self.openChannel(NetconfChannel(2 ** 16, 2 ** 15, conn=self))
        # self.openChannel(NetconfChannel(2 ** 16, 2 ** 15, conn=self, avatar='netconf'))

    def adjustWindow(self, channel, bytesToAdd):
        log.msg('CONNECTION ADJUST WINDOW')

        # TODO Other SSHConnection base class methods include
        # def serviceStopped(self):
        # def packetReceived(self, messageNum, packet):
        # def sendGlobalRequest(self, request, data, wantReply=0):
        # def openChannel(self, channel, extra=b''):
        # def sendRequest(self, channel, requestType, data, wantReply=0):
        # def adjustWindow(self, channel, bytesToAdd):
        # def sendData(self, channel, data):
        # def sendExtendedData(self, channel, dataType, data):
        # def sendEOF(self, channel):
        # def sendClose(self, channel):
        # def getChannel(self, channelType, windowSize, maxPacket, data):
        # def gotGlobalRequest(self, requestType, data):
        # def channelClosed(self, channel):

class NetconfChannel(SSHChannel):
    """
    A class that represents a multiplexed channel over an SSH connection.
    The channel has a local window which is the maximum amount of data it will
    receive, and a remote which is the maximum amount of data the remote side
    will accept.  There is also a maximum packet size for any individual data
    packet going each way.
    """
    name = 'session'

    def openFailed(self, reason):
        """
        Called when the open failed for some reason.
        reason.desc is a string descrption, reason.code the SSH error code.

        @type reason: L{error.ConchError}
        """
        print('echo failed', reason)

    def channelOpen(self, ignoredData):
        """
        Called when the channel is opened.  specificData is any data that the
        other side sent us when opening the channel.

        @type specificData: L{bytes}
        """
        self.data = '<?xml version="1.0" encoding="UTF-8"?>'
        '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'\
        '<capabilities>'
        '<capability>urn:ietf:params:netconf:base:1.0</capability>'
        '<capability>urn:ietf:params:netconf:base:1.1</capability>'
        '<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>'
        '<capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>'
        '<capability>urn:ietf:params:netconf:capability:startup:1.0</capability>'
        '<capability>urn:ietf:params:netconf:capability:rollback-on-error:1.0</capability>'
        '<capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>'
        '<capability>urn:ietf:params:netconf:capability:notification:1.0</capability>'
        '<capability>urn:ietf:params:netconf:capability:validate:1.0</capability>'
        '<capability>urn:ietf:params:netconf:capability:validate:1.1</capability>'
        '</capabilities>'
        '<session-id>1</session-id>'
        '</hello>'
        ']]>]]>'
        d = self.conn.sendRequest(self, b'subsystem', common.NS(b'netconf'))

        #self.conn.sendRequest(self, 'netconf', self.data)
        self.conn.sendData(self, self.data)
    #
    # def later(self):
    #     reactor.callLater(2, self._cbRequest)
    #     self.conn.sendData(self, self.data)
    #     reactor.callLater(2, self._cbRequest)
    #     # d.addCallback(self._cbRequest)

    def _cbRequest(self, ignored):
        self.write('hello conch\n')
        self.conn.sendEOF(self)

    def dataReceived(self, data):
        """
        Called when we receive data.

        @type data: L{bytes}
        """
        self.data += data

    def closed(self):
        """
        Called when the channel is closed.  This means that both our side and
        the remote side have closed the channel.
        """
        print('got data from cat: %s' % repr(self.data))
        self.loseConnection()
        reactor.stop()

        # TODO Other SSHChannel methods include
        # def requestReceived(self, requestType, data):
        # def eofReceived(self):
        # def extReceived(self, dataType, data):
        # def closeReceived(self):
        # def write(self, data):
        # def writeExtended(self, dataType, data):
        # def writeSequence(self, data):
        # def loseConnection(self):
        # def stopWriting(self):
        # def startWriting(self):


def ssh_test(args):
    client = protocol.ClientCreator(reactor,
                                    NetconfTransport,
                                    username=args.username,
                                    password=args.password
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


def main(args, ip_address, port, username, password):
    # So we know that things are at least set up properly
    reactor.callLater(0, hello_world)

    # In case we hang....
    # reactor.callLater(60, reactor.stop)

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
    parser.add_argument('--ip_address', '-i', action='store', default='172.22.12.241',
                        help='IP Address of NETCONF server')
    parser.add_argument('--username', '-u', action='store', default='mininet', help='Username')
    parser.add_argument('--password', '-p', action='store', default='mininet', help='Password')
    parser.add_argument('--port', '-P', action='store', default=830, help='TCP Port')

    args = parser.parse_args()

    log.startLogging(sys.stdout)

    main(args,
         ip_address=args.ip_address,
         port=args.port,
         username=args.username,
         password=args.password)
