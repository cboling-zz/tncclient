# Copyright 2017-present Chip Boling
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import getpass

from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.keys import Key
from twisted.conch.ssh.transport import SSHClientTransport
from twisted.conch.ssh.userauth import SSHUserAuthClient
from twisted.internet import defer
from twisted.internet.protocol import connectionDone
from twisted.python._oldstyle import _oldStyle
from tncclient.transport.errors import SSHError

logger = logging.getLogger('tncclient.transport.transport')


class NetconfTransport(object, SSHClientTransport):
    """
    NetconfTransport implements the client side of the NETCONF SSH protocol.

    This class must, at a minimum, implement the verifyHostKey() and the
    connectionSecure() methods of transport.SSHClientTransport.
    """
    def __init__(self, username,
                 password=None,
                 host_keys=None,
                 key_filenames=[],
                 allow_agent=True,
                 look_for_keys=True,
                 device_handler=None,
                 session=None):
        """
        Initialize our transport
        
        :param host_keys: (HostKeys) if not NONE, host_key file to check server key with
        :param key_filenames: (list) filenames where a the private key to be used can be 
                                     found
        :param allow_agent: (boolean) enables querying SSH agent (if found) for keys
        :param look_for_keys: (boolean) To disable attempting publickey authentication
                                        altogether, call with allow_agent and
                                        look_for_keys as False.
        """
        try:
            super(NetconfTransport, self).__init__()

        except AttributeError:
            # At the time this was written, the SSHClientTransport class did not have
            # an __init__ function
            pass

        except Exception as e:
            logger.exception(e.message)
            raise

        self._username = username
        self._password = password
        self._host_keys = host_keys
        self._peer_fingerprint = {'hostKey': None, 'fingerprint': None}  # Actual

        self._key_filenames = key_filenames
        self._allow_agent = allow_agent
        self._look_for_keys = look_for_keys
        self._device_handler = device_handler
        self._session = session

    def verifyHostKey(self, host_key, fingerprint):
        """
        Returns a Deferred that gets a callback if it is a valid key, or
        an errback if not.

        @type host_key: L{bytes}
        @param host_key: The host key to verify.

        @type fingerprint: L{bytes}
        @param fingerprint: The fingerprint of the key.

        @return: A deferred firing with C{True} if the key is valid.
        """
        logger.info('Server host key fingerprint: {}'.format(fingerprint))

        self._peer_fingerprint['hostKey'] = host_key
        self._peer_fingerprint['fingerprint'] = fingerprint

        if self._host_keys is None:
            return defer.succeed(True)

        elif self._host_keys.check(self.realHost, fingerprint) or\
                False:
            return defer.succeed(True)

        else:
            print('Bad host key: {}'.format(fingerprint))
            return defer.fail(Exception('Bad server key: {}'.format(fingerprint)))

    def connectionSecure(self):
        """
        Called when the encryption has been set up.  Generally,
        requestService() is called to run another service over the transport.
        """
        logger.info('connectionSecure: entry')

        if self.transport.addressFamily == 2:
            host = self.transport.addr[0]
        else:
            raise NotImplementedError('TODO: Currently do not support address type {}'.
                                      format(self.transport.addressFamily))

        self.requestService(UserAuth(user=self._username,
                                     password=self._password,
                                     host=host,
                                     instance=NetconfConnection(self._device_handler),
                                     key_filenames=self._key_filenames,
                                     allow_agent=self._allow_agent,
                                     look_for_keys=self._look_for_keys))

    def connectionLost(self, reason=connectionDone):
        """
        When the underlying connection is closed, stop the running service (if
        any), and log out the avatar (if any).

        @type reason: L{twisted.python.failure.Failure}
        @param reason: The cause of the connection being closed.
        """
        logger.info('NetconfTransport: Connection lost: {}'.format(reason))

        self.connected = False

        # Call base class which will perform the logout operation
        super(NetconfTransport, self).connectionLost(reason)

    def connectionMade(self):
        """
        Called when the connection is made to the other side.  We sent our
        version and the MSG_KEXINIT packet.
        """
        logger.info('connectionMade: entry')

        self.connected = True   # TODO: This needs to be set up in SSH parent

        # Call into base class
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

    @property
    def session(self):
        return self._session

@_oldStyle
class UserAuth(SSHUserAuthClient):
    """
    A service implementing the client side of 'ssh-userauth'.

    This service will try all authentication methods provided by the server,
    making callbacks for more information when necessary.
    """

    def __init__(self, user, instance,
                 host=None,
                 password=None,
                 key_filenames=[],
                 allow_agent=True,
                 look_for_keys=True):
        """
        :param key_filenames: (list) filenames where a the private key to be used can be 
                                     found
        :param allow_agent: (boolean) enables querying SSH agent (if found) for keys
        :param look_for_keys: (boolean) To disable attempting publickey authentication
                                        altogether, call with allow_agent and
                                        look_for_keys as False.

        """
        self._host = host
        self._password = password
        self._key_filenames = key_filenames
        self._allow_agent = allow_agent
        self._look_for_keys = look_for_keys

        if allow_agent:
            raise NotImplemented('TODO: Authentication agent not supported')
        if look_for_keys:
            raise NotImplemented('TODO: pub/private key lookup is not supported')

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
        @param questions: A list of (prompt, echo) pairs, where prompt is a
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

        @rtype: L{Key} or L{None}
        """
        # To disable attempting publickey authentication altogether, call
        # with allow_agent and look_for_keys as False.

        if not self._look_for_keys and not self._allow_agent:
            return

        raise NotImplemented('TODO Public keys are not yet supported')

    def getPrivateKey(self):
        """
        Return a L{Deferred} that will be called back with the private key
        object corresponding to the last public key from getPublicKey().
        If the private key is not available, errback on the Deferred.

        @rtype: L{Deferred} called back with L{Key}
        """
        raise NotImplemented('TODO Private keys are not yet supported')


@_oldStyle
class NetconfConnection(SSHConnection):

    def __init__(self, device_handler):
        SSHConnection.__init__(self)
        self._device_handler = device_handler      # TODO: May be able to clean this up (remove)

    def serviceStarted(self):
        """
        Called when the service is active on the transport.
        """
        # Open a new channel on this connection.

        subsystem_names = self._device_handler.get_ssh_subsystem_names()

        for subname in subsystem_names:
            from channel import NetconfChannel

            c = NetconfChannel(conn=self)

            try:
                self.openChannel(c)
                self.session.channel = c

            except Exception as e:
                logging.exception(e.message)  # TODO: Test various modes of failures

                handle_exception = self._device_handler.handle_connection_exceptions(self)

                if not handle_exception:
                    continue

        if self.session.channel is None:
            raise SSHError("Could not open connection, possibly due to unacceptable"
                           " SSH subsystem name.")

    @property
    def session(self):
        return self.transport.session

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
