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

logger = logging.getLogger('tncclient.transport.connection')


@_oldStyle
class NetConfConnection(SSHConnection):

    def __init__(self, device_handler):
        SSHConnection.__init__(self)
        self._netconf = Deferred()
        self._channel = None
        self._device_handler = device_handler      # TODO: May be able to clean this up (remove)

    def serviceStarted(self):
        """
        Called when the service is active on the transport.
        """
        # Open a new channel on this connection.

        subsystem_names = self._device_handler.get_ssh_subsystem_names()

        for subsystem in subsystem_names:
            from channel import NetConfChannel

            c = NetConfChannel(subsystem, conn=self)

            try:
                self.openChannel(c)
                self._channel = c           # TODO: Is this the right place to check

            except Exception as e:
                logging.exception(e.message)  # TODO: Test various modes of failures
                handle_exception = self._device_handler.handle_connection_exceptions(self)

                if not handle_exception:
                    continue

        if self._channel is None:
            raise SSHError("Could not open connection, possibly due to unacceptable"
                           " SSH subsystem name.")

    # @property
    # def session(self):
    #     return self.transport.session

    @property
    def netconf_deferred(self):
        return self._netconf

    @property
    def channel(self):
        return self._channel

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
