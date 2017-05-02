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

import struct
import logging
from twisted.conch.ssh.transport import SSHClientTransport
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.common import NS
from twisted.python._oldstyle import _oldStyle
from twisted.internet.defer import Deferred

logger = logging.getLogger('tncclient.transport.channel')

exit_status = 0


@_oldStyle
class NetConfChannel(SSHChannel):
    name = 'session'

    def __init__(self, subsystem, conn=None):
        SSHChannel.__init__(self)
        self._netconf = Deferred()
        self._channel = None
        self._subsystem = subsystem

    def channelOpen(self, _):
        """
        Called when the channel is opened.  specificData is any data that the
        other side sent us when opening the channel.

        @type specificData: L{bytes}
        """
        logging.info('Channel open')
        # d = self.conn.sendRequest(self, 'subsystem', NS('netconf'), wantReply=True)
        d = self.conn.sendRequest(self, 'subsystem', NS(self._subsystem), wantReply=True)
        d.addCallbacks(self._cb_netconf_subsystem)

    def _cb_netconf_subsystem(self, _):
        logging.info('netconf subsystem ready')
        transport = SSHClientTransport()
        transport.makeConnection(self)

        # Run the success callbacks for this connection
        self.conn.netconf_deferred.callback(transport)

    def dataReceived(self, data):
        """
        Called when we receive data.

        @type data: L{bytes}
        """
        assert False             # Client should rx the data

    def request_exit_status(self, data):
        global exit_status
        exit_status = int(struct.unpack('>L', data)[0])
        logging.info('My exit status: %s' % exit_status)

    def openFailed(self, reason):
        """
        Called when the open failed for some reason.
        reason.desc is a string description, reason.code the SSH error code.

        @type reason: L{error.ConchError}
        """
        logger.error('echo failed', reason)

    def closed(self):
        """
        Called when the channel is closed.  This means that both our side and
        the remote side have closed the channel.
        """
        logger.debug('got close from remote')
        self.loseConnection()

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
