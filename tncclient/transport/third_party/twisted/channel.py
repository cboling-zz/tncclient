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

import os
import logging
import getpass

from twisted.conch.ssh import common, keys
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.keys import Key
from twisted.conch.ssh.transport import SSHClientTransport
from twisted.conch.ssh.userauth import SSHUserAuthClient
from twisted.conch.ssh.channel import SSHChannel
from twisted.internet import defer
from twisted.internet.protocol import connectionDone
from twisted.python._oldstyle import _oldStyle
from tncclient.transport.errors import AuthenticationError, SessionCloseError, SSHError, SSHUnknownHostError

logger = logging.getLogger('tncclient.transport.channel')


class NetconfChannel(SSHChannel):
    name = 'session'

    # def __init__(self, subsystem_name):
    #     super(NetconfChannel, self).__init__()
        # name = subsystem_name

    def openFailed(self, reason):
        """
        Called when the open failed for some reason.
        reason.desc is a string descrption, reason.code the SSH error code.

        @type reason: L{error.ConchError}
        """
        logger.error('echo failed', reason)

    def closed(self):
        """
        Called when the channel is closed.  This means that both our side and
        the remote side have closed the channel.
        """
        logger.debug('got data from remote: %s' % repr(self.data))
        self.loseConnection()

    def channelOpen(self, ignoredData):
        """
        Called when the channel is opened.  specificData is any data that the
        other side sent us when opening the channel.

        @type specificData: L{bytes}
        """
        return defer.succeed(None)

    def dataReceived(self, data):
        """
        Called when we receive data.

        @type data: L{bytes}
        """
        self.data += data

        def start_delim(data_len):
            return '\n#%s\n' % data_len

        # chan = self._channel
        # q = self._q
        #
        #
        #
        # try:
        #     while True:
        #         # select on a paramiko ssh channel object does not ever return it in the writable list, so channels don't exactly emulate the socket api
        #         r, w, e = select([chan], [], [], TICK)
        #         # will wakeup evey TICK seconds to check if something to send, more if something to read (due to select returning chan in readable list)
        #         if r:
        #             data = chan.recv(BUF_SIZE)
        #             if data:
        #                 self._buffer.write(data)
        #                 if self._server_capabilities:
        #                     if 'urn:ietf:params:netconf:base:1.1' in self._server_capabilities and 'urn:ietf:params:netconf:base:1.1' in self._client_capabilities:
        #                         logger.debug("Selecting netconf:base:1.1 for encoding")
        #                         self._parse11()
        #                     elif 'urn:ietf:params:netconf:base:1.0' in self._server_capabilities or 'urn:ietf:params:xml:ns:netconf:base:1.0' in self._server_capabilities or 'urn:ietf:params:netconf:base:1.0' in self._client_capabilities:
        #                         logger.debug("Selecting netconf:base:1.0 for encoding")
        #                         self._parse10()
        #                     else: raise Exception
        #                 else:
        #                     self._parse10() # HELLO msg uses EOM markers.
        #             else:
        #                 raise SessionCloseError(self._buffer.getvalue())
        #         if not q.empty() and chan.send_ready():
        #             logger.debug("Sending message")
        #             data = q.get()
        #             try:
        #                 # send a HELLO msg using v1.0 EOM markers.
        #                 validated_element(data, tags='{urn:ietf:params:xml:ns:netconf:base:1.0}hello')
        #                 data = "%s%s"%(data, MSG_DELIM)
        #             except XMLError:
        #                 # this is not a HELLO msg
        #                 # we publish v1.1 support
        #                 if 'urn:ietf:params:netconf:base:1.1' in self._client_capabilities:
        #                     if self._server_capabilities:
        #                         if 'urn:ietf:params:netconf:base:1.1' in self._server_capabilities:
        #                             # send using v1.1 chunked framing
        #                             data = "%s%s%s"%(start_delim(len(data)), data, END_DELIM)
        #                         elif 'urn:ietf:params:netconf:base:1.0' in self._server_capabilities or 'urn:ietf:params:xml:ns:netconf:base:1.0' in self._server_capabilities:
        #                             # send using v1.0 EOM markers
        #                             data = "%s%s"%(data, MSG_DELIM)
        #                         else: raise Exception
        #                     else:
        #                         logger.debug('HELLO msg was sent, but server capabilities are still not known')
        #                         raise Exception
        #                 # we publish only v1.0 support
        #                 else:
        #                     # send using v1.0 EOM markers
        #                     data = "%s%s"%(data, MSG_DELIM)
        #             finally:
        #                 logger.debug("Sending: %s", data)
        #                 while data:
        #                     n = chan.send(data)
        #                     if n <= 0:
        #                         raise SessionCloseError(self._buffer.getvalue(), data)
        #                     data = data[n:]
        # except Exception as e:
        #     logger.debug("Broke out of main loop, error=%r", e)
        #     self._dispatch_error(e)
        #     self.close()
        pass

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
