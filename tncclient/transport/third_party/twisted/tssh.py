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
# TODO: This is a 'cut & paste' copy of the original SSHSession file
#       to help in getting the twisted version to work as expected. It
#       will hopefully be able to move the twisted specific logic back
#       into that file once things work or perhaps refactor both to
#       allow for a cleaner way to do things.

import os
import getpass
from twisted.internet import defer, protocol, reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue
from twisted.conch.client.knownhosts import KnownHostsFile
from tncclient.capabilities import Capabilities
from tncclient.transport.errors import AuthenticationError, SessionCloseError, SSHError, SSHUnknownHostError
from tncclient.transport.session import Session
from tncclient.xml_ import *
from tncclient.transport.session import NotificationHandler, SessionError, HelloHandler, TransportError

import logging
logger = logging.getLogger("ncclient.transport.ssh")

BUF_SIZE = 4096
# v1.0: RFC 4742
MSG_DELIM = "]]>]]>"
MSG_DELIM_LEN = len(MSG_DELIM)
# v1.1: RFC 6242
END_DELIM = '\n##\n'

TICK = 0.1

def default_unknown_host_cb(host, fingerprint):
    """An unknown host callback returns `True` if it finds the key acceptable, and `False` if not.

    This default callback always returns `False`, which would lead to :meth:`connect` raising a :exc:`SSHUnknownHost` exception.

    Supply another valid callback if you need to verify the host key programatically.

    *host* is the hostname that needs to be verified

    *fingerprint* is a hex string representing the host key fingerprint, colon-delimited e.g. `"4b:69:6c:72:6f:79:20:77:61:73:20:68:65:72:65:21"`
    """
    return False

def _colonify(fp):
    fp = fp.decode('UTF-8')
    finga = fp[:2]
    for idx  in range(2, len(fp), 2):
        finga += ":" + fp[idx:idx+2]
    return finga

if sys.version < '3':
    def textify(buf):
        return buf
else:
    def textify(buf):
        return buf.decode('UTF-8')

if sys.version < '3':
    from six import StringIO
else:
    from io import BytesIO as StringIO


class TSSHSession(Session):
    """
    Implements a :rfc:`4742` NETCONF session over SSH (provided by twisted-conch).
    """
    def __init__(self, device_handler):
        capabilities = Capabilities(device_handler.get_capabilities())
        Session.__init__(self, capabilities)
        self._host_keys = KnownHostsFile(None)
        self._transport = None
        self._connected = False
        self._connect_deferred = None
        self._channel = None
        self._channel_id = None
        self._channel_name = None
        self._buffer = StringIO()
        # parsing-related, see _parse()
        self._device_handler = device_handler
        self._parsing_state10 = 0
        self._parsing_pos10 = 0
        self._parsing_pos11 = 0
        self._parsing_state11 = 0
        self._expchunksize = 0
        self._curchunksize = 0
        self._inendpos = 0
        self._size_num_list = []
        # self._message_list = []
        self._message_list = DeferredQueue()            # Incoming messages
        self._tx_deferred = None

    def _parse(self):
        "Messages ae delimited by MSG_DELIM. The buffer could have grown by a maximum of BUF_SIZE bytes everytime this method is called. Retains state across method calls and if a byte has been read it will not be considered again."
        return self._parse10()

    def _parse10(self):

        """Messages are delimited by MSG_DELIM. The buffer could have grown by
        a maximum of BUF_SIZE bytes everytime this method is called. Retains
        state across method calls and if a chunk has been read it will not be
        considered again."""

        logger.debug("parsing netconf v1.0")
        buf = self._buffer
        buf.seek(self._parsing_pos10)
        if MSG_DELIM in buf.read().decode('UTF-8'):
            buf.seek(0)
            msg, _, remaining = buf.read().decode('UTF-8').partition(MSG_DELIM)
            msg = msg.strip()
            if sys.version < '3':
                self._dispatch_message(msg.encode())
            else:
                self._dispatch_message(msg)
            # create new buffer which contains remaining of old buffer
            self._buffer = StringIO()
            self._buffer.write(remaining.encode())
            self._parsing_pos10 = 0
            if len(remaining) > 0:
                # There could be another entire message in the
                # buffer, so we should try to parse again.
                logger.debug('Trying another round of parsing since there is still data')
                self._parse10()
        else:
            # handle case that MSG_DELIM is split over two chunks
            self._parsing_pos10 = buf.tell() - MSG_DELIM_LEN
            if self._parsing_pos10 < 0:
                self._parsing_pos10 = 0

    def _parse11(self):
        logger.debug("parsing netconf v1.1")
        expchunksize = self._expchunksize
        curchunksize = self._curchunksize
        idle, instart, inmsg, inbetween, inend = range(5)
        state = self._parsing_state11
        inendpos = self._inendpos
        num_list = self._size_num_list
        MAX_STARTCHUNK_SIZE = 12 # \#+4294967295+\n
        pre = 'invalid base:1:1 frame'
        buf = self._buffer
        buf.seek(self._parsing_pos11)
        message_list = self._message_list # a message is a list of chunks
        chunk_list = []   # a chunk is a list of characters

        should_recurse = False

        while True:
            x = buf.read(1)
            if not x:
                logger.debug('No more data to read')
                # Store the current chunk to the message list
                chunk = b''.join(chunk_list)
                message_list.append(textify(chunk))
                break # done reading
            logger.debug('x: %s', x)
            if state == idle:
                if x == b'\n':
                    state = instart
                    inendpos = 1
                else:
                    logger.debug('%s (%s: expect newline)'%(pre, state))
                    raise Exception
            elif state == instart:
                if inendpos == 1:
                    if x == b'#':
                        inendpos += 1
                    else:
                        logger.debug('%s (%s: expect "#")'%(pre, state))
                        raise Exception
                elif inendpos == 2:
                    if x.isdigit():
                        inendpos += 1 # == 3 now #
                        num_list.append(x)
                    else:
                        logger.debug('%s (%s: expect digit)'%(pre, state))
                        raise Exception
                else:
                    if inendpos == MAX_STARTCHUNK_SIZE:
                        logger.debug('%s (%s: no. too long)'%(pre, state))
                        raise Exception
                    elif x == b'\n':
                        num = b''.join(num_list)
                        num_list = [] # Reset num_list
                        try: num = int(num)
                        except:
                            logger.debug('%s (%s: invalid no.)'%(pre, state))
                            raise Exception
                        else:
                            state = inmsg
                            expchunksize = num
                            logger.debug('response length: %d'%expchunksize)
                            curchunksize = 0
                            inendpos += 1
                    elif x.isdigit():
                        inendpos += 1 # > 3 now #
                        num_list.append(x)
                    else:
                        logger.debug('%s (%s: expect digit)'%(pre, state))
                        raise Exception
            elif state == inmsg:
                chunk_list.append(x)
                curchunksize += 1
                chunkleft = expchunksize - curchunksize
                if chunkleft == 0:
                    inendpos = 0
                    state = inbetween
                    chunk = b''.join(chunk_list)
                    message_list.append(textify(chunk))
                    chunk_list = [] # Reset chunk_list
                    logger.debug('parsed new chunk: %s'%(chunk))
            elif state == inbetween:
                if inendpos == 0:
                    if x == b'\n': inendpos += 1
                    else:
                        logger.debug('%s (%s: expect newline)'%(pre, state))
                        raise Exception
                elif inendpos == 1:
                    if x == b'#': inendpos += 1
                    else:
                        logger.debug('%s (%s: expect "#")'%(pre, state))
                        raise Exception
                else:
                    inendpos += 1 # == 3 now #
                    if x == b'#':
                        state = inend
                    elif x.isdigit():
                        # More trunks
                        state = instart
                        num_list = []
                        num_list.append(x)
                    else:
                        logger.debug('%s (%s: expect "#")'%(pre, state))
                        raise Exception
            elif state == inend:
                if inendpos == 3:
                    if x == b'\n':
                        inendpos = 0
                        state = idle
                        logger.debug('dispatching message')
                        self._dispatch_message(''.join(message_list))
                        # reset
                        rest = buf.read()
                        buf = BytesIO()
                        buf.write(rest)
                        buf.seek(0)
                        message_list = []
                        self._message_list = message_list
                        chunk_list = []
                        expchunksize = chunksize = 0
                        parsing_state11 = idle
                        inendpos = parsing_pos11 = 0
                        # There could be another entire message in the
                        # buffer, so we should try to parse again.
                        should_recurse = True
                        break
                    else:
                        logger.debug('%s (%s: expect newline)'%(pre, state))
                        raise Exception
            else:
                logger.debug('%s (%s invalid state)'%(pre, state))
                raise Exception

        self._expchunksize = expchunksize
        self._curchunksize = curchunksize
        self._parsing_state11 = state
        self._inendpos = inendpos
        self._size_num_list = num_list
        self._buffer = buf
        self._parsing_pos11 = self._buffer.tell()
        logger.debug('parse11 ending ...')

        if should_recurse:
            logger.debug('Trying another round of parsing since there is still data')
            self._parse11()

    def load_known_hosts(self, filename=None):

        """Load host keys from an openssh :file:`known_hosts`-style file. Can
        be called multiple times.

        If *filename* is not specified, looks in the default locations i.e. :file:`~/.ssh/known_hosts` and :file:`~/ssh/known_hosts` for Windows.
        """

        if filename is None:
            filename = os.path.expanduser('~/.ssh/known_hosts')
            try:
                self._host_keys = KnownHostsFile.fromPath(filename)
            except IOError:
                # for windows
                filename = os.path.expanduser('~/ssh/known_hosts')
                try:
                    self._host_keys = KnownHostsFile.fromPath(filename)
                except IOError:
                    pass
        else:
            self._host_keys = KnownHostsFile.fromPath(filename)

    def close(self):
        if self._connect_deferred:
            self._connect_deferred.cancel()

        if self._transport.is_active():
            self._transport.close()
        self._channel = None
        self._connected = False

    @inlineCallbacks
    def wait_for_response(self):
        logging.info('wait-for-response')
        try:
            response = yield self._message_list.get()
            logging.info('got-response')
            returnValue(response)

        except Exception as e:
            self.log.info('wait-for-response-exception', exc=str(e))
            # self.last_response = None

    # REMEMBER to update transport.rst if sig. changes, since it is hardcoded there
    @inlineCallbacks
    def connect(self, host, port=830, timeout=30, unknown_host_cb=default_unknown_host_cb,
                username=None, password=None, key_filename=None, allow_agent=True,
                hostkey_verify=True, look_for_keys=True, ssh_config=None, **kwargs):

        from transport import NetconfTransport

        """Connect via SSH and initialize the NETCONF session. First attempts the publickey authentication method and then password authentication.

        To disable attempting publickey authentication altogether, call with *allow_agent* and *look_for_keys* as `False`.

        *host* is the hostname or IP address to connect to

        *port* is by default 830, but some devices use the default SSH port of 22 so this may need to be specified

        *timeout* is an optional timeout for socket connect

        *unknown_host_cb* is called when the server host key is not recognized. It takes two arguments, the hostname and the fingerprint (see the signature of :func:`default_unknown_host_cb`)

        *username* is the username to use for SSH authentication

        *password* is the password used if using password authentication, or the passphrase to use for unlocking keys that require it

        *key_filename* is a filename where a the private key to be used can be found

        *allow_agent* enables querying SSH agent (if found) for keys

        *hostkey_verify* enables hostkey verification from ~/.ssh/known_hosts

        *look_for_keys* enables looking in the usual locations for ssh keys (e.g. :file:`~/.ssh/id_*`)

        *ssh_config* enables parsing of an OpenSSH configuration file, if set to its path, e.g. :file:`~/.ssh/config` or to True (in this case, use :file:`~/.ssh/config`).
        """
        # Optionaly, parse .ssh/config
        config = {}
        if ssh_config is True:
            ssh_config = "~/.ssh/config" if sys.platform != "win32" else "~/ssh/config"
        if ssh_config is not None:
            raise NotImplemented('TODO: does Twisted conch support the next set of calls')
            # config = paramiko.SSHConfig()
            # config.parse(open(os.path.expanduser(ssh_config)))
            # config = config.lookup(host)
            # host = config.get("hostname", host)
            # if username is None:
            #     username = config.get("user")
            # if key_filename is None:
            #     key_filename = config.get("identityfile")

        if username is None:
            username = getpass.getuser()

        if config.get("proxycommand"):
            raise NotImplemented('TODO: does Twisted conch support proxycommand?')
        else:
            try:
                host_keys = self._host_keys if hostkey_verify else None

                if key_filename is None:
                    key_filenames = []
                elif isinstance(key_filename, (str, bytes)):
                    key_filenames = [key_filename]
                else:
                    key_filenames = key_filename

                self._transport = protocol.ClientCreator(reactor,
                                                         NetconfTransport,
                                                         username=username,
                                                         password=password,
                                                         host_keys=host_keys,
                                                         key_filenames=key_filenames,
                                                         allow_agent=allow_agent,
                                                         look_for_keys=look_for_keys,
                                                         device_handler=self._device_handler,
                                                         session=self)

                self._connect_deferred = self._transport.connectTCP(host=host, port=port, timeout=timeout)

                def connect_fail(err):
                    self._connect_deferred = None
                    raise err

                self._connect_deferred.addErrback(connect_fail)
                results = yield self._connect_deferred

                self._connected = True

                # subsystem_names = self._device_handler.get_ssh_subsystem_names()
                #
                # for subname in subsystem_names:
                #     from channel import NetconfChannel
                #
                #     c = NetconfChannel(subname)
                #
                #     try:
                #         # connection = self.transport.
                #         results = yield self.openChannel(c)
                #         self._channel = c
                #
                #     except Exception as e:
                #         logging.exception(e.message)        # TODO: Test various modes of failures
                #
                #         handle_exception = self._device_handler.handle_connection_exceptions(self)
                #
                #         if not handle_exception:
                #             continue
                # if self._channel is None:
                #     raise SSHError("Could not open connection, possibly due to unacceptable"
                #                    " SSH subsystem name.")
                #
                # # Greeting stuff
                # error = [None]  # so that err_cb can bind error[0]. just how it is.
                #
                # # callbacks
                # def ok_cb(id, capabilities):
                #     self._id = id
                #     self.server_capabilities = capabilities
                #
                # def err_cb(err):
                #     error[0] = err
                #
                # self.add_listener(NotificationHandler(self._notification_q))
                # listener = HelloHandler(ok_cb, err_cb)
                # self.add_listener(listener)
                #
                # self._connect_deferred = self.sendMsg(HelloHandler.build(self._client_capabilities,
                #                                                          self._device_handler))
                # watchdog = self.add_watchdog(self._connect_deferred, listener=listener)
                #
                # results = yield watchdog
                # # received hello message or an error happened
                # if error[0]:
                #     raise error[0]

            except Exception as e:
                logger.exception(e.message)     # TODO: Test various failure and refactor this
                raise

    def sendMsg(self, data):
        """Send the supplied *message* (xml string) to NETCONF server."""
        chan = self._channel

        if not self.connected or not chan:
            raise TransportError('Not connected to NETCONF server')

        def start_delim(data_len): return '\n#%s\n'% data_len

        try:
            # send a HELLO msg using v1.0 EOM markers.
            validated_element(data, tags='{urn:ietf:params:xml:ns:netconf:base:1.0}hello')
            data = "%s%s" % (data, MSG_DELIM)

        except XMLError:
            # this is not a HELLO msg
            # we publish v1.1 support
            if 'urn:ietf:params:netconf:base:1.1' in self._client_capabilities:
                if self._server_capabilities:
                    if 'urn:ietf:params:netconf:base:1.1' in self._server_capabilities:
                        # send using v1.1 chunked framing
                        data = "%s%s%s" % (start_delim(len(data)), data, END_DELIM)
                    elif 'urn:ietf:params:netconf:base:1.0' in self._server_capabilities or 'urn:ietf:params:xml:ns:netconf:base:1.0' in self._server_capabilities:
                        # send using v1.0 EOM markers
                        data = "%s%s" % (data, MSG_DELIM)
                    else:
                        raise Exception
                else:
                    logger.debug('HELLO msg was sent, but server capabilities are still not known')
                    raise Exception

            # we publish only v1.0 support
            else:
                # send using v1.0 EOM markers
                data = "%s%s" % (data, MSG_DELIM)
        finally:
            logger.debug("Sending: %s", data)
            return chan.write(data)

    def add_watchdog(self, deferred, listener=None, timeout=60):
        def callback(value):
            if listener:
                self.remove_listener(listener)

            if not watchdog.called:
                watchdog.cancel()
                logger.info('initialized: session-id=%s | server_capabilities=%s' %
                            (self._id, self.server_capabilities))
            else:
                raise SessionError('Capability exchange timed out')
            return value

        deferred.addBoth(callback)

        from twisted.internet import reactor
        watchdog = reactor.callLater(timeout, defer.timeout, deferred)
        return watchdog

    def _connect_failed(self, error):
        raise SSHError("Could not open connection, possibly due to unacceptable"
                       " SSH subsystem name.")

    @property
    def transport(self):
        "Underlying `paramiko.Transport <http://www.lag.net/paramiko/docs/paramiko.Transport-class.html>`_ object. This makes it possible to call methods like :meth:`~paramiko.Transport.set_keepalive` on it."
        return self._transport

    @property
    def connect_deferred(self):
        return self._connect_deferred

    @property
    def channel(self):
        return self._channel

    @channel.setter
    def channel(self, value):
        self._channel = value

    def run(self):
        pass

    def scp(self):
        pass
