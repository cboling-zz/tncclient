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
import os
import getpass
from twisted.conch.ssh.userauth import SSHUserAuthClient
from twisted.conch.client.default import SSHUserAuthClient
from twisted.conch.client.default import verifyHostKey as default_verifyHostKey
from twisted.internet import defer
from twisted.conch.ssh import keys

logger = logging.getLogger('tncclient.transport.connection')

# The default location of the known hosts file (probably should be parsed out
# of an ssh config file someday).
_KNOWN_HOSTS = "~/.ssh/known_hosts"

# Set CLIENT_RSA_PUBLIC to empty to not use SSH key auth.
# CLIENT_RSA_PUBLIC = 'ssh-keys/client_rsa.pub'  # Path to RSA SSH keys accepted by the server.
CLIENT_RSA_PUBLIC = ''
CLIENT_RSA_PRIVATE = 'ssh-keys/client_rsa'

# This name is bound so that the unit tests can use 'patch' to override it.
_open = open


def verify_host_key(transport, host, pubKey, fingerprint):
    """
    Skip hostkey authentications
    """
    options = transport.factory.options
    if options and not options.get('hostkey_verify', True):
        return defer.succeed('success')

    # TODO: Make use of keyfiles, fingerprint and other auth options
    return default_verifyHostKey(transport, host, pubKey, fingerprint)


class NetconfUserAuthClient(SSHUserAuthClient):

    def __init__(self, user, options, *args):
        self._host = options['host']
        self._password = options['password']
        SSHUserAuthClient.__init__(self, user, options, *args)

    def getPassword(self):
        """
        Return a L{Deferred} that will be called back with a password.
        prompt is a string to display for the password, or None for a generic
        'user@hostname's password: '.

        @type prompt: L{bytes}/L{None}
        @rtype: L{defer.Deferred}
        """
        if self._password is None:
            # TODO: May want to just use base class here
            self._password = getpass.getpass("%s@%s's password: " % (self.user, self._host))

        return defer.succeed(self._password)


    def getPublicKey(self):
        """
        Return a public key for the user.  If no more public keys are
        available, return L{None}.

        This implementation always returns L{None}.  Override it in a
        subclass to actually find and return a public key object.

        @rtype: L{Key} or L{None}
        """
        # TODO: May want to just use base class here
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
        # TODO: May want to just use base class here
        return defer.succeed(keys.Key.fromFile(CLIENT_RSA_PRIVATE))
