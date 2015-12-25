# Copyright 2015 Spotify AB
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
import base64
import os
import socket
import struct

SSH2_AGENTC_REQUEST_IDENTITIES = 11


class AgentProxy(object):
    """
    An AgentProxy is an object that provides communications facilities
    to an ssh-agent process.
    """
    def __init__(self, socket_path=os.getenv("SSH_AUTH_SOCK"), sock=None):
        """
        Constructs an AgentProxy set up to communicate with a local ssh-agent

        :param socket_path: A string referencing the path of a unix socket
         used to communicate with the ssh-agent. If not provided, the
         SSH_AUTH_SOCK environment variable is used.
        :param sock: An alternative sock implementation used to communicate
         with ssh-agent
        """
        if sock:
            self.sock = sock
        else:
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.settimeout(5.0)
            self.sock.connect(socket_path)

    def list(self):
        """
        Lists the keys that the ssh agent you are connecting to holds.

        :return: a tuple of strings containing ssh public keys in the single
        line format that OpenSSH uses.
        """
        _write_field(self.sock, SSH2_AGENTC_REQUEST_IDENTITIES)
        data = _safe_recv(self.sock, 9)
        length, response_code, count = struct.unpack("!IBI", data)
        fields = read_fields(_safe_recv(self.sock, (length - 5)))
        # every other line is a filename, ignore them
        keys = [y for x, y in enumerate(fields) if not x % 2]
        return tuple(base64.b64encode(x) for x in keys)


def _safe_recv(sock, count):
    """
    Wraps sock.recv() handling short reads.

    :param sock: a socket to recv() from
    :param count: the number of bytes to ask for
    :return: a byte string with those bytes
    """
    result = sock.recv(count)
    bytes_read = len(result)
    if 0 < bytes_read < count:
        return result + _safe_recv(sock, count - bytes_read)
    return result


def _write_field(sock, data):
    if type(data) is int and data < 0x80:
        data = chr(data)
    elif type(data) is not str:
        data = repr(data)
    sock.send(struct.pack("!I", len(data)) + data)


def read_fields(data):
    off = 0
    while off < len(data):
        l = _s2i(data[off:])
        off += 4
        yield data[off:off + l]
        off += l


def _s2i(data):
    """Read four bytes off the provided byte string and return the value as
    a big endian 32 bit unsigned integer

    :param data: the byte string to read from.
    """
    num = 0
    for i, val in enumerate(data[:4]):
        num += ord(val) << ((3 - i) * 8)
    return num
