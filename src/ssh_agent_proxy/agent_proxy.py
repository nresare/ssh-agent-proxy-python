import base64
import os
import socket
import struct

SSH2_AGENTC_REQUEST_IDENTITIES = 11


class AgentProxy(object):
    def __init__(self, socket_path=os.getenv("SSH_AUTH_SOCK"), sock=None):
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
        write_field(self.sock, SSH2_AGENTC_REQUEST_IDENTITIES)
        data = safe_recv(self.sock, 9)
        length, response_code, count = struct.unpack("!IBI", data)
        fields = read_fields(safe_recv(self.sock, (length - 5)))
        # every other line is a filename, ignore them
        keys = [y for x, y in enumerate(fields) if not x % 2]
        return tuple(base64.b64encode(x) for x in keys)


def safe_recv(sock, count):
    """
    Wraps sock.recv() handling short reads.

    :param sock: a socket to recv() from
    :param count: the number of bytes to ask for
    :return: a byte string with those bytes
    """
    result = sock.recv(count)
    bytes_read = len(result)
    if 0 < bytes_read < count:
        return result + safe_recv(sock, count - bytes_read)
    return result


def write_field(sock, data):
    if type(data) is int and data < 0x80:
        data = chr(data)
    elif type(data) is not str:
        data = repr(data)
    sock.send(struct.pack("!I", len(data)) + data)


def read_fields(data):
    off = 0
    while off < len(data):
        l = s2i(data[off:])
        off += 4
        yield data[off:off + l]
        off += l


def s2i(data):
    """Read four bytes off the provided byte string and return the value as
    a big endian 32 bit unsigned integer

    :param data: the byte string to read from.
    """
    num = 0
    for i, val in enumerate(data[:4]):
        num += ord(val) << ((3 - i) * 8)
    return num
