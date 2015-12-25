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
import os
import socket
import sys


def list_keys_dump_raw_data(out_file):
    """
     Connects to the ssh agent on localhost and requests a key listing, dumping
     what gets sent as a response to a file. Useful for constructing test data

    :param out_file: the filename to write to
    """
    with open(out_file, "w") as f:
        s = socket.socket(socket.AF_UNIX)
        s.connect(os.getenv("SSH_AUTH_SOCK"))
        s.send("\x00\x00\x00\x01\x0b")

        data = s.recv(8192)
        f.write(data)
        print "read and wrote %d bytes of data" % len(data)


if __name__ == '__main__':
    list_keys_dump_raw_data(sys.argv[1])
