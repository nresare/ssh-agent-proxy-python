import unittest

from ssh_agent_proxy import agent_proxy


class DummySocket(object):
    def __init__(self, file_name):
        with open(file_name, 'r') as f:
            self.data = f.read()
        self.pos = 0

    def recv(self, count):
        val = self.data[self.pos:self.pos + count]
        self.pos += count
        return val

    def send(self, data):
        pass


class AgentProxyTest(unittest.TestCase):
    def test_read_public_keys(self):
        proxy = agent_proxy.AgentProxy(
                sock=DummySocket("list_single_key_input.bin")
        )
        self.assertSequenceEqual(
                proxy.list(),
                ("AAAAB3NzaC1yc2EAAAADAQABAAABAQDtsi2KpukVzMnOmGyT3pDwmyiVSID"
                 "mhj2J9t3b2XbASMy32Jm8ZrHnjKOsVQVBWaPDwlSvqPSCME5cTMu/bLkQ6P"
                 "Zl2lsyvfmUQFmR2sFAy9M0SNjbllix2cxuxW3iB6m5I+67HndxIf0YCRBxk"
                 "h3CKrUnqlJLkS8G6BhwSTufw6VKHsHQoMKA8sx0K3CuSpSC4UptBnjOzVfV"
                 "e+Su/CxzGkidaZnSKs3Tqw48L4NYYczMZhhSZDOktgti/1wK43jWan8HjQ+"
                 "wXx15FVEKsXTMPncAZCjIw2OeZ42NinkWd+kk1ICOhJmAqLNLCJQp+GY7m5"
                 "hJO2U+OQtXTUpeuOPV",)
        )
