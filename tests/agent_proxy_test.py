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
                ("AAAAB3NzaC1yc2EAAAADAQABAAABAQDtsi2KpukVzMnOmGyT3pDwmyiVSID"
                 "mhj2J9t3b2XbASMy32Jm8ZrHnjKOsVQVBWaPDwlSvqPSCME5cTMu/bLkQ6P"
                 "Zl2lsyvfmUQFmR2sFAy9M0SNjbllix2cxuxW3iB6m5I+67HndxIf0YCRBxk"
                 "h3CKrUnqlJLkS8G6BhwSTufw6VKHsHQoMKA8sx0K3CuSpSC4UptBnjOzVfV"
                 "e+Su/CxzGkidaZnSKs3Tqw48L4NYYczMZhhSZDOktgti/1wK43jWan8HjQ+"
                 "wXx15FVEKsXTMPncAZCjIw2OeZ42NinkWd+kk1ICOhJmAqLNLCJQp+GY7m5"
                 "hJO2U+OQtXTUpeuOPV",),
                proxy.list()
        )

    def test_read_no_keys(self):
        proxy = agent_proxy.AgentProxy(
                sock=DummySocket("list_no_keys_input.bin")
        )
        self.assertSequenceEqual((), proxy.list())

    def test_read_two_keys(self):
        proxy = agent_proxy.AgentProxy(
                sock=DummySocket("list_two_keys_dsa_rsa.bin")
        )
        self.assertSequenceEqual(
                ("AAAAB3NzaC1kc3MAAACBAL0WYTvla66/+R11GIr81uy9Dv0u24idCkjGLg/"
                 "u6TpowqJypm4zp6ED1raMV1iv4ShH9mPZmVDt44BaB8mpyeEj1tm9FzXDhy"
                 "AosPx2CIKcNorooRWuwl9tMOsMNlG5ZPBSsyfVaf1P7ygHMBcWCKyBBx38R"
                 "zIli15dQbSaH1qXAAAAFQC+uQOvC7eTsliLFqMB/5zzPjR+swAAAIAINv21"
                 "2r0lT/lem9P6jIm1+AZyRUGlSvXFv7HPI/F0Lp5EFCBBmgxT4AWoBRIsaiO"
                 "Zva/XMR8NTEtpkmI+4/dQrFnrpTo33KIIhb8kEBrLMII+b3Afn1Dv6bPty+"
                 "NtoD0MX4Soy/GZx3ta+QKrs3hiPmiBOvzBGOqQCgVoxVLSzwAAAIAEuQL4l"
                 "cGDU/6W0RHQEX4wyOvp41KCGNs4cMK2Ig5TsbPEh0Sv4QdSYCsuKJUlMQ5D"
                 "rhVQYxfOqSTloWV2Xy15JvIX6Au5mMS78DZx1+k68lx+EeVFFjbZ4Y2Xga4"
                 "K3FTfmaE8+Xvk0SPM1bkIkwtEU1uMl/gaYawxjJHH+Sstdg==",
                 "AAAAB3NzaC1yc2EAAAADAQABAAABAQDtsi2KpukVzMnOmGyT3pDwmyiVSID"
                 "mhj2J9t3b2XbASMy32Jm8ZrHnjKOsVQVBWaPDwlSvqPSCME5cTMu/bLkQ6P"
                 "Zl2lsyvfmUQFmR2sFAy9M0SNjbllix2cxuxW3iB6m5I+67HndxIf0YCRBxk"
                 "h3CKrUnqlJLkS8G6BhwSTufw6VKHsHQoMKA8sx0K3CuSpSC4UptBnjOzVfV"
                 "e+Su/CxzGkidaZnSKs3Tqw48L4NYYczMZhhSZDOktgti/1wK43jWan8HjQ+"
                 "wXx15FVEKsXTMPncAZCjIw2OeZ42NinkWd+kk1ICOhJmAqLNLCJQp+GY7m5"
                 "hJO2U+OQtXTUpeuOPV"),
                proxy.list()
        )
