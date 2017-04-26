from lxml import etree

from tncclient.xml_ import *
from tncclient.operations.rpc import RPC

class ExecCommand(RPC):
    def request(self, cmds):
        node = etree.Element(qualify('exec-command', NXOS_1_0))

        for cmd in cmds:
            etree.SubElement(node, qualify('cmd', NXOS_1_0)).text = cmd

        return self._request(node)
