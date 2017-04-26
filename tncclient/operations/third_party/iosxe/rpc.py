from lxml import etree

from tncclient.xml_ import *
from tncclient.operations.rpc import RPC

class SaveConfig(RPC):
    def request(self, cmds):
        node = etree.Element(qualify('save-config', "http://cisco.com/yang/cisco-ia"))
        return self._request(node)
