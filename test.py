#!/usr/bin/env python
# Quick and dirty NETCONF client for testing

import pprint
import argparse
import os
#from ncclient import manager, xml_, capabilities
from tncclient import manager, xml_, capabilities
from tncclient.operations.rpc import SyncMode
from lxml import etree
from twisted.internet import reactor, defer
from twisted.internet.defer import returnValue, inlineCallbacks

_pp = pprint.PrettyPrinter(indent=2)

allNamespaces = {
    "adtn-evcs": "http://www.adtran.com/ns/yang/adtran-evcs",
    "adtn-evc-maps": "http://www.adtran.com/ns/yang/adtran-evc-maps",
    "adtn-policers": "http://www.adtran.com/ns/yang/adtran-policers",
    "adtn-shapers": "http://www.adtran.com/ns/yang/adtran-traffic-shapers",
    "adtn-subsystem-traces": "http://www.adtran.com/ns/yang/adtran-subsystem-traces",
    "adtn-hello": "http://www.adtran.com/ns/yang/adtran-hello",
}
onf_ns = {'of-config': 'urn:onf:config:yang'}


# For an evc, look at
#   http://confluence.adtran.com/display/AgileDev/OSA+L2+KB+-+Netconf+Testing+Examples
# http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.452.8737&rep=rep1&type=pdf
# https://trac.ietf.org/trac/edu/raw-attachment/wiki/IETF94/94-module-3-netconf.pdf
# https://github.com/ksator/python-training-for-network-engineers/blob/master/rpc-netconf-lxml-ncclient/ncclient.md
# TODO: Look into   yang tools netconf_utils for netconf code generation


def pp(value):
    pprint.PrettyPrinter(indent=2).pprint(value)


def elem2dict(node):
    """
    Convert an lxml.etree node tree into a dict.
    """
    d = {}
    for e in node.iterchildren():
        key = e.tag.split('}')[1] if '}' in e.tag else e.tag
        value = e.text if e.text else elem2dict(e)
        d[key] = value
    return d


def etree_to_dict(t, discard_ns=False):
    d = {t.tag: map(etree_to_dict, t.iterchildren())}
    d.update(('@' + k, v) for k, v in t.attrib.iteritems())
    d['text'] = t.text
    return d


def recursive_dict(element):
    return element.tag, \
           dict(map(recursive_dict, element)) or element.text


class Main(object):
    def __init__(self, ip_address, username, password, port=830, is_async=False, is_twisted=False):
        self.ip_address = ip_address
        self.port = port
        self.username = username
        self.password = password
        self.manager = None
        self.capabilities = None
        if is_twisted:
            self.sync_mode = SyncMode.ASYNCHRONOUS_TWISTED
        elif is_async:
            self.sync_mode = SyncMode.ASYNCHRONOUS_THREADED
        else:
            self.sync_mode = SyncMode.SYNCHRONOUS

    def __str__(self):
        return "netconf {}@{}".format(self.username, self.ip_address)

    def connect(self):
        # o To disable attempting publickey authentication altogether, call with
        #   allow_agent and look_for_keys as False.
        #
        # o hostkey_verify enables hostkey verification from ~/.ssh/known_hosts

        connection = manager.connect(host=self.ip_address,
                                     port=self.port,
                                     username=self.username,
                                     password=self.password,
                                     allow_agent=False,
                                     look_for_keys=False,
                                     hostkey_verify=False,
                                     sync_mode=self.sync_mode)

        if self.sync_mode == SyncMode.ASYNCHRONOUS_THREADED:
            connection.async_mode = True

        return connection

    def output_results(self, results, text=None):
        print(os.linesep + '=================================================')
        if text is not None:
            print(text)
        pp(results)

    def do_work(self):
        ##########################################################################
        # Connect to the NETCONF Server and exchange capabilities

        connection = self.connect()
        self.manager = connection

        # full = self.get_full_config()
        #
        # if self.sync_mode == SyncMode.ASYNCHRONOUS_TWISTED:
        #     full.addBoth(self.output_results, text='Full device config follows:')
        # else:
        #     assert self.manager.connected
        #     self.output_results(full, text='Full device config follows:')
        #
        # # full_dict = elem2dict(full.data_ele)
        # # full_dict = etree_to_dict(full.data_ele)
        # # full_dict = recursive_dict(full.data_ele)
        # # pp(full_dict)
        #
        # # Only do the next if not twisted. No special reason, just didn't want to mess with it
        #
        # if self.sync_mode != SyncMode.ASYNCHRONOUS_TWISTED:
        #     xml, ident = self.get_id()
        #     self.output_results(xml, text='ID Information follows:')
        #     print('  ID id: {}'.format(ident))


    def start(self):
        if self.sync_mode == SyncMode.ASYNCHRONOUS_TWISTED:
            reactor.callLater(0, self.do_work)
            reactor.run()

        else:
            self.do_work()

    def wait_for_response(self, request):
        # If not asynchronous, request is an RpcReply object
        # If async, request is an operations object
        if self.sync_mode == SyncMode.SYNCHRONOUS:
            return request

        def check_async(op):
            from ncclient import NCClientError

            if op.error is not None:  # e.g. transport layer error
                return op.error
            elif not op.reply.ok:  # <rpc-error>(s) present
                return op.reply.error

        if self.sync_mode == SyncMode.ASYNCHRONOUS_TWISTED:
            raise NotImplemented('TODO: Twisted is not yet supported in the test app')
        else:
            request.event.wait(self.manager.timeout)
            error = check_async(request)
            if error is not None:
                raise error

        return request.reply

    def get_full_config(self, source='running'):
        """
        Get the configuration from the specified source

        :param source: (string) Configuration source, 'running', 'candidate', ...

        :return: XML rpc-reply such as:

        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:uuid:c9a15c6e-50ed-4a05-ac54-38d9e227a44e">
          <data>
            <capable-switch xmlns="urn:onf:config:yang">
              <id>openvswitch</id>
              <resources>
                <port>
                  <name>ofc-bridge</name>
                  <requested-number>666</requested-number>
                  <configuration>
                    <admin-state>down</admin-state>
                    <no-receive>false</no-receive>
                    <no-forward>false</no-forward>
                    <no-packet-in>false</no-packet-in>
                  </configuration>
                </port>
              </resources>
              <logical-switches>
                <switch>
                  <id>ofc-bridge</id>
                  <datapath-id>00:01:02:03:04:05:06:07</datapath-id>
                  <lost-connection-behavior>failSecureMode</lost-connection-behavior>
                  <resources>
                    <port>ofc-bridge</port>
                  </resources>
                </switch>
              </logical-switches>
            </capable-switch>
          </data>
        </rpc-reply>         
        """
        request = self.manager.get_config(source)

        return self.wait_for_response(request)

    def get_id(self, source='running'):
        assert self.sync_mode != SyncMode.ASYNCHRONOUS_TWISTED

        id_filter = xml_.new_ele('filter')
        switch_filter = xml_.sub_ele(id_filter, 'capable-switch', nsmap=onf_ns)
        _ = xml_.sub_ele(switch_filter, 'id')

        request = self.manager.get_config(source, filter=id_filter)
        response = self.wait_for_response(request)

        return response, response.data_ele[0][0].text

    @property
    def caps(self):
        if self.capabilities is None:
            self.capabilities = self.manager.server_capabilities()
        return self.capabilities

    def get_namespaced_xml_text(self, path):
        response = self.manager.get_xml_response()
        print("The response was:" + response)
        xml_root = etree.fromstring(response)

        results = xml_root.xpath(path, namespaces=allNamespaces)
        if len(results) == 1:
            return results[0].text
        else:
            return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NETCONF Test App')
    parser.add_argument('--ip_address', '-i', action='store', default=None, help='IP Address of NETCONF server')
    parser.add_argument('--username', '-u', action='store', default='mininet', help='Username')
    parser.add_argument('--password', '-p', action='store', default='mininet', help='Password')
    parser.add_argument('--port', '-P', action='store', default=830, help='TCP Port')
    parser.add_argument('--async', '-a', action='store_true', help='Do all operations asynchronously')
    parser.add_argument('--twisted', '-t', action='store_true', help='Use twisted-reactor for all operations')

    args = parser.parse_args()

    Main(args.ip_address,
         port=args.port,
         username=args.username,
         password=args.password,
         is_async=args.async,
         is_twisted=args.twisted).start()

# 'http://www.adtran.com/ns/yang/adtran-hello?module=adtran-hello&revision=2015-07-20': [],

# {'http://www.adtran.com/ns/yang/adtran-access-control-lists?module=adtran-access-control-lists&revision=2016-08-04&features=extended-acl,ipv4-wildcard,hostname,rule-match-counter': [],
#  'http://www.adtran.com/ns/yang/adtran-alarming-test?module=adtran-alarming-test&revision=2016-04-27': [],
#  'http://www.adtran.com/ns/yang/adtran-alarming-types?module=adtran-alarming-types&revision=2017-01-05&features=alarm-severity-profiles': [],
#  'http://www.adtran.com/ns/yang/adtran-alarming?module=adtran-alarming&revision=2016-04-21&features=alarm-status-change,alarm-inventory,alarm-summary,alarm-rpc,alarm-notification': [],
#  'http://www.adtran.com/ns/yang/adtran-availability-status?module=adtran-availability-status&revision=2016-11-23&features=availability-status': [],
#  'http://www.adtran.com/ns/yang/adtran-diagnostic-jobs?module=adtran-diagnostic-jobs&revision=2016-11-16&features=upload-status': [],
#  'http://www.adtran.com/ns/yang/adtran-entities?module=adtran-entities&revision=2016-05-04': [],
#  'http://www.adtran.com/ns/yang/adtran-ethernet-performance-management?module=adtran-ethernet-performance-management&revision=2016-11-08': [],
#  'http://www.adtran.com/ns/yang/adtran-ethernet?module=adtran-ethernet&revision=2017-03-16': [],
#  'http://www.adtran.com/ns/yang/adtran-evc-management?module=adtran-evc-management&revision=2016-03-25': [],
#  'http://www.adtran.com/ns/yang/adtran-evc-map-subscriber-statistics?module=adtran-evc-map-subscriber-statistics&revision=2016-09-26': [],
#  'http://www.adtran.com/ns/yang/adtran-evc-map-subscribers?module=adtran-evc-map-subscribers&revision=2016-01-28&features=server-ip-address': [],
#  'http://www.adtran.com/ns/yang/adtran-evc-maps?module=adtran-evc-maps&revision=2016-12-09&features=match-criteria-ce-dscp,match-criteria-destination-mac-address,match-criteria-l2cp,match-criteria-xcast,match-criteria-igmp,evc-map-availability-status,network-vlan-reporting,uni-egress-queue-mapping,network-ingress-filter,network-ingress-filter-men-pri': [],
#  'http://www.adtran.com/ns/yang/adtran-evcs?module=adtran-evcs&revision=2017-03-03&features=double-tag-switching,mac-switching,double-tag-mac-switching,mac-address-table,evc-availability-status,evc-stag-tpid,men-to-uni-tag-manipulation,men-to-uni-tag-manipulation-pop-outer-tag-only': [],
#  'http://www.adtran.com/ns/yang/adtran-event-types?module=adtran-event-types&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-exception-reports?module=adtran-exception-reports&revision=2016-08-31': [],
#  'http://www.adtran.com/ns/yang/adtran-file-servers-https?module=adtran-file-servers-https&revision=2016-10-11&features=http,https,redirection': [],
#  'http://www.adtran.com/ns/yang/adtran-file-servers-proxy?module=adtran-file-servers-proxy&revision=2016-10-11': [],
#  'http://www.adtran.com/ns/yang/adtran-file-servers-sftp-jobs?module=adtran-file-servers-sftp-jobs&revision=2015-10-16': [],
#  'http://www.adtran.com/ns/yang/adtran-file-servers-sftp?module=adtran-file-servers-sftp&revision=2016-04-22&features=sftp,sftp-rpc,sftp-client-authentication,sftp-import-export-keys': [],
#  'http://www.adtran.com/ns/yang/adtran-file-servers-supervision?module=adtran-file-servers-supervision&revision=2016-10-11': [],
#  'http://www.adtran.com/ns/yang/adtran-file-servers?module=adtran-file-servers&revision=2016-11-15&features=distribution-profiles,tftp,ftp,custom-port,file-server-profile-availability-status': [],
#  'http://www.adtran.com/ns/yang/adtran-hello?module=adtran-hello&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-igmp-multicast-groups?module=adtran-igmp-multicast-groups&revision=2016-08-22&features=igmp-multicast-group-bandwidth': [],
#  'http://www.adtran.com/ns/yang/adtran-igmp-multicast-packages?module=adtran-igmp-multicast-packages&revision=2016-08-22&features=multicast-packages': [],
#  'http://www.adtran.com/ns/yang/adtran-igmp?module=adtran-igmp&revision=2016-08-22': [],
#  'http://www.adtran.com/ns/yang/adtran-interface-entities?module=adtran-interface-entities&revision=2016-03-18&features=interface-slot,interface-shelf,interface-oper-status-down-alarm,interface-availability-status': [],
#  'http://www.adtran.com/ns/yang/adtran-interface-performance-management?module=adtran-interface-performance-management&revision=2016-11-08&features=performance-24hrs': [],
#  'http://www.adtran.com/ns/yang/adtran-interface-threshold-management?module=adtran-interface-threshold-management&revision=2017-03-15': [],
#  'http://www.adtran.com/ns/yang/adtran-interfaces?module=adtran-interfaces&revision=2016-10-10&features=interface-attributes,network-connection': [],
#  'http://www.adtran.com/ns/yang/adtran-internal-notification-simulator?module=adtran-internal-notification-simulator&revision=2016-11-15': [],
#  'http://www.adtran.com/ns/yang/adtran-internal-state-data-simulator?module=adtran-internal-state-data-simulator&revision=2016-11-16': [],
#  'http://www.adtran.com/ns/yang/adtran-maintenance-jobs?module=adtran-maintenance-jobs&revision=2016-11-16': [],
#  'http://www.adtran.com/ns/yang/adtran-notification-discovery?module=adtran-notification-discovery&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-notification-subscriptions?module=adtran-notification-subscriptions&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-notification-types?module=adtran-notification-types&revision=2016-04-21&features=notification-subscriptions': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-chassis?module=adtran-physical-chassis&revision=2015-10-16&features=chassis': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-containers?module=adtran-physical-containers&revision=2015-07-20&features=container,module-configuration': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-cpus?module=adtran-physical-cpus&revision=2016-04-01': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-entities?module=adtran-physical-entities&revision=2016-06-07': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-entity-alarms?module=adtran-physical-entity-alarms&revision=2016-09-15&features=physical-entity-hw-dependency-alarm': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-entity-availability?module=adtran-physical-entity-availability&revision=2016-11-18': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-fans?module=adtran-physical-fans&revision=2016-09-15&features=fan,fan-not-installed-alarm,fan-dependency-alarm,fan-failed-alarm': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-module-power?module=adtran-physical-module-power&revision=2015-12-01': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-module-resources?module=adtran-physical-module-resources&revision=2016-08-15&features=cpu-statistics,maximum-cpu-utilization,memory-statistics,flash-statistics,ram-statistics,heap-statistics,block-manager-statistics,block-manager-partitions,resource-alarming': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-module-transceivers?module=adtran-physical-module-transceivers&revision=2017-02-10&features=adtran-approved-transceivers': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-modules?module=adtran-physical-modules&revision=2016-04-25&features=module': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-sensor-temperature?module=adtran-physical-sensor-temperature&revision=2016-03-18&features=inactive-thresholds,high-temp-alarm,low-temp-alarm,thermal-shutdown,power-reduction': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-sensors?module=adtran-physical-sensors&revision=2016-09-15&features=sensor,threshold-crossing-alarms': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-software-maintenance?module=adtran-physical-software-maintenance&revision=2016-12-06&features=activate-software,commit-software': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-software?module=adtran-physical-software&revision=2015-10-05': [],
#  'http://www.adtran.com/ns/yang/adtran-physical-stack?module=adtran-physical-stack&revision=2015-07-20&features=stack': [],
#  'http://www.adtran.com/ns/yang/adtran-pm-attributes-ethernet?module=adtran-pm-attributes-ethernet&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-pm-notifications?module=adtran-pm-notifications&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-pm-types?module=adtran-pm-types&revision=2015-12-10': [],
#  'http://www.adtran.com/ns/yang/adtran-policers?module=adtran-policers&revision=2016-12-09&features=uni-egress-policing,policer-availability-status,color-marking,policer-statistics,reset-policer-statistics': [],
#  'http://www.adtran.com/ns/yang/adtran-queues?module=adtran-queues&revision=2017-03-03&features=dynamic-queue-weight,queue-profiles,static-queue-configuration,queue-profile-availability-status,system-queue-configuration,color-aware-queues': [],
#  'http://www.adtran.com/ns/yang/adtran-rest-api?module=adtran-rest-api&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-rest-auth?module=adtran-rest-auth&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-ssh-key-types?module=adtran-ssh-key-types&revision=2016-06-07': [],
#  'http://www.adtran.com/ns/yang/adtran-subscriber-profiles?module=adtran-subscriber-profiles&revision=2017-03-15&features=vendor-specific-insertion,line-characteristic-insertion,vendor-specific-enterprise-number,umas,access-node-id,ipas,subscriber-profile-availability-status,connect-per-evc-per-uni,connect-per-evc-map,dhcp-inverted-pass-through,pppoe-inverted-pass-through,igmp-explicit-host-tracking,multicast-group-limiting,igmp-proxy-reporting,igmp-multicast-group-configuration,igmp-static-multicast-groups,igmp-querier-parameters,igmp-upstream-priority,igmp-downstream-priority,igmp-proxy-host,igmp-proxy-router-igmp-version,igmp-multicast-group-bandwidth,igmp-maximum-multicast-bandwidth,igmp-minimum-unicast-bandwidth': [],
#  'http://www.adtran.com/ns/yang/adtran-subscriber-statistics?module=adtran-subscriber-statistics&revision=2016-09-26': [],
#  'http://www.adtran.com/ns/yang/adtran-subsystem-traces?module=adtran-subsystem-traces&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-system-entities?module=adtran-system-entities&revision=2016-04-15&features=configuration-storage,configurable-persistence,system-access-node-id': [],
#  'http://www.adtran.com/ns/yang/adtran-system-ntp?module=adtran-system-ntp&revision=2016-04-14&features=ntp-client-alarming,ntp-message-authentication': [],
#  'http://www.adtran.com/ns/yang/adtran-system-platform?module=adtran-system-platform&revision=2015-07-20': [],
#  'http://www.adtran.com/ns/yang/adtran-system-types?module=adtran-system-types&revision=2015-09-28': [],
#  'http://www.adtran.com/ns/yang/adtran-traffic-management?module=adtran-traffic-management&revision=2016-09-29&features=subscriber-authentication,dhcp,ipoe,pppoe,igmp,men-ctag,arp,qos-untagged-cos': [],
#  'http://www.adtran.com/ns/yang/adtran-traffic-shapers?module=adtran-traffic-shapers&revision=2016-12-09&features=per-queue-shaping,shaper-availability-status': [],
#  'http://www.adtran.com/ns/yang/adtran-xpon-applications?module=adtran-xpon-applications&revision=2017-03-14': [],
#  'http://www.adtran.com/ns/yang/adtran-xpon-yang-types?module=adtran-xpon-yang-types&revision=2017-03-28': [],
#  'http://www.adtran.com/ns/yang/adtran-xpon?module=adtran-xpon&revision=2017-03-28&features=vdsl-support,optical-power-support,acs-server-profile': [],
#  'http://www.adtran.com/ns/yang/adtran-yang-extensions?module=adtran-yang-extensions&revision=2015-10-16': [],
#  'http://www.adtran.com/ns/yang/adtran-yang-types?module=adtran-yang-types&revision=2016-10-26': [],
#  'urn:cesnet:tmc:netopeer:1.0?module=netopeer-cfgnetopeer&revision=2015-05-19&features=ssh,dynamic-modules': [],
#  'urn:ietf:params:netconf:base:1.0': [':base', ':base:1.0'],
#  'urn:ietf:params:netconf:base:1.1': [':base', ':base:1.1'],
#  'urn:ietf:params:netconf:capability:candidate:1.0': [':candidate',
#                                                       ':candidate:1.0'],
#  'urn:ietf:params:netconf:capability:interleave:1.0': [':interleave',
#                                                        ':interleave:1.0'],
#  'urn:ietf:params:netconf:capability:notification:1.0': [':notification',
#                                                          ':notification:1.0'],
#  'urn:ietf:params:netconf:capability:rollback-on-error:1.0': [':rollback-on-error',
#                                                               ':rollback-on-error:1.0'],
#  'urn:ietf:params:netconf:capability:validate:1.0': [':validate',
#                                                      ':validate:1.0'],
#  'urn:ietf:params:netconf:capability:validate:1.1': [':validate',
#                                                      ':validate:1.1'],
#  'urn:ietf:params:netconf:capability:with-defaults:1.0': [':with-defaults',
#                                                           ':with-defaults:1.0'],
#  'urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=explicit&also-supported=report-all,report-all-tagged,trim,explicit': [':with-defaults',
#                                                                                                                                         ':with-defaults:1.0?basic-mode=explicit&also-supported=report-all,report-all-tagged,trim,explicit'],
#  'urn:ietf:params:netconf:capability:writable-running:1.0': [':writable-running',
#                                                              ':writable-running:1.0'],
#  'urn:ietf:params:xml:ns:netconf:base:1.0?module=ietf-netconf&revision=2011-03-08&features=writable-running,candidate,rollback-on-error,validate,startup': [':base',
#                                                                                                                                                             ':base:1.0?module=ietf-netconf&revision=2011-03-08&features=writable-running,candidate,rollback-on-error,validate,startup'],
#  'urn:ietf:params:xml:ns:netconf:base:1.0?module=ietf-netconf&revision=2011-06-01&features=writable-running,candidate,rollback-on-error,validate,startup': [':base',
#                                                                                                                                                             ':base:1.0?module=ietf-netconf&revision=2011-06-01&features=writable-running,candidate,rollback-on-error,validate,startup'],
#  'urn:ietf:params:xml:ns:netconf:notification:1.0?module=notifications&revision=2008-07-14': [],
#  'urn:ietf:params:xml:ns:netmod:notification?module=nc-notifications&revision=2008-07-14': [],
#  'urn:ietf:params:xml:ns:yang:iana-crypt-hash?module=iana-crypt-hash&revision=2014-08-06&features=crypt-hash-md5,crypt-hash-sha-256,crypt-hash-sha-512': [],
#  'urn:ietf:params:xml:ns:yang:iana-if-type?module=iana-if-type&revision=2015-06-12': [],
#  'urn:ietf:params:xml:ns:yang:ietf-inet-types?module=ietf-inet-types&revision=2013-07-15': [],
#  'urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces&revision=2014-05-08&features=arbitrary-names,pre-provisioning,if-mib': [],
#  'urn:ietf:params:xml:ns:yang:ietf-netconf-acm?module=ietf-netconf-acm&revision=2012-02-22': [],
#  'urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&revision=2010-10-04': [],
#  'urn:ietf:params:xml:ns:yang:ietf-netconf-notifications?module=ietf-netconf-notifications&revision=2011-08-07': [],
#  'urn:ietf:params:xml:ns:yang:ietf-netconf-notifications?module=ietf-netconf-notifications&revision=2012-02-06': [],
#  'urn:ietf:params:xml:ns:yang:ietf-netconf-server?module=ietf-netconf-server&revision=2014-01-24&features=ssh,inbound-ssh,outbound-ssh': [],
#  'urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults?module=ietf-netconf-with-defaults&revision=2010-06-09': [],
#  'urn:ietf:params:xml:ns:yang:ietf-system?module=ietf-system&revision=2014-08-06&features=radius,authentication,local-users,radius-authentication,ntp,ntp-udp-port,timezone-name,dns-udp-tcp-port': [],
#  'urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name?module=ietf-x509-cert-to-name&revision=2013-03-26': [],
#  'urn:ietf:params:xml:ns:yang:ietf-yang-types?module=ietf-yang-types&revision=2013-07-15': []}

#
# import pprint
# from ncclient import manager, xml_, capabilities
# from lxml import etree
# def dummy():
# def pp(value): pprint.PrettyPrinter(indent=2).pprint(value)
#
# ip = '192.168.0.22'
# ip = '172.22.12.241'
# username = 'mininet'
# password = 'mininet'
# mgr = manager.connect(host=ip,port=830,username=username,password=password, allow_agent=False,look_for_keys=False, hostkey_verify=False)
# mgr.connected
#
# source = 'running'
#
# full_config = mgr.get_config(source)
# pp(full_config)
#
# # Namespaces
#
# onf_ns = {'of-config': 'urn:onf:config:yang'}
# with_def_ns = {'with-defaults': 'urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults'}
#
# # ID
#
# id_filter = xml_.new_ele('filter')
# switch_filter = xml_.sub_ele(id_filter, 'capable-switch', nsmap=onf_ns)
# _ = xml_.sub_ele(switch_filter, 'id')
#
# ident_data = mgr.get_config(source, filter=id_filter)
# pp(ident_data)
#
# # Resources
#
# resource_filter = xml_.new_ele('filter')
# switch_filter = xml_.sub_ele(resource_filter, 'capable-switch', nsmap=onf_ns)
# _ = xml_.sub_ele(switch_filter, 'resources')
#
# resource_data = mgr.get_config(source, filter=resource_filter)
# pp(resource_data)
