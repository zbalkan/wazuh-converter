#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from huawei_usg.ini
class TestHuaweiUsgRules(unittest.TestCase):

    def test_huawei_usg_filter(self) -> None:
        log = r'''
2018/10/05 09:52:14 USG6300 %%01URL/4/FILTER(l): The URL filtering policy was matched. (SyslogId=1906054, VSys="public", Policy="Internet Access", SrcIp=1.1.1.1, DstIp=2.2.2.2, SrcPort=5702, DstPort=80, SrcZone=dmz, DstZone=untrust, User="unknown", Protocol=TCP, Application="google", Profile="prof1", Type=Pre-defined, EventNum=1, Category="Search Engines/Portals", SubCategory="Search Engines", Page="*", Host="www.google.com", Item="none", Action=Alert)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'huawei-usg')
        self.assertEqual(response.rule_id, '89214')
        self.assertEqual(response.rule_level, 3)


    def test_huawei_usg_default_level_6_1(self) -> None:
        log = r'''
Oct  5 2018 10:52:19 USG6300 %%01POLICY/6/POLICYPERMIT(l):vsys=public, protocol=17, source-ip=1.1.1.1, source-port=2426, destination-ip=2.2.2.2, destination-port=2234, time=2018/10/5 09:52:19, source-zone=dmz, destination-zone=untrust, rule-name=Internet Access.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'huawei-usg')
        self.assertEqual(response.rule_id, '89216')
        self.assertEqual(response.rule_level, 0)


    def test_huawei_usg_default_level_6_2(self) -> None:
        log = r'''
2018-10-05 10:52:13 USG6300 %%01SECLOG/6/SESSION_TEARDOWN(l):IPVer=4,Protocol=tcp,SourceIP=1.1.1.1,DestinationIP=2.2.2.2,SourcePort=6182,DestinationPort=443,BeginTime=1538736476,EndTime=1538736733,SendPkts=21,SendBytes=2135,RcvPkts=18,RcvBytes=1534,SourceVpnID=0,DestinationVpnID=0,PolicyName=Internet Access.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'huawei-usg')
        self.assertEqual(response.rule_id, '89216')
        self.assertEqual(response.rule_level, 0)

