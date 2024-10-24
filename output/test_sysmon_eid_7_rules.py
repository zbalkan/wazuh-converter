#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sysmon_eid_7.ini
class TestSysmonEid7Rules(unittest.TestCase):

    def test_binary_loaded_powershell_automation_library(self) -> None:
        log = r'''
{"win":{"eventdata":{"originalFileName":"System.Management.Automation.dll","image":"C:\\\\Windows\\\\tiny.exe","product":"Microsoft (R) Windows (R) Operating System","imageLoaded":"C:\\\\Windows\\\\assembly\\\\NativeImages_v4.0.30319_64\\\\System.Manaa57fc8cc#\\\\b9fb242f469332d0a2e43fbb5bed25bd\\\\System.Management.Automation.ni.dll","description":"System.Management.Automation","signed":"false","signatureStatus":"Unavailable","processGuid":"{86107A5D-D195-60DC-0B08-B60000000000}","processId":"8436","utcTime":"2021-06-30 20:19:04.450","hashes":"SHA1=6B7D60621FB17C0DE264109E1404AC9D1FD52AB3,MD5=67CFC833A98E43C452388F918FB7E4C1,SHA256=71DACD5ECFFE84A09F38C927F5C7561594391E3DD7DD9DF962BEC7F120F34186,IMPHASH=00000000000000000000000000000000","ruleName":"technique_id=T1059.001,technique_name=PowerShell","company":"Microsoft Corporation","fileVersion":"10.0.14393.693"},"system":{"eventID":"7","keywords":"0x8000000000000000","providerGuid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Image loaded:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2021-06-30 20:19:04.450\r\nProcessGuid: {86107A5D-D195-60DC-0B08-B60000000000}\r\nProcessId: 8436\r\nImage: C:\\Windows\\tiny.exe\r\nImageLoaded: C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System.Manaa57fc8cc#\\b9fb242f469332d0a2e43fbb5bed25bd\\System.Management.Automation.ni.dll\r\nFileVersion: 10.0.14393.693\r\nDescription: System.Management.Automation\r\nProduct: Microsoft (R) Windows (R) Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: System.Management.Automation.dll\r\nHashes: SHA1=6B7D60621FB17C0DE264109E1404AC9D1FD52AB3,MD5=67CFC833A98E43C452388F918FB7E4C1,SHA256=71DACD5ECFFE84A09F38C927F5C7561594391E3DD7DD9DF962BEC7F120F34186,IMPHASH=00000000000000000000000000000000\r\nSigned: false\r\nSignature: -\r\nSignatureStatus: Unavailable\"","version":"3","systemTime":"2021-06-30T20:19:05.025071300Z","eventRecordID":"829139","threadID":"3700","computer":"bankdc.ExchangeTest.com","task":"7","processID":"2508","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92151')
        self.assertEqual(response.rule_level, 12)


    def test_printer_spooler_service_loads_a_dll_file(self) -> None:
        log = r'''
{"win":{"eventdata":{"originalFileName":"mimispool.dll","image":"C:\\\\Windows\\\\System32\\\\spoolsv.exe","product":"mimispool (mimikatz)","signature":"Open Source Developer, Benjamin Delpy","imageLoaded":"C:\\\\Windows\\\\System32\\\\spool\\\\drivers\\\\x64\\\\3\\\\mimispoolbis.dll","description":"mimispool for Windows (mimikatz)","signed":"true","signatureStatus":"Valid","processGuid":"{4dc16835-6534-60ec-92a4-010000000000}","processId":"1912","utcTime":"2021-07-12 15:58:13.023","hashes":"SHA1=BE9CB098C3331CC153E5E1BEA14B8D3B4D8CFD47,MD5=BB3DA838233101941460B5A8A85D326E,SHA256=C5CB049D25FAB0401C450F94A536898884681EE07C56B485BA4C6066B1DAE710,IMPHASH=D2007D8F257A5C5861BAB65684E7C6A3","ruleName":"technique_id=1210,technique_name=Exploitation of Remote Services","company":"gentilkiwi (Benjamin DELPY)","fileVersion":"0.3.0.0"},"system":{"eventID":"7","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Image loaded:\r\nRuleName: technique_id=1210,technique_name=Exploitation of Remote Services\r\nUtcTime: 2021-07-12 15:58:13.023\r\nProcessGuid: {4dc16835-6534-60ec-92a4-010000000000}\r\nProcessId: 1912\r\nImage: C:\\Windows\\System32\\spoolsv.exe\r\nImageLoaded: C:\\Windows\\System32\\spool\\drivers\\x64\\3\\mimispoolbis.dll\r\nFileVersion: 0.3.0.0\r\nDescription: mimispool for Windows (mimikatz)\r\nProduct: mimispool (mimikatz)\r\nCompany: gentilkiwi (Benjamin DELPY)\r\nOriginalFileName: mimispool.dll\r\nHashes: SHA1=BE9CB098C3331CC153E5E1BEA14B8D3B4D8CFD47,MD5=BB3DA838233101941460B5A8A85D326E,SHA256=C5CB049D25FAB0401C450F94A536898884681EE07C56B485BA4C6066B1DAE710,IMPHASH=D2007D8F257A5C5861BAB65684E7C6A3\r\nSigned: true\r\nSignature: Open Source Developer, Benjamin Delpy\r\nSignatureStatus: Valid\"","version":"3","systemTime":"2021-07-12T15:58:13.0304995Z","eventRecordID":"267563","threadID":"3552","computer":"hrmanager.ExchangeTest.com","task":"7","processID":"2092","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92152')
        self.assertEqual(response.rule_level, 6)


    def test_suspicious_process_loaded_vaultclidll_module(self) -> None:
        log = r'''
{"win":{"eventdata":{"originalFileName":"vaultcli.dll","image":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Local\\\\Temp\\\\infosMin48.exe","product":"Microsoft® Windows® Operating System","signature":"Microsoft Windows","imageLoaded":"C:\\\\Windows\\\\System32\\\\vaultcli.dll","description":"Credential Vault Client Library","signed":"true","signatureStatus":"Valid","processGuid":"{4dc16835-24d1-60f7-4001-000000005000}","processId":"5700","utcTime":"2021-07-20 19:32:33.428","hashes":"SHA1=0EA18B2789A85C20803DA84831B53A6236728FFF,MD5=C1D3933110B46BED9F4977BC5FADF607,SHA256=523EB270522AB2EC59CBE57B097A95FAB097E309FCE05B6F74A237BCC2463278,IMPHASH=D74C340A21D3A0792E913BA12F081859","ruleName":"technique_id=T1555,technique_name=Credentials from Password Stores","company":"Microsoft Corporation","fileVersion":"10.0.19041.746 (WinBuild.160101.0800)"},"system":{"eventID":"7","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Image loaded:\r\nRuleName: technique_id=T1555,technique_name=Credentials from Password Stores\r\nUtcTime: 2021-07-20 19:32:33.428\r\nProcessGuid: {4dc16835-24d1-60f7-4001-000000005000}\r\nProcessId: 5700\r\nImage: C:\\Users\\AtomicRed\\AppData\\Local\\Temp\\infosMin48.exe\r\nImageLoaded: C:\\Windows\\System32\\vaultcli.dll\r\nFileVersion: 10.0.19041.746 (WinBuild.160101.0800)\r\nDescription: Credential Vault Client Library\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: vaultcli.dll\r\nHashes: SHA1=0EA18B2789A85C20803DA84831B53A6236728FFF,MD5=C1D3933110B46BED9F4977BC5FADF607,SHA256=523EB270522AB2EC59CBE57B097A95FAB097E309FCE05B6F74A237BCC2463278,IMPHASH=D74C340A21D3A0792E913BA12F081859\r\nSigned: true\r\nSignature: Microsoft Windows\r\nSignatureStatus: Valid\"","version":"3","systemTime":"2021-07-20T19:32:33.4755381Z","eventRecordID":"279054","threadID":"3248","computer":"hrmanager.ExchangeTest.com","task":"7","processID":"2392","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92153')
        self.assertEqual(response.rule_level, 10)


    def test_mshta_process_loaded_taskschddll_module(self) -> None:
        log = r'''
{"win":{"eventdata":{"originalFileName":"taskschd.dll","image":"C:\\\\Windows\\\\SysWOW64\\\\mshta.exe","product":"Microsoft® Windows® Operating System","signature":"Microsoft Windows","imageLoaded":"C:\\\\Windows\\\\SysWOW64\\\\taskschd.dll","description":"Task Scheduler COM API","signed":"true","signatureStatus":"Valid","processGuid":"{4dc16835-8cdf-614b-90f6-cf0000000000}","processId":"7736","utcTime":"2021-09-22 20:06:57.547","hashes":"SHA1=7DEE697ABA99177E43C0AE1F5E5E0C4AE53CD5F5,MD5=ED7A3151F0AC41ADEEF11700B653CBB2,SHA256=F18EB1CBA18AC1DF339C9DF4AEC95B8302DF99A6BD20439E514E5BB4D7610080,IMPHASH=59BF7D0FAD0B5B7F706EA9250167BD5B","ruleName":"technique_id=T1053,technique_name=Scheduled Task","company":"Microsoft Corporation","fileVersion":"10.0.19041.1202 (WinBuild.160101.0800)"},"system":{"eventID":"7","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Image loaded:\r\nRuleName: technique_id=T1053,technique_name=Scheduled Task\r\nUtcTime: 2021-09-22 20:06:57.547\r\nProcessGuid: {4dc16835-8cdf-614b-90f6-cf0000000000}\r\nProcessId: 7736\r\nImage: C:\\Windows\\SysWOW64\\mshta.exe\r\nImageLoaded: C:\\Windows\\SysWOW64\\taskschd.dll\r\nFileVersion: 10.0.19041.1202 (WinBuild.160101.0800)\r\nDescription: Task Scheduler COM API\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: taskschd.dll\r\nHashes: SHA1=7DEE697ABA99177E43C0AE1F5E5E0C4AE53CD5F5,MD5=ED7A3151F0AC41ADEEF11700B653CBB2,SHA256=F18EB1CBA18AC1DF339C9DF4AEC95B8302DF99A6BD20439E514E5BB4D7610080,IMPHASH=59BF7D0FAD0B5B7F706EA9250167BD5B\r\nSigned: true\r\nSignature: Microsoft Windows\r\nSignatureStatus: Valid\"","version":"3","systemTime":"2021-09-22T20:06:57.5512462Z","eventRecordID":"385283","threadID":"3560","computer":"hrmanager.ExchangeTest.com","task":"7","processID":"2736","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92155')
        self.assertEqual(response.rule_level, 12)


    def test_word_process_loaded_vbeuidll_module(self) -> None:
        log = r'''
{"win":{"eventdata":{"originalFileName":"VBEUI.DLL","image":"C:\\\\Program Files (x86)\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE","product":"Microsoft Visual Basic for Applications","signature":"Microsoft Corporation","imageLoaded":"C:\\\\Program Files (x86)\\\\Microsoft Office\\\\root\\\\vfs\\\\ProgramFilesCommonX86\\\\Microsoft Shared\\\\VBA\\\\VBA7.1\\\\VBEUI.DLL","description":"Microsoft Visual Basic for Applications component","signed":"true","signatureStatus":"Valid","processGuid":"{4dc16835-8cd1-614b-1585-cc0000000000}","processId":"8108","utcTime":"2021-09-22 20:06:57.355","hashes":"SHA1=B05EDB49CB26F5686C509245FF829CAD027A55DD,MD5=5E3A049D154D5E873B08716E42355ED3,SHA256=FDC4479EECFD7B15BA63FF89E4893CE3D53CB18DF0BB64A79D09B164C4111D87,IMPHASH=94335E873709DE292ED48CD97740EBDD","ruleName":"technique_id=T1059.005,technique_name=Command and Scripting Interpreter VBScript","company":"Microsoft Corporation","fileVersion":"7.1.16.14026"},"system":{"eventID":"7","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Image loaded:\r\nRuleName: technique_id=T1059.005,technique_name=Command and Scripting Interpreter VBScript\r\nUtcTime: 2021-09-22 20:06:57.355\r\nProcessGuid: {4dc16835-8cd1-614b-1585-cc0000000000}\r\nProcessId: 8108\r\nImage: C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE\r\nImageLoaded: C:\\Program Files (x86)\\Microsoft Office\\root\\vfs\\ProgramFilesCommonX86\\Microsoft Shared\\VBA\\VBA7.1\\VBEUI.DLL\r\nFileVersion: 7.1.16.14026\r\nDescription: Microsoft Visual Basic for Applications component\r\nProduct: Microsoft Visual Basic for Applications\r\nCompany: Microsoft Corporation\r\nOriginalFileName: VBEUI.DLL\r\nHashes: SHA1=B05EDB49CB26F5686C509245FF829CAD027A55DD,MD5=5E3A049D154D5E873B08716E42355ED3,SHA256=FDC4479EECFD7B15BA63FF89E4893CE3D53CB18DF0BB64A79D09B164C4111D87,IMPHASH=94335E873709DE292ED48CD97740EBDD\r\nSigned: true\r\nSignature: Microsoft Corporation\r\nSignatureStatus: Valid\"","version":"3","systemTime":"2021-09-22T20:06:57.3715694Z","eventRecordID":"385278","threadID":"3564","computer":"hrmanager.ExchangeTest.com","task":"7","processID":"2736","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92156')
        self.assertEqual(response.rule_level, 12)


    def test_executable_loaded_a_dll_from_temp_directory(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Users\\\\Public\\\\AccountingIQ.exe", "signatureStatus": "Unavailable", "processGuid": "{94f48244-782d-6169-8900-000000001b00}", "processId": "5372", "utcTime": "2021-10-15 12:46:41.400", "hashes": "SHA1=F1D67C1422C188A8CA889E979CE3C80F54973A2F,MD5=2405AC14520E5A5A5000A22A804320F3,SHA256=EFFA02347AAE8B9BB5002D0B400CCADCE6BB954349146C1F70E3DEF1DD684A9A,IMPHASH=BEEE3207913DDEFA6F0BCC6FBE061D04", "ruleName": "technique_id=T1073,technique_name=DLL Side-Loading", "imageLoaded": "C:\\\\Windows\\\\Temp\\\\dll329.dll", "signed": "false" }, "system": { "eventID": "7", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"Image loaded:\r\nRuleName: technique_id=T1073,technique_name=DLL Side-Loading\r\nUtcTime: 2021-10-15 12:46:41.400\r\nProcessGuid: {94f48244-782d-6169-8900-000000001b00}\r\nProcessId: 5372\r\nImage: C:\\Users\\Public\\AccountingIQ.exe\r\nImageLoaded: C:\\Windows\\Temp\\dll329.dll\r\nFileVersion: -\r\nDescription: -\r\nProduct: -\r\nCompany: -\r\nOriginalFileName: -\r\nHashes: SHA1=F1D67C1422C188A8CA889E979CE3C80F54973A2F,MD5=2405AC14520E5A5A5000A22A804320F3,SHA256=EFFA02347AAE8B9BB5002D0B400CCADCE6BB954349146C1F70E3DEF1DD684A9A,IMPHASH=BEEE3207913DDEFA6F0BCC6FBE061D04\r\nSigned: false\r\nSignature: -\r\nSignatureStatus: Unavailable\"", "version": "3", "systemTime": "2021-10-15T12:46:41.9405329Z", "eventRecordID": "55999", "threadID": "3592", "computer": "accounting.xrisbarney.local", "task": "7", "processID": "2192", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92157')
        self.assertEqual(response.rule_level, 6)

