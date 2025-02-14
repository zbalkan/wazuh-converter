import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0011CommandAndControlT1090Proxy(unittest.TestCase):

    def test_id5600_proxy_configuration_changed(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:22:34.8335166Z", "eventRecordID": "5", "processID": "1100", "threadID": "2220", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszProxy": "http://hacker-proxy.lan:123"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:22:34.8359851Z", "eventRecordID": "6", "processID": "1100", "threadID": "2220", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszProxy": "http://hacker-proxy.lan:123"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:24:15.2119054Z", "eventRecordID": "7", "processID": "1100", "threadID": "2220", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:24:36.0760082Z", "eventRecordID": "8", "processID": "1100", "threadID": "1244", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszAutoConfigUrl": "http://hacker-bypass.com/"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:24:41.5770445Z", "eventRecordID": "9", "processID": "1100", "threadID": "1244", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszAutoConfigUrl": "http://hacker-bypass.com/", "pwszProxy": "http://hacker-proxy.lan:123"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:24:41.5803444Z", "eventRecordID": "10", "processID": "1100", "threadID": "1244", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszAutoConfigUrl": "http://hacker-bypass.com/", "pwszProxy": "http://hacker-proxy.lan:123"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:24:56.3642876Z", "eventRecordID": "11", "processID": "1100", "threadID": "1808", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszAutoConfigUrl": "http://hacker-bypass.com/", "pwszProxy": "http://hacker-proxy.lan:123"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:24:56.3680739Z", "eventRecordID": "12", "processID": "1100", "threadID": "1808", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszAutoConfigUrl": "http://hacker-bypass.com/", "pwszProxy": "http://hacker-proxy.lan:123", "pwszProxyBypass": "<local>"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:25:12.2200531Z", "eventRecordID": "13", "processID": "1100", "threadID": "1240", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszAutoConfigUrl": "http://hacker-bypass.com/", "pwszProxy": "http://hacker-proxy.lan:123", "pwszProxyBypass": "<local>"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-WinINet-Config", "providerGuid": "{5402e5ea-1bdd-4390-82be-e108f1e634f5}", "eventID": "5600", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2023-04-14T08:25:12.2234708Z", "eventRecordID": "14", "processID": "1100", "threadID": "1808", "channel": "Microsoft-Windows-WinINet-Config/ProxyConfigChanged", "computer": "WIN", "severityValue": "INFORMATION", "message": "None"}, "eventdata": {"fAutoDetect": "false", "pwszAutoConfigUrl": "http://hacker-bypass.com/", "pwszProxy": "http://hacker-proxy.lan:123", "pwszProxyBypass": "http://internal.lan;<local>"}}}'''
        ]

        responses = send_multiple_logs(logs, location="stdin", log_format="json")

        # Ensure we receive a response for each log sent
        self.assertEqual(len(responses), len(logs))

        for _, response in enumerate(responses):
            self.assertEqual(response.status, LogtestStatus.RuleMatch)
            self.assertEqual(response.decoder, 'json')

            # Example: Set expected Wazuh rule ID and level when analyzing logs
            # expected_rule_id = None  # Replace with actual rule ID
            # expected_rule_level = None  # Replace with actual rule level

            # self.assertEqual(response.rule_id, expected_rule_id)
            # self.assertEqual(response.rule_level, expected_rule_level)

        # TODO: Write the expected result as test cases when the logs are analyzed by Wazuh.
        self.fail("Test not implemented yet. Define expected results.")
