import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0009CollectionT1125VideoCapture(unittest.TestCase):

    def test_id13_rdp_shadow_session_configuration_enabled_registry(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "eventID": "12", "version": "2", "level": "4", "task": "12", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2021-12-17T22:44:18.4754285Z", "eventRecordID": "598393", "processID": "1160", "threadID": "1856", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "FS03.offsec.lan", "severityValue": "INFORMATION", "message": "Registry object added or deleted:\nRuleName: technique_id=T1076,technique_name=Remote Desktop Protocol\nEventType: CreateKey\nUtcTime: 2021-12-17 22:44:18.475\nProcessGuid: {7cf65fc7-12c2-61bd-ea04-000000001400}\nProcessId: 2848\nImage: C:\\Windows\\system32\\reg.exe\nTargetObject: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\nUser: %8"}, "eventdata": {"ruleName": "technique_id=T1076,technique_name=Remote Desktop Protocol", "eventType": "CreateKey", "utcTime": "2021-12-17 22:44:18.475", "processGuid": "{7cf65fc7-12c2-61bd-ea04-000000001400}", "processId": "2848", "image": "C:\\Windows\\system32\\reg.exe", "targetObject": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"}}}'''
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
