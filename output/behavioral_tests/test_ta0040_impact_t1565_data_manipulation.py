import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0040ImpactT1565DataManipulation(unittest.TestCase):

    def test_id11_dns_hosts_files_modified(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "eventID": "11", "version": "2", "level": "4", "task": "11", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2021-12-12T12:01:18.8967708Z", "eventRecordID": "50530", "processID": "1048", "threadID": "1684", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "fs03vuln.offsec.lan", "severityValue": "INFORMATION", "message": "File created:\nRuleName: -\nUtcTime: 2021-12-12 12:01:18.896\nProcessGuid: {a57649d1-e44f-61b5-d88f-850800000000}\nProcessId: 2592\nImage: C:\\Program Files (x86)\\Notepad++\\notepad++.exe\nTargetFilename: C:\\Windows\\System32\\drivers\\etc\\hosts\nCreationUtcTime: 2013-08-22 13:25:43.270\nUser: %8"}, "eventdata": {"utcTime": "2021-12-12 12:01:18.896", "processGuid": "{a57649d1-e44f-61b5-d88f-850800000000}", "processId": "2592", "image": "C:\\Program Files (x86)\\Notepad++\\notepad++.exe", "targetFilename": "C:\\Windows\\System32\\drivers\\etc\\hosts", "creationUtcTime": "2013-08-22 13:25:43.270"}}}'''
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
