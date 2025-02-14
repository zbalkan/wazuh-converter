import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0006CredentialAccessT1552004UnsecuredCredentialsPrivateKeys(unittest.TestCase):

    def test_id70_capi_private_key_accessed_mimikatz(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-CAPI2", "providerGuid": "{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}", "eventID": "70", "version": "0", "level": "4", "task": "70", "opcode": "0", "keywords": "0x4000000000000080", "systemTime": "2020-07-11T13:21:11.6931030Z", "eventRecordID": "13969076", "processID": "5708", "threadID": "5712", "channel": "Microsoft-Windows-CAPI2/Operational", "computer": "wec02", "severityValue": "INFORMATION", "message": "For more details for this event, please refer to the \"Details\" section"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-CAPI2", "providerGuid": "{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}", "eventID": "70", "version": "0", "level": "4", "task": "70", "opcode": "0", "keywords": "0x4000000000000080", "systemTime": "2020-07-11T13:21:17.5140762Z", "eventRecordID": "13969094", "processID": "5708", "threadID": "5712", "channel": "Microsoft-Windows-CAPI2/Operational", "computer": "wec02", "severityValue": "INFORMATION", "message": "For more details for this event, please refer to the \"Details\" section"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-CAPI2", "providerGuid": "{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}", "eventID": "70", "version": "0", "level": "4", "task": "70", "opcode": "0", "keywords": "0x4000000000000080", "systemTime": "2020-07-11T13:21:18.6409835Z", "eventRecordID": "13969096", "processID": "5708", "threadID": "5712", "channel": "Microsoft-Windows-CAPI2/Operational", "computer": "wec02", "severityValue": "INFORMATION", "message": "For more details for this event, please refer to the \"Details\" section"}, "eventdata": {}}}'''
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
