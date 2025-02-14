import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0003PersistenceT1505ServerSoftwareComponent(unittest.TestCase):

    def test_id11_exchange_transport_config_modified(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "eventID": "11", "version": "2", "level": "4", "task": "11", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2021-06-04T09:30:48.1705788Z", "eventRecordID": "98", "processID": "1680", "threadID": "6620", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "exchange01.offsec.lan", "severityValue": "INFORMATION", "message": "File created:\nRuleName: -\nUtcTime: 2021-06-04 09:30:48.170\nProcessGuid: {6d3c60fe-f13d-60b9-22e2-010000001d00}\nProcessId: 19108\nImage: C:\\Program Files (x86)\\Notepad++\\notepad++.exe\nTargetFilename: E:\\Exchange2016\\TransportRoles\\Shared\\agents.config\nCreationUtcTime: 2021-01-21 10:20:36.244\nUser: %8"}, "eventdata": {"utcTime": "2021-06-04 09:30:48.170", "processGuid": "{6d3c60fe-f13d-60b9-22e2-010000001d00}", "processId": "19108", "image": "C:\\Program Files (x86)\\Notepad++\\notepad++.exe", "targetFilename": "E:\\Exchange2016\\TransportRoles\\Shared\\agents.config", "creationUtcTime": "2021-01-21 10:20:36.244"}}}'''
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

    def test_id6_failed_to_install_an_exchange_transport_agent(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "MSExchange CmdletLogs", "providerGuid": {"@Name": "MSExchange CmdletLogs"}, "eventID": "6", "level": "2", "task": "1", "keywords": "0x80000000000000", "systemTime": "2021-06-04T08:41:47.9821281Z", "eventRecordID": "7184", "channel": "MSExchange Management", "computer": "exchange01.offsec.lan", "severityValue": "ERROR", "message": "Failed to get metadata for provider MSExchange CmdletLogs)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "MSExchange CmdletLogs", "providerGuid": {"@Name": "MSExchange CmdletLogs"}, "eventID": "6", "level": "2", "task": "1", "keywords": "0x80000000000000", "systemTime": "2021-06-04T08:41:48.0411363Z", "eventRecordID": "7185", "channel": "MSExchange Management", "computer": "exchange01.offsec.lan", "severityValue": "ERROR", "message": "Failed to get metadata for provider MSExchange CmdletLogs)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "MSExchange CmdletLogs", "providerGuid": {"@Name": "MSExchange CmdletLogs"}, "eventID": "6", "level": "2", "task": "1", "keywords": "0x80000000000000", "systemTime": "2021-06-04T08:43:08.4765853Z", "eventRecordID": "7186", "channel": "MSExchange Management", "computer": "exchange01.offsec.lan", "severityValue": "ERROR", "message": "Failed to get metadata for provider MSExchange CmdletLogs)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "MSExchange CmdletLogs", "providerGuid": {"@Name": "MSExchange CmdletLogs"}, "eventID": "6", "level": "2", "task": "1", "keywords": "0x80000000000000", "systemTime": "2021-06-04T08:43:08.5465892Z", "eventRecordID": "7187", "channel": "MSExchange Management", "computer": "exchange01.offsec.lan", "severityValue": "ERROR", "message": "Failed to get metadata for provider MSExchange CmdletLogs)"}, "eventdata": {}}}'''
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
