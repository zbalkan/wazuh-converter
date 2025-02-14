import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0004PrivilegeEscalationT1134005AccessTokenManipulationSidHistoryInjection(unittest.TestCase):

    def test_id_4765_sid_history_added(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4765", "version": "0", "level": "0", "task": "13824", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2017-06-12T23:39:43.5129867Z", "eventRecordID": "8075", "processID": "496", "threadID": "1696", "channel": "Security", "computer": "2012r2srv.maincorp.local", "severityValue": "AUDIT_SUCCESS", "message": "SID History was added to an account.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-2634088540-571122920-1382659128-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tMAINCORP\n\tLogon ID:\t\t0x432C8\n\nTarget Account:\n\tSecurity ID:\t\tS-1-5-21-2634088540-571122920-1382659128-1104\n\tAccount Name:\t\tAndrei\n\tAccount Domain:\t\tMAINCORP\n\nSource Account:\n\tSecurity ID:\t\tS-1-5-21-2634088540-571122920-1382659128-512\n\tAccount Name:\t\tmaincorp.local\\Domain Admins\n\nAdditional Information:\n\tPrivileges:\t\t-\n\tSID List:\t\t\t-"}, "eventdata": {"sourceUserName": "maincorp.local\\Domain Admins", "sourceSid": "S-1-5-21-2634088540-571122920-1382659128-512", "targetUserName": "Andrei", "targetDomainName": "MAINCORP", "targetSid": "S-1-5-21-2634088540-571122920-1382659128-1104", "subjectUserSid": "S-1-5-21-2634088540-571122920-1382659128-500", "subjectUserName": "Administrator", "subjectDomainName": "MAINCORP", "subjectLogonId": "0x432c8"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4658", "version": "0", "level": "0", "task": "12804", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2017-06-12T23:39:43.5129867Z", "eventRecordID": "8076", "processID": "4", "threadID": "252", "channel": "Security", "computer": "2012r2srv.maincorp.local", "severityValue": "AUDIT_SUCCESS", "message": "The handle to an object was closed.\n\nSubject :\n\tSecurity ID:\t\tS-1-5-21-2634088540-571122920-1382659128-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tMAINCORP\n\tLogon ID:\t\t0x432C8\n\nObject:\n\tObject Server:\t\tSecurity Account Manager\n\tHandle ID:\t\t0xc9774b43b0\n\nProcess Information:\n\tProcess ID:\t\t0x1f0\n\tProcess Name:\t\tC:\\Windows\\System32\\lsass.exe"}, "eventdata": {"subjectUserSid": "S-1-5-21-2634088540-571122920-1382659128-500", "subjectUserName": "Administrator", "subjectDomainName": "MAINCORP", "subjectLogonId": "0x432c8", "objectServer": "Security Account Manager", "handleId": "0xc9774b43b0", "processId": "0x1f0", "processName": "C:\\Windows\\System32\\lsass.exe"}}}'''
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
