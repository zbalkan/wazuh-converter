import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0001InitialAccessT1078ValidAccounts(unittest.TestCase):

    def test_id1149_rdp_success_logins_to_multiple_hosts(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.351835800Z", "eventRecordID": "6433", "processID": "952", "threadID": "5672", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "rootdc1.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:30.415637900Z", "eventRecordID": "99456", "processID": "1788", "threadID": "2392", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "fs03vuln.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.594963600Z", "eventRecordID": "318", "processID": "1900", "threadID": "4088", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "FS03.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.367518000Z", "eventRecordID": "2858", "processID": "816", "threadID": "2208", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "mssql01.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.407320600Z", "eventRecordID": "6067", "processID": "812", "threadID": "6964", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "dhcp01.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.473120500Z", "eventRecordID": "1860", "processID": "876", "threadID": "3964", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "webiis01.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.782376000Z", "eventRecordID": "1813", "processID": "888", "threadID": "3956", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "prtg-mon.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.648199100Z", "eventRecordID": "6783", "processID": "996", "threadID": "13724", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "exchange01.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.794683900Z", "eventRecordID": "1831", "processID": "876", "threadID": "2700", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "pki01.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.726718800Z", "eventRecordID": "6126", "processID": "848", "threadID": "720", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "wsus01.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "providerGuid": "{C76BAA63-AE81-421C-B425-340B4B24157F}", "eventID": "1149", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x1000000000000000", "systemTime": "2021-12-16T10:25:32.673214500Z", "eventRecordID": "1801", "processID": "872", "threadID": "2432", "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "computer": "adfs01.offsec.lan", "severityValue": "INFORMATION", "message": "Remote Desktop Services: User authentication succeeded:\n\nUser: admmig\nDomain: 10.23.123.11\nSource Network Address: %3"}, "eventdata": {}}}'''
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

    def test_id33205_sql_server_failed_login_with_disabled_sa_account(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "MSSQL$RADAR", "providerGuid": {"@Name": "MSSQL$RADAR"}, "eventID": "33205", "level": "0", "task": "4", "keywords": "0x90000000000000", "systemTime": "2020-07-15T19:39:15.9758779Z", "eventRecordID": "58975", "channel": "Application", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_FAILURE", "message": "Failed to get metadata for provider MSSQL$RADAR)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "MSSQL$RADAR", "providerGuid": {"@Name": "MSSQL$RADAR"}, "eventID": "33205", "level": "0", "task": "4", "keywords": "0x90000000000000", "systemTime": "2020-07-15T19:39:36.0133233Z", "eventRecordID": "58977", "channel": "Application", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_FAILURE", "message": "Failed to get metadata for provider MSSQL$RADAR)"}, "eventdata": {}}}'''
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

    def test_id4625_failed_login_with_denied_access_due_to_account_restriction(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4625", "version": "0", "level": "0", "task": "12544", "opcode": "0", "keywords": "0x8010000000000000", "systemTime": "2021-10-23T21:50:11.6665197Z", "eventRecordID": "90907", "processID": "512", "threadID": "500", "channel": "Security", "computer": "FS03.offsec.lan", "severityValue": "AUDIT_FAILURE", "message": "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tFS03$\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x3E7\n\nLogon Type:\t\t\t10\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006E\n\tSub Status:\t\t0x0\n\nProcess Information:\n\tCaller Process ID:\t0x1310\n\tCaller Process Name:\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t10.23.23.9\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."}, "eventdata": {"subjectUserSid": "S-1-5-18", "subjectUserName": "FS03$", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x3e7", "targetUserSid": "S-1-0-0", "status": "0xc000006e", "failureReason": "%%2313", "subStatus": "0x0", "logonType": "10", "logonProcessName": "User32", "authenticationPackageName": "Negotiate", "keyLength": "0", "processId": "0x1310", "processName": "C:\\Windows\\System32\\winlogon.exe", "ipAddress": "10.23.23.9", "ipPort": "0"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4625", "version": "0", "level": "0", "task": "12544", "opcode": "0", "keywords": "0x8010000000000000", "systemTime": "2021-10-23T21:51:57.2125134Z", "eventRecordID": "90939", "processID": "512", "threadID": "2988", "channel": "Security", "computer": "FS03.offsec.lan", "severityValue": "AUDIT_FAILURE", "message": "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tFS03$\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x3E7\n\nLogon Type:\t\t\t10\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006E\n\tSub Status:\t\t0x0\n\nProcess Information:\n\tCaller Process ID:\t0xdb4\n\tCaller Process Name:\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t10.23.23.9\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."}, "eventdata": {"subjectUserSid": "S-1-5-18", "subjectUserName": "FS03$", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x3e7", "targetUserSid": "S-1-0-0", "status": "0xc000006e", "failureReason": "%%2313", "subStatus": "0x0", "logonType": "10", "logonProcessName": "User32", "authenticationPackageName": "Negotiate", "keyLength": "0", "processId": "0xdb4", "processName": "C:\\Windows\\System32\\winlogon.exe", "ipAddress": "10.23.23.9", "ipPort": "0"}}}'''
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
