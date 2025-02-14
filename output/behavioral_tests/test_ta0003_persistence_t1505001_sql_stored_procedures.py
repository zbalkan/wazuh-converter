import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0003PersistenceT1505001SqlStoredProcedures(unittest.TestCase):

    def test_id11715_sql_server_started_in_single_mode_for_psw_recovery(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "MSSQL$RADAR", "providerGuid": {"@Name": "MSSQL$RADAR"}, "eventID": "17115", "level": "4", "task": "2", "keywords": "0x80000000000000", "systemTime": "2021-02-03T15:18:22.2602859Z", "eventRecordID": "125735", "channel": "Application", "computer": "mssql01.offsec.lan", "severityValue": "INFORMATION", "message": "Failed to get metadata for provider MSSQL$RADAR)"}, "eventdata": {}}}'''
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

    def test_id15457_sql_server_clr_lateral_movement(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "MSSQL$RADAR", "providerGuid": {"@Name": "MSSQL$RADAR"}, "eventID": "15457", "level": "4", "task": "2", "keywords": "0x80000000000000", "systemTime": "2021-04-13T21:56:36.1888803Z", "eventRecordID": "150985", "channel": "Application", "computer": "mssql01.offsec.lan", "severityValue": "INFORMATION", "message": "Failed to get metadata for provider MSSQL$RADAR)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "MSSQL$RADAR", "providerGuid": {"@Name": "MSSQL$RADAR"}, "eventID": "15457", "level": "4", "task": "2", "keywords": "0x80000000000000", "systemTime": "2021-04-13T21:56:47.2646891Z", "eventRecordID": "151004", "channel": "Application", "computer": "mssql01.offsec.lan", "severityValue": "INFORMATION", "message": "Failed to get metadata for provider MSSQL$RADAR)"}, "eventdata": {}}}'''
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

    def test_id15457_sql_server_cmdshell_enabled(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "MSSQL$RADAR", "providerGuid": {"@Name": "MSSQL$RADAR"}, "eventID": "15457", "level": "4", "task": "2", "keywords": "0x80000000000000", "systemTime": "2020-08-01T21:32:10.5982911Z", "eventRecordID": "70665", "channel": "Application", "computer": "mssql01.offsec.lan", "severityValue": "INFORMATION", "message": "Failed to get metadata for provider MSSQL$RADAR)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "MSSQL$RADAR", "providerGuid": {"@Name": "MSSQL$RADAR"}, "eventID": "33205", "level": "0", "task": "5", "keywords": "0xa0000000000000", "systemTime": "2020-08-01T21:32:13.3583347Z", "eventRecordID": "70666", "channel": "Application", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "Failed to get metadata for provider MSSQL$RADAR)"}, "eventdata": {}}}'''
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

    def test_id4688_sql_server_started_in_single_mode_for_psw_recovery(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4688", "version": "2", "level": "0", "task": "13312", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2021-02-03T15:17:15.9013789Z", "eventRecordID": "1617146", "processID": "4", "threadID": "164", "channel": "Security", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-4230534742-2542757381-3142984815-1111\n\tAccount Name:\t\tadmmig\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x372A4\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0xc70\n\tNew Process Name:\tC:\\Windows\\System32\\net.exe\n\tToken Elevation Type:\t%%1937\n\tMandatory Label:\t\tS-1-16-12288\n\tCreator Process ID:\t0x14c4\n\tCreator Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tProcess Command Line:\t\"C:\\Windows\\system32\\net.exe\" start MSSQL$RADAR /m\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}, "eventdata": {"subjectUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111", "subjectUserName": "admmig", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x372a4", "newProcessId": "0xc70", "newProcessName": "C:\\Windows\\System32\\net.exe", "tokenElevationType": "%%1937", "processId": "0x14c4", "commandLine": "\"C:\\Windows\\system32\\net.exe\" start MSSQL$RADAR /m", "targetUserSid": "S-1-0-0", "targetLogonId": "0x0", "parentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "mandatoryLabel": "S-1-16-12288"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4688", "version": "2", "level": "0", "task": "13312", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2021-02-03T15:17:15.9074699Z", "eventRecordID": "1617147", "processID": "4", "threadID": "164", "channel": "Security", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-4230534742-2542757381-3142984815-1111\n\tAccount Name:\t\tadmmig\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x372A4\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0xe48\n\tNew Process Name:\tC:\\Windows\\System32\\net1.exe\n\tToken Elevation Type:\t%%1937\n\tMandatory Label:\t\tS-1-16-12288\n\tCreator Process ID:\t0xc70\n\tCreator Process Name:\tC:\\Windows\\System32\\net.exe\n\tProcess Command Line:\tC:\\Windows\\system32\\net1 start MSSQL$RADAR /m\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}, "eventdata": {"subjectUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111", "subjectUserName": "admmig", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x372a4", "newProcessId": "0xe48", "newProcessName": "C:\\Windows\\System32\\net1.exe", "tokenElevationType": "%%1937", "processId": "0xc70", "commandLine": "C:\\Windows\\system32\\net1 start MSSQL$RADAR /m", "targetUserSid": "S-1-0-0", "targetLogonId": "0x0", "parentProcessName": "C:\\Windows\\System32\\net.exe", "mandatoryLabel": "S-1-16-12288"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4688", "version": "2", "level": "0", "task": "13312", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2021-02-03T15:17:16.0854450Z", "eventRecordID": "1617154", "processID": "4", "threadID": "164", "channel": "Security", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tMSSQL01$\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x3E7\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x13d8\n\tNew Process Name:\tC:\\Windows\\System32\\dllhost.exe\n\tToken Elevation Type:\t%%1936\n\tMandatory Label:\t\tS-1-16-16384\n\tCreator Process ID:\t0x298\n\tCreator Process Name:\tC:\\Windows\\System32\\svchost.exe\n\tProcess Command Line:\tC:\\Windows\\system32\\DllHost.exe /Processid:{E10F6C3A-F1AE-4ADC-AA9D-2FE65525666E}\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}, "eventdata": {"subjectUserSid": "S-1-5-18", "subjectUserName": "MSSQL01$", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x3e7", "newProcessId": "0x13d8", "newProcessName": "C:\\Windows\\System32\\dllhost.exe", "tokenElevationType": "%%1936", "processId": "0x298", "commandLine": "C:\\Windows\\system32\\DllHost.exe /Processid:{E10F6C3A-F1AE-4ADC-AA9D-2FE65525666E}", "targetUserSid": "S-1-0-0", "targetLogonId": "0x0", "parentProcessName": "C:\\Windows\\System32\\svchost.exe", "mandatoryLabel": "S-1-16-16384"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4688", "version": "2", "level": "0", "task": "13312", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2021-02-03T15:17:16.0996648Z", "eventRecordID": "1617155", "processID": "4", "threadID": "164", "channel": "Security", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tMSSQL01$\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x3E7\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tSvc-SQL-DB01\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x16C3E0\n\nProcess Information:\n\tNew Process ID:\t\t0xb10\n\tNew Process Name:\tC:\\Program Files\\Microsoft SQL Server\\MSSQL12.RADAR\\MSSQL\\Binn\\sqlservr.exe\n\tToken Elevation Type:\t%%1936\n\tMandatory Label:\t\tS-1-16-12288\n\tCreator Process ID:\t0x238\n\tCreator Process Name:\tC:\\Windows\\System32\\services.exe\n\tProcess Command Line:\t\"C:\\Program Files\\Microsoft SQL Server\\MSSQL12.RADAR\\MSSQL\\Binn\\sqlservr.exe\" -sRADAR\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}, "eventdata": {"subjectUserSid": "S-1-5-18", "subjectUserName": "MSSQL01$", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x3e7", "newProcessId": "0xb10", "newProcessName": "C:\\Program Files\\Microsoft SQL Server\\MSSQL12.RADAR\\MSSQL\\Binn\\sqlservr.exe", "tokenElevationType": "%%1936", "processId": "0x238", "commandLine": "\"C:\\Program Files\\Microsoft SQL Server\\MSSQL12.RADAR\\MSSQL\\Binn\\sqlservr.exe\" -sRADAR", "targetUserSid": "S-1-0-0", "targetUserName": "Svc-SQL-DB01", "targetDomainName": "OFFSEC", "targetLogonId": "0x16c3e0", "parentProcessName": "C:\\Windows\\System32\\services.exe", "mandatoryLabel": "S-1-16-12288"}}}'''
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

    def test_id4688_sqlcmd_tool_abuse_in_sql_server(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4688", "version": "2", "level": "0", "task": "13312", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2021-02-03T15:33:16.1076519Z", "eventRecordID": "1617340", "processID": "4", "threadID": "1168", "channel": "Security", "computer": "mssql01.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-4230534742-2542757381-3142984815-1111\n\tAccount Name:\t\tadmmig\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x372A4\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x1204\n\tNew Process Name:\tC:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\110\\Tools\\Binn\\SQLCMD.EXE\n\tToken Elevation Type:\t%%1937\n\tMandatory Label:\t\tS-1-16-12288\n\tCreator Process ID:\t0x9e4\n\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe\n\tProcess Command Line:\tsqlcmd  -S .\\RADAR,2020\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}, "eventdata": {"subjectUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111", "subjectUserName": "admmig", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x372a4", "newProcessId": "0x1204", "newProcessName": "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\110\\Tools\\Binn\\SQLCMD.EXE", "tokenElevationType": "%%1937", "processId": "0x9e4", "commandLine": "sqlcmd  -S .\\RADAR,2020", "targetUserSid": "S-1-0-0", "targetLogonId": "0x0", "parentProcessName": "C:\\Windows\\System32\\cmd.exe", "mandatoryLabel": "S-1-16-12288"}}}'''
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
