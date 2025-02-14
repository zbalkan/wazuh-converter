import unittest

from internal.logtest import LogtestStatus, send_multiple_logs  # type: ignore


class TestTa0003PersistenceT1574HijackExecutionFlow(unittest.TestCase):

    def test_id150_failed_dll_loaded_by_dns_server(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-DNS-Server-Service", "providerGuid": "{71a551f5-c893-4849-886b-b5ec8502641e}", "eventID": "150", "version": "0", "level": "2", "task": "0", "opcode": "0", "keywords": "0x8000000000008000", "systemTime": "2021-05-18T21:18:40.6070185Z", "eventRecordID": "11645", "processID": "2320", "threadID": "3384", "channel": "DNS Server", "computer": "rootdc1.offsec.lan", "severityValue": "ERROR", "message": "Failed to get metadata for provider Microsoft-Windows-DNS-Server-Service)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-DNS-Server-Service", "providerGuid": "{71a551f5-c893-4849-886b-b5ec8502641e}", "eventID": "150", "version": "0", "level": "2", "task": "0", "opcode": "0", "keywords": "0x8000000000008000", "systemTime": "2021-05-18T21:23:27.0383058Z", "eventRecordID": "11659", "processID": "3880", "threadID": "444", "channel": "DNS Server", "computer": "rootdc1.offsec.lan", "severityValue": "ERROR", "message": "Failed to get metadata for provider Microsoft-Windows-DNS-Server-Service)"}, "eventdata": {}}}'''
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

    def test_id4688_dns_dll_serverlevelplugindll_command(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4688", "version": "2", "level": "0", "task": "13312", "opcode": "0", "keywords": "0x8020000000000000", "systemTime": "2021-05-18T21:30:17.3189877Z", "eventRecordID": "147796707", "processID": "4", "threadID": "6268", "channel": "Security", "computer": "rootdc1.offsec.lan", "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-4230534742-2542757381-3142984815-1111\n\tAccount Name:\t\tadmmig\n\tAccount Domain:\t\tOFFSEC\n\tLogon ID:\t\t0x907C7C09\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x1498\n\tNew Process Name:\tC:\\Windows\\System32\\dnscmd.exe\n\tToken Elevation Type:\t%%1937\n\tMandatory Label:\t\tS-1-16-12288\n\tCreator Process ID:\t0x114\n\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe\n\tProcess Command Line:\tdnscmd.exe  /config /serverlevelplugindll \"C:\\TOOLS\\Mimikatz-fev-2020\\mimilib.dll\"\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}, "eventdata": {"subjectUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111", "subjectUserName": "admmig", "subjectDomainName": "OFFSEC", "subjectLogonId": "0x907c7c09", "newProcessId": "0x1498", "newProcessName": "C:\\Windows\\System32\\dnscmd.exe", "tokenElevationType": "%%1937", "processId": "0x114", "commandLine": "dnscmd.exe  /config /serverlevelplugindll \"C:\\TOOLS\\Mimikatz-fev-2020\\mimilib.dll\"", "targetUserSid": "S-1-0-0", "targetLogonId": "0x0", "parentProcessName": "C:\\Windows\\System32\\cmd.exe", "mandatoryLabel": "S-1-16-12288"}}}'''
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

    def test_id770_success_dll_loaded_by_dns_server(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-DNS-Server-Service", "providerGuid": "{71a551f5-c893-4849-886b-b5ec8502641e}", "eventID": "771", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000008000", "systemTime": "2021-05-18T21:33:49.5480621Z", "eventRecordID": "11683", "processID": "180", "threadID": "4116", "channel": "DNS Server", "computer": "rootdc1.offsec.lan", "severityValue": "INFORMATION", "message": "Failed to get metadata for provider Microsoft-Windows-DNS-Server-Service)"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-DNS-Server-Service", "providerGuid": "{71a551f5-c893-4849-886b-b5ec8502641e}", "eventID": "770", "version": "0", "level": "4", "task": "0", "opcode": "0", "keywords": "0x8000000000008000", "systemTime": "2021-05-18T21:33:49.5480653Z", "eventRecordID": "11684", "processID": "180", "threadID": "4116", "channel": "DNS Server", "computer": "rootdc1.offsec.lan", "severityValue": "INFORMATION", "message": "Failed to get metadata for provider Microsoft-Windows-DNS-Server-Service)"}, "eventdata": {"param1": "C:\\TOOLS\\Mimikatz-fev-2020\\mimilib.dll", "param2": "rootdc1.offsec.lan"}}}'''
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

    def test_id800_4103_4104_print_spooler_privilege_escalation_cve_2020_1048(self) -> None:
        # Logs extracted from EVTX file
        logs = [
            r'''{"win": {"system": {"providerName": "PowerShell", "providerGuid": {"@Name": "PowerShell"}, "eventID": "800", "level": "4", "task": "8", "keywords": "0x80000000000000", "systemTime": "2021-06-03T17:42:33.374798900Z", "eventRecordID": "28431", "channel": "Windows PowerShell", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "Pipeline execution details for command line: \tDetailSequence=1\n\tDetailTotal=1\n\n\tSequenceNumber=441\n\n\tUserId=OFFSEC\\admmig\n\tHostName=ConsoleHost\n\tHostVersion=5.1.14393.3383\n\tHostId=d61c85aa-4638-43bc-ae77-c65b9a535602\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tEngineVersion=5.1.14393.3383\n\tRunspaceId=1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n\tPipelineId=87\n\tScriptName=\n\tCommandLine=. \n\nContext Information: \nCommandInvocation(Resolve-Path): \"Resolve-Path\"\nParameterBinding(Resolve-Path): name=\"ErrorAction\"; value=\"Ignore\"\nParameterBinding(Resolve-Path): name=\"WarningAction\"; value=\"Ignore\"\nParameterBinding(Resolve-Path): name=\"InformationAction\"; value=\"Ignore\"\nParameterBinding(Resolve-Path): name=\"Verbose\"; value=\"False\"\nParameterBinding(Resolve-Path): name=\"Debug\"; value=\"False\"\nParameterBinding(Resolve-Path): name=\"Path\"; value=\"Net*\"\n \n\nDetails: \n%3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-PowerShell", "providerGuid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", "eventID": "4103", "version": "1", "level": "4", "task": "106", "opcode": "20", "keywords": "0x0", "systemTime": "2021-06-03T17:42:33.379251900Z", "eventRecordID": "29663", "processID": "5200", "threadID": "4232", "channel": "Microsoft-Windows-PowerShell/Operational", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "%3\n\nContext:\n%1\n\nUser Data:\n%2"}, "eventdata": {"contextInfo": "Severity = Informational\n        Host Name = ConsoleHost\n        Host Version = 5.1.14393.3383\n        Host ID = d61c85aa-4638-43bc-ae77-c65b9a535602\n        Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n        Engine Version = 5.1.14393.3383\n        Runspace ID = 1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n        Pipeline ID = 87\n        Command Name = Resolve-Path\n        Command Type = Cmdlet\n        Script Name = \n        Command Path = \n        Sequence Number = 442\n        User = OFFSEC\\admmig\n        Connected User = \n        Shell ID = Microsoft.PowerShell", "payload": "CommandInvocation(Resolve-Path): \"Resolve-Path\"\nParameterBinding(Resolve-Path): name=\"ErrorAction\"; value=\"Ignore\"\nParameterBinding(Resolve-Path): name=\"WarningAction\"; value=\"Ignore\"\nParameterBinding(Resolve-Path): name=\"InformationAction\"; value=\"Ignore\"\nParameterBinding(Resolve-Path): name=\"Verbose\"; value=\"False\"\nParameterBinding(Resolve-Path): name=\"Debug\"; value=\"False\"\nParameterBinding(Resolve-Path): name=\"Path\"; value=\"Net*\""}}}''',
            r'''{"win": {"system": {"providerName": "PowerShell", "providerGuid": {"@Name": "PowerShell"}, "eventID": "800", "level": "4", "task": "8", "keywords": "0x80000000000000", "systemTime": "2021-06-03T17:42:35.912051800Z", "eventRecordID": "28432", "channel": "Windows PowerShell", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "Pipeline execution details for command line: \tDetailSequence=1\n\tDetailTotal=1\n\n\tSequenceNumber=443\n\n\tUserId=OFFSEC\\admmig\n\tHostName=ConsoleHost\n\tHostVersion=5.1.14393.3383\n\tHostId=d61c85aa-4638-43bc-ae77-c65b9a535602\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tEngineVersion=5.1.14393.3383\n\tRunspaceId=1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n\tPipelineId=85\n\tScriptName=\n\tCommandLine=. \n\nContext Information: \nCommandInvocation(PSConsoleHostReadline): \"PSConsoleHostReadline\"\n \n\nDetails: \n%3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "PowerShell", "providerGuid": {"@Name": "PowerShell"}, "eventID": "800", "level": "4", "task": "8", "keywords": "0x80000000000000", "systemTime": "2021-06-03T17:42:35.927684700Z", "eventRecordID": "28433", "channel": "Windows PowerShell", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "Pipeline execution details for command line: Add-PrinterPort -Name .\\NetshHelperBeacon.dll. \n\nContext Information: \n\tDetailSequence=1\n\tDetailTotal=1\n\n\tSequenceNumber=445\n\n\tUserId=OFFSEC\\admmig\n\tHostName=ConsoleHost\n\tHostVersion=5.1.14393.3383\n\tHostId=d61c85aa-4638-43bc-ae77-c65b9a535602\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tEngineVersion=5.1.14393.3383\n\tRunspaceId=1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n\tPipelineId=88\n\tScriptName=\n\tCommandLine=Add-PrinterPort -Name .\\NetshHelperBeacon.dll \n\nDetails: \nCommandInvocation(Add-PrinterPort): \"Add-PrinterPort\"\nParameterBinding(Add-PrinterPort): name=\"Name\"; value=\".\\NetshHelperBeacon.dll\"\nParameterBinding(Add-PrinterPort): name=\"ComputerName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"HostName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"PrinterName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"PrinterHostAddress\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"PortNumber\"; value=\"0\"\nParameterBinding(Add-PrinterPort): name=\"SNMP\"; value=\"0\"\nParameterBinding(Add-PrinterPort): name=\"SNMPCommunity\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"LprHostAddress\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"LprQueueName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"LprByteCounting\"; value=\"False\"\nParameterBinding(Add-PrinterPort): name=\"ThrottleLimit\"; value=\"0\"\nParameterBinding(Add-PrinterPort): name=\"AsJob\"; value=\"False\""}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "PowerShell", "providerGuid": {"@Name": "PowerShell"}, "eventID": "800", "level": "4", "task": "8", "keywords": "0x80000000000000", "systemTime": "2021-06-03T17:42:35.927684700Z", "eventRecordID": "28434", "channel": "Windows PowerShell", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "Pipeline execution details for command line: \tDetailSequence=1\n\tDetailTotal=1\n\n\tSequenceNumber=447\n\n\tUserId=OFFSEC\\admmig\n\tHostName=ConsoleHost\n\tHostVersion=5.1.14393.3383\n\tHostId=d61c85aa-4638-43bc-ae77-c65b9a535602\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tEngineVersion=5.1.14393.3383\n\tRunspaceId=1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n\tPipelineId=88\n\tScriptName=\n\tCommandLine=. \n\nContext Information: \nCommandInvocation(Out-Default): \"Out-Default\"\n \n\nDetails: \n%3"}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "PowerShell", "providerGuid": {"@Name": "PowerShell"}, "eventID": "800", "level": "4", "task": "8", "keywords": "0x80000000000000", "systemTime": "2021-06-03T17:42:35.927684700Z", "eventRecordID": "28435", "channel": "Windows PowerShell", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "Pipeline execution details for command line:     Microsoft.PowerShell.Core\\Set-StrictMode -Off\n. \n\nContext Information: \n\tDetailSequence=1\n\tDetailTotal=1\n\n\tSequenceNumber=449\n\n\tUserId=OFFSEC\\admmig\n\tHostName=ConsoleHost\n\tHostVersion=5.1.14393.3383\n\tHostId=d61c85aa-4638-43bc-ae77-c65b9a535602\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tEngineVersion=5.1.14393.3383\n\tRunspaceId=1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n\tPipelineId=90\n\tScriptName=C:\\Program Files\\WindowsPowerShell\\Modules\\PSReadline\\1.2\\PSReadLine.psm1\n\tCommandLine=    Microsoft.PowerShell.Core\\Set-StrictMode -Off\n \n\nDetails: \nCommandInvocation(Set-StrictMode): \"Set-StrictMode\"\nParameterBinding(Set-StrictMode): name=\"Off\"; value=\"True\""}, "eventdata": {}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-PowerShell", "providerGuid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", "eventID": "4103", "version": "1", "level": "4", "task": "106", "opcode": "20", "keywords": "0x0", "systemTime": "2021-06-03T17:42:35.914139900Z", "eventRecordID": "29664", "processID": "5200", "threadID": "4232", "channel": "Microsoft-Windows-PowerShell/Operational", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "%3\n\nContext:\n%1\n\nUser Data:\n%2"}, "eventdata": {"contextInfo": "Severity = Informational\n        Host Name = ConsoleHost\n        Host Version = 5.1.14393.3383\n        Host ID = d61c85aa-4638-43bc-ae77-c65b9a535602\n        Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n        Engine Version = 5.1.14393.3383\n        Runspace ID = 1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n        Pipeline ID = 85\n        Command Name = PSConsoleHostReadline\n        Command Type = Function\n        Script Name = \n        Command Path = \n        Sequence Number = 444\n        User = OFFSEC\\admmig\n        Connected User = \n        Shell ID = Microsoft.PowerShell", "payload": "CommandInvocation(PSConsoleHostReadline): \"PSConsoleHostReadline\""}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-PowerShell", "providerGuid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", "eventID": "4104", "version": "1", "level": "5", "task": "2", "opcode": "15", "keywords": "0x0", "systemTime": "2021-06-03T17:42:35.915055600Z", "eventRecordID": "29665", "processID": "5200", "threadID": "4232", "channel": "Microsoft-Windows-PowerShell/Operational", "computer": "fs01.offsec.lan", "severityValue": "VERBOSE", "message": "Creating Scriptblock text (1 of 1):\nAdd-PrinterPort -Name .\\NetshHelperBeacon.dll\n\nScriptBlock ID: 39ff8bd8-c01d-48b1-ae29-ff16e71de49f\nPath: %5"}, "eventdata": {"messageNumber": "1", "messageTotal": "1", "scriptBlockText": "Add-PrinterPort -Name .\\NetshHelperBeacon.dll", "scriptBlockId": "39ff8bd8-c01d-48b1-ae29-ff16e71de49f"}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-PowerShell", "providerGuid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", "eventID": "4103", "version": "1", "level": "4", "task": "106", "opcode": "20", "keywords": "0x0", "systemTime": "2021-06-03T17:42:35.939298300Z", "eventRecordID": "29666", "processID": "5200", "threadID": "4232", "channel": "Microsoft-Windows-PowerShell/Operational", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "%3\n\nContext:\n%1\n\nUser Data:\n%2"}, "eventdata": {"contextInfo": "Severity = Informational\n        Host Name = ConsoleHost\n        Host Version = 5.1.14393.3383\n        Host ID = d61c85aa-4638-43bc-ae77-c65b9a535602\n        Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n        Engine Version = 5.1.14393.3383\n        Runspace ID = 1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n        Pipeline ID = 88\n        Command Name = Add-PrinterPort\n        Command Type = Function\n        Script Name = \n        Command Path = \n        Sequence Number = 446\n        User = OFFSEC\\admmig\n        Connected User = \n        Shell ID = Microsoft.PowerShell", "payload": "CommandInvocation(Add-PrinterPort): \"Add-PrinterPort\"\nParameterBinding(Add-PrinterPort): name=\"Name\"; value=\".\\NetshHelperBeacon.dll\"\nParameterBinding(Add-PrinterPort): name=\"ComputerName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"HostName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"PrinterName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"PrinterHostAddress\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"PortNumber\"; value=\"0\"\nParameterBinding(Add-PrinterPort): name=\"SNMP\"; value=\"0\"\nParameterBinding(Add-PrinterPort): name=\"SNMPCommunity\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"LprHostAddress\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"LprQueueName\"; value=\"\"\nParameterBinding(Add-PrinterPort): name=\"LprByteCounting\"; value=\"False\"\nParameterBinding(Add-PrinterPort): name=\"ThrottleLimit\"; value=\"0\"\nParameterBinding(Add-PrinterPort): name=\"AsJob\"; value=\"False\""}}}''',
            r'''{"win": {"system": {"providerName": "Microsoft-Windows-PowerShell", "providerGuid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", "eventID": "4103", "version": "1", "level": "4", "task": "106", "opcode": "20", "keywords": "0x0", "systemTime": "2021-06-03T17:42:35.939518700Z", "eventRecordID": "29667", "processID": "5200", "threadID": "4232", "channel": "Microsoft-Windows-PowerShell/Operational", "computer": "fs01.offsec.lan", "severityValue": "INFORMATION", "message": "%3\n\nContext:\n%1\n\nUser Data:\n%2"}, "eventdata": {"contextInfo": "Severity = Informational\n        Host Name = ConsoleHost\n        Host Version = 5.1.14393.3383\n        Host ID = d61c85aa-4638-43bc-ae77-c65b9a535602\n        Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n        Engine Version = 5.1.14393.3383\n        Runspace ID = 1b55a157-a0b9-4e11-bc7a-f1d86023a61c\n        Pipeline ID = 88\n        Command Name = \n        Command Type = Script\n        Script Name = \n        Command Path = \n        Sequence Number = 448\n        User = OFFSEC\\admmig\n        Connected User = \n        Shell ID = Microsoft.PowerShell", "payload": "CommandInvocation(Out-Default): \"Out-Default\""}}}'''
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
