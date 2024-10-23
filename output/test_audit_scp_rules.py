#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from audit_scp.ini
class TestAuditScpRules(unittest.TestCase):

    def test_executed_python_script(self) -> None:
        log = r'''type=SYSCALL msg=audit(1624643172.076:11843): arch=c000003e syscall=59 success=yes exit=0 a0=25c81f0 a1=255f000 a2=255df40 a3=7ffc66d5c8e0 items=3 ppid=4353 pid=13331 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=pts0 ses=48 comm="runtime" exe="/usr/bin/python3.6" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="wazuh_execution"\u001DARCH=x86_64 SYSCALL=execve AUID="administrator@ExchangeTest.com" UID="administrator@ExchangeTest.com" GID=646F6D61696E2075736572734045786368616E6765546573742E636F6D EUID="administrator@ExchangeTest.com" SUID="administrator@ExchangeTest.com" FSUID="administrator@ExchangeTest.com" EGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D SGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D FSGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=EXECVE msg=audit(1624643172.076:11843): argc=6 a0="/usr/bin/python3" a1="./runtime" a2="psexec.py" a3="exchangetest.com/administrator@192.168.0.57"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '92600')
        self.assertEqual(response.rule_level, 0)


    def test_executed_python_script_from_tmp_folder_1(self) -> None:
        log = r'''type=SYSCALL msg=audit(1624643172.076:11843): arch=c000003e syscall=59 success=yes exit=0 a0=25c81f0 a1=255f000 a2=255df40 a3=7ffc66d5c8e0 items=3 ppid=4353 pid=13331 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=pts0 ses=48 comm="runtime" exe="/usr/bin/python3.6" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="wazuh_execution"\u001DARCH=x86_64 SYSCALL=execve AUID="administrator@ExchangeTest.com" UID="administrator@ExchangeTest.com" GID=646F6D61696E2075736572734045786368616E6765546573742E636F6D EUID="administrator@ExchangeTest.com" SUID="administrator@ExchangeTest.com" FSUID="administrator@ExchangeTest.com" EGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D SGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D FSGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=EXECVE msg=audit(1624643172.076:11843): argc=6 a0="/usr/bin/python3" a1="./runtime" a2="calc.py" a3="exchangetest.com/administrator@192.168.0.57" a4="-hashes" a5="c615d74f277acb732af4e8680330fcf1:c615d74f277acb732af4e8680330fcf1" type=CWD msg=audit(1624643172.076:11843):  cwd="/tmp" type=PATH msg=audit(1624643172.076:11843): item=0 name="./runtime" inode=8409155 dev=fd:00 mode=0100755 ouid=1198400500 ogid=1198400513 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="administrator@ExchangeTest.com" OGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=PATH msg=audit(1624643172.076:11843): item=1 name="/usr/bin/python3" inode=1691048 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PATH msg=audit(1624643172.076:11843): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=4636927 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PROCTITLE msg=audit(1624643172.076:11843): proctitle=2F7573722F62696E2F707974686F6E33002E2F72756E74696D65007073657865632E70790065786368616E6765746573742E636F6D2F61646D696E6973747261746F72403139322E3136382E302E3537002D6861736865730063363135643734663237376163623733326166346538363830333330666366313A633631356437'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '92601')
        self.assertEqual(response.rule_level, 6)


    def test_executed_python_script_from_tmp_folder_2(self) -> None:
        log = r'''type=SYSCALL msg=audit(1624643172.076:11843): arch=c000003e syscall=59 success=yes exit=0 a0=25c81f0 a1=255f000 a2=255df40 a3=7ffc66d5c8e0 items=3 ppid=4353 pid=13331 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=pts0 ses=48 comm="runtime" exe="/usr/bin/python2.7" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="wazuh_execution"\u001DARCH=x86_64 SYSCALL=execve AUID="administrator@ExchangeTest.com" UID="administrator@ExchangeTest.com" GID=646F6D61696E2075736572734045786368616E6765546573742E636F6D EUID="administrator@ExchangeTest.com" SUID="administrator@ExchangeTest.com" FSUID="administrator@ExchangeTest.com" EGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D SGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D FSGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=EXECVE msg=audit(1624643172.076:11843): argc=6 a0="/usr/bin/python3" a1="./runtime" a2="/tmp/calc.py" a3="exchangetest.com/administrator@192.168.0.57" a4="-hashes" a5="c615d74f277acb732af4e8680330fcf1:c615d74f277acb732af4e8680330fcf1" type=CWD msg=audit(1624643172.076:11843):  cwd="/tmp" type=PATH msg=audit(1624643172.076:11843): item=0 name="./runtime" inode=8409155 dev=fd:00 mode=0100755 ouid=1198400500 ogid=1198400513 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="administrator@ExchangeTest.com" OGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=PATH msg=audit(1624643172.076:11843): item=1 name="/usr/bin/python3" inode=1691048 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PATH msg=audit(1624643172.076:11843): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=4636927 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PROCTITLE msg=audit(1624643172.076:11843): proctitle=2F7573722F62696E2F707974686F6E33002E2F72756E74696D65007073657865632E70790065786368616E6765746573742E636F6D2F61646D696E6973747261746F72403139322E3136382E302E3537002D6861736865730063363135643734663237376163623733326166346538363830333330666366313A633631356437'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '92601')
        self.assertEqual(response.rule_level, 6)


    def test_executed_python_script_from_tmp_folder_3(self) -> None:
        log = r'''type=SYSCALL msg=audit(1624643172.076:11843): arch=c000003e syscall=59 success=yes exit=0 a0=25c81f0 a1=255f000 a2=255df40 a3=7ffc66d5c8e0 items=3 ppid=4353 pid=13331 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=pts0 ses=48 comm="runtime" exe="/usr/bin/python2.7" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="wazuh_execution"\u001DARCH=x86_64 SYSCALL=execve AUID="administrator@ExchangeTest.com" UID="administrator@ExchangeTest.com" GID=646F6D61696E2075736572734045786368616E6765546573742E636F6D EUID="administrator@ExchangeTest.com" SUID="administrator@ExchangeTest.com" FSUID="administrator@ExchangeTest.com" EGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D SGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D FSGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=EXECVE msg=audit(1624643172.076:11843): argc=6 a0="/usr/bin/python3" a1="./runtime" a2="/calc.py" a3="exchangetest.com/administrator@192.168.0.57" a4="-hashes" a5="c615d74f277acb732af4e8680330fcf1:c615d74f277acb732af4e8680330fcf1" type=CWD msg=audit(1624643172.076:11843):  cwd="/tmp" type=PATH msg=audit(1624643172.076:11843): item=0 name="./runtime" inode=8409155 dev=fd:00 mode=0100755 ouid=1198400500 ogid=1198400513 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="administrator@ExchangeTest.com" OGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=PATH msg=audit(1624643172.076:11843): item=1 name="/usr/bin/python3" inode=1691048 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PATH msg=audit(1624643172.076:11843): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=4636927 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PROCTITLE msg=audit(1624643172.076:11843): proctitle=2F7573722F62696E2F707974686F6E33002E2F72756E74696D65007073657865632E70790065786368616E6765746573742E636F6D2F61646D696E6973747261746F72403139322E3136382E302E3537002D6861736865730063363135643734663237376163623733326166346538363830333330666366313A633631356437'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '92601')


    def test_suspicious_python_script_matches_impacket_signature_possible_use_of_stolen_credentials_or_pass_the_hash_attack(self) -> None:
        log = r'''type=SYSCALL msg=audit(1624643172.076:11843): arch=c000003e syscall=59 success=yes exit=0 a0=25c81f0 a1=255f000 a2=255df40 a3=7ffc66d5c8e0 items=3 ppid=4353 pid=13331 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=pts0 ses=48 comm="runtime" exe="/usr/bin/python3.6" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="wazuh_execution"\u001DARCH=x86_64 SYSCALL=execve AUID="administrator@ExchangeTest.com" UID="administrator@ExchangeTest.com" GID=646F6D61696E2075736572734045786368616E6765546573742E636F6D EUID="administrator@ExchangeTest.com" SUID="administrator@ExchangeTest.com" FSUID="administrator@ExchangeTest.com" EGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D SGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D FSGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=EXECVE msg=audit(1624643172.076:11843): argc=6 a0="/usr/bin/python3" a1="./runtime" a2="psexec.py" a3="exchangetest.com/administrator@192.168.0.57" a4="-hashes" a5="c615d74f277acb732af4e8680330fcf1:c615d74f277acb732af4e8680330fcf1" type=CWD msg=audit(1624643172.076:11843):  cwd="/tmp" type=PATH msg=audit(1624643172.076:11843): item=0 name="./runtime" inode=8409155 dev=fd:00 mode=0100755 ouid=1198400500 ogid=1198400513 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="administrator@ExchangeTest.com" OGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=PATH msg=audit(1624643172.076:11843): item=1 name="/usr/bin/python3" inode=1691048 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PATH msg=audit(1624643172.076:11843): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=4636927 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PROCTITLE msg=audit(1624643172.076:11843): proctitle=2F7573722F62696E2F707974686F6E33002E2F72756E74696D65007073657865632E70790065786368616E6765746573742E636F6D2F61646D696E6973747261746F72403139322E3136382E302E3537002D6861736865730063363135643734663237376163623733326166346538363830333330666366313A633631356437'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '92602')
        self.assertEqual(response.rule_level, 12)


    def test_scp_used_to_copy_a_file_over_ssh(self) -> None:
        log = r'''type=SYSCALL msg=audit(1620937405.872:764): arch=c000003e syscall=2 success=yes exit=4 a0=555c2e4a6fb0 a1=41 a2=1a4 a3=7fcfaf0607b8 items=2 ppid=7903 pid=7909 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=(none) ses=21 comm="scp" exe="/usr/bin/scp" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="wazuh_fim" type=CWD msg=audit(1620937405.872:764):  cwd="/home/administrator@ExchangeTest.com" type=PATH msg=audit(1620937405.872:764): item=0 name="/tmp/" inode=8409157 dev=fd:00 mode=041777 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:tmp_t:s0 objtype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0 type=PATH msg=audit(1620937405.872:764): item=1 name="/tmp/ps2.py" inode=9595745 dev=fd:00 mode=0100644 ouid=1198400500 ogid=1198400513 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=CREATE cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0 type=PROCTITLE msg=audit(1620937405.872:764): proctitle=736370002D74002F746D702F7073322E7079'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '92603')
        self.assertEqual(response.rule_level, 6)


    def test_processes_running_for_all_users_were_queried_with_ps_command(self) -> None:
        log = r'''type=SYSCALL msg=audit(1624476656.044:9687): arch=c000003e syscall=59 success=yes exit=0 a0=c4f630 a1=b370a0 a2=b3df40 a3=7ffe0c9f12e0 items=2 ppid=3177 pid=4646 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=pts0 ses=4 comm="ps" exe="/usr/bin/ps" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="recon"\u001DARCH=x86_64 SYSCALL=execve AUID="administrator@ExchangeTest.com" UID="administrator@ExchangeTest.com" GID=646F6D61696E2075736572734045786368616E6765546573742E636F6D EUID="administrator@ExchangeTest.com" SUID="administrator@ExchangeTest.com" FSUID="administrator@ExchangeTest.com" EGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D SGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D FSGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=EXECVE msg=audit(1624476656.044:9687): argc=2 a0="ps" a1="ax" type=CWD msg=audit(1624476656.044:9687):  cwd="/home/administrator@ExchangeTest.com" type=PATH msg=audit(1624476656.044:9687): item=0 name="/usr/bin/ps" inode=574271 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PATH msg=audit(1624476656.044:9687): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=4636927 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PROCTITLE msg=audit(1624476656.044:9687): proctitle=7073006178'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '92604')
        self.assertEqual(response.rule_level, 6)


    def test_executed_recursive_query_of_all_files_using_ls_command(self) -> None:
        log = r'''type=SYSCALL msg=audit(1624476775.094:9702): arch=c000003e syscall=59 success=yes exit=0 a0=c4f630 a1=b3a580 a2=b3df40 a3=7ffe0c9f12e0 items=2 ppid=3177 pid=4697 auid=1198400500 uid=1198400500 gid=1198400513 euid=1198400500 suid=1198400500 fsuid=1198400500 egid=1198400513 sgid=1198400513 fsgid=1198400513 tty=pts0 ses=4 comm="ls" exe="/usr/bin/ls" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="recon"\u001DARCH=x86_64 SYSCALL=execve AUID="administrator@ExchangeTest.com" UID="administrator@ExchangeTest.com" GID=646F6D61696E2075736572734045786368616E6765546573742E636F6D EUID="administrator@ExchangeTest.com" SUID="administrator@ExchangeTest.com" FSUID="administrator@ExchangeTest.com" EGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D SGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D FSGID=646F6D61696E2075736572734045786368616E6765546573742E636F6D type=EXECVE msg=audit(1624476775.094:9702): argc=4 a0="ls" a1="--color=auto" a2="-lsahR" a3="/var/" type=CWD msg=audit(1624476775.094:9702):  cwd="/home/administrator@ExchangeTest.com" type=PATH msg=audit(1624476775.094:9702): item=0 name="/usr/bin/ls" inode=416001 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PATH msg=audit(1624476775.094:9702): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=4636927 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\u001DOUID="root" OGID="root" type=PROCTITLE msg=audit(1624476775.094:9702): proctitle=6C73002D2D636F6C6F723D6175746F002D6C73616852002F7661722F'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '92605')
        self.assertEqual(response.rule_level, 6)

