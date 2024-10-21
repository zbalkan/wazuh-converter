    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from pam.ini
    class TestPamRules(unittest.TestCase):
            def test_User_login_failed(self) -> None:
            log = '''Nov 11 22:46:29 localhost su(pam_unix)[23164]: authentication failure; logname= uid=1342 euid=0 tty= ruser=dcid rhost=  user=osaudit'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'pam')
            self.assertEqual(response.rule_id, '5503')
            self.assertEqual(response.alert_level, 5)

            def test_Attempt_to_login_with_an_invalid_user(self) -> None:
            log = '''Nov 11 22:46:29 localhost vsftpd(pam_unix)[25073]: check pass; user unknown'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'pam')
            self.assertEqual(response.rule_id, '5504')
            self.assertEqual(response.alert_level, 5)

            def test_Login_session_opened(self) -> None:
            log = '''Nov 11 22:46:29 localhost su(pam_unix)[14592]: session opened for user news by (uid=0)'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'pam')
            self.assertEqual(response.rule_id, '5501')
            self.assertEqual(response.alert_level, 3)

            def test_Login_session_closed(self) -> None:
            log = '''Nov 11 22:46:29 localhost su(pam_unix)[14592]: session closed for user news'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'pam')
            self.assertEqual(response.rule_id, '5502')
            self.assertEqual(response.alert_level, 3)

            def test_User_missed_the_password_more_than_one_time(self) -> None:
            log = '''Nov 11 22:46:29 localhost sshd(pam_unix)[15794]: 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.3.1  user=root'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'pam')
            self.assertEqual(response.rule_id, '2502')
            self.assertEqual(response.alert_level, 10)

    