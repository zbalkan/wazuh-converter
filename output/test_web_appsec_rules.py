    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from web_appsec.ini
    class TestWeb_appsecRules(unittest.TestCase):
            def test_WordPress_Comment_Spam_coming_from_a_fake_search_engine_UA_1(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-comments-post.php HTTP/1.1" 403 181 "-" "Googlebot/1'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31501')
            self.assertEqual(response.alert_level, 6)

            def test_WordPress_Comment_Spam_coming_from_a_fake_search_engine_UA_2(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-comments-post.php HTTP/1.1" 403 181 "-" "msnbot/1'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31501')
            self.assertEqual(response.alert_level, 6)

            def test_WordPress_Comment_Spam_coming_from_a_fake_search_engine_UA_3(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-comments-post.php HTTP/1.1" 403 181 "-" "BingBot/1'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31501')
            self.assertEqual(response.alert_level, 6)

            def test_TimThumb_vulnerability_exploit_attempt(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /examplethumb.php?src=example.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31502')
            self.assertEqual(response.alert_level, 6)

            def test_osCommerce_loginphp_bypass_attempt(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /example.php/login.php?cPath= HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31503')
            self.assertEqual(response.alert_level, 6)

            def test_osCommerce_file_manager_loginphp_bypass_attempt(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /admin/example.php/login.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31504')
            self.assertEqual(response.alert_level, 6)

            def test_TimThumb_backdoor_access_attempt(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /example/cache/externalexample.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31505')
            self.assertEqual(response.alert_level, 6)

            def test_Cartphp_directory_transversal_attempt(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /examplecart.php?exampletemplatefile=../ HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31506')
            self.assertEqual(response.alert_level, 6)

            def test_Blacklisted_user_agent_known_malicious_user_agent_1(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "ZmEu"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31508')
            self.assertEqual(response.alert_level, 6)

            def test_Blacklisted_user_agent_known_malicious_user_agent_2(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "libwww-perl/1.1 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31508')
            self.assertEqual(response.alert_level, 6)

            def test_Blacklisted_user_agent_known_malicious_user_agent_3(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "the beast"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31508')
            self.assertEqual(response.alert_level, 6)

            def test_Blacklisted_user_agent_known_malicious_user_agent_4(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "Morfeus"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31508')
            self.assertEqual(response.alert_level, 6)

            def test_Blacklisted_user_agent_known_malicious_user_agent_5(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "ZmEu (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31508')
            self.assertEqual(response.alert_level, 6)

            def test_Blacklisted_user_agent_known_malicious_user_agent_6(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "Nikto (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31508')
            self.assertEqual(response.alert_level, 6)

            def test_Blacklisted_user_agent_known_malicious_user_agent_7(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET / HTTP/1.1" 403 181 "-" "w3af.sourceforge.net (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31508')
            self.assertEqual(response.alert_level, 6)

            def test_CMS_WordPress_or_Joomla_login_attempt_1(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /example/wp-login.php HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31509')
            self.assertEqual(response.alert_level, 3)

            def test_CMS_WordPress_or_Joomla_login_attempt_2(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /administrator HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31509')
            self.assertEqual(response.alert_level, 3)

            def test_Blacklisted_user_agent_wget(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /index.html? HTTP/1.1" 200 4617 "-" "Wget/1.15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31511')
            self.assertEqual(response.alert_level, 0)

            def test_Uploadify_vulnerability_exploit_attempt(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /example/uploadify.php?src=http://example.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31512')
            self.assertEqual(response.alert_level, 6)

            def test_BBS_deletephp_exploit_attempt(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET example/delete.php?board_skin_path=http://example.php HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31513')
            self.assertEqual(response.alert_level, 6)

            def test_Simple_shellphp_command_execution(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET example/shell.php?cmd= HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31514')
            self.assertEqual(response.alert_level, 6)

            def test_PHPMyAdmin_scans_looking_for_setupphp(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /phpMyAdmin/scripts/setup.php HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31515')
            self.assertEqual(response.alert_level, 6)

            def test_Suspicious_URL_access_1(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /db/config.php.swp HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31516')
            self.assertEqual(response.alert_level, 6)

            def test_Suspicious_URL_access_2(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /db/config.php.bak HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31516')
            self.assertEqual(response.alert_level, 6)

            def test_Suspicious_URL_access_3(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /db/.htaccess HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31516')
            self.assertEqual(response.alert_level, 6)

            def test_Suspicious_URL_access_4(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /server-status HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31516')
            self.assertEqual(response.alert_level, 6)

            def test_Suspicious_URL_access_5(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /.ssh HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31516')
            self.assertEqual(response.alert_level, 6)

            def test_Suspicious_URL_access_6(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "GET /.history HTTP/1.1" 404 4617 "-" "Mozilla/15 (linux-gnu)"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'web-accesslog')
            self.assertEqual(response.rule_id, '31516')
            self.assertEqual(response.alert_level, 6)

            def test_POST_request_received(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST / HTTP/1.1" 403 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

                    def test_Ignoring_often_post_requests_inside_wp_admin_and_admin_1(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-admin HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

                    def test_Ignoring_often_post_requests_inside_wp_admin_and_admin_2(self) -> None:
            log = '''10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /admin HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"'''
            response = send_log(log)

            self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

            