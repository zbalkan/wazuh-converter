    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from test_osregex_regex_geoip.ini
    class TestTest_osregex_regex_geoipRules(unittest.TestCase):
            def test_osregex_test_osregex_16_srcgeoip(self) -> None:
            log = '''Dec 19 17:20:08 ubuntu test_osregex_16[12345]:test_srcgeoip 41.78.120.9'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'test_osregex_16')
            self.assertEqual(response.rule_id, '999800')
            self.assertEqual(response.alert_level, 3)

            def test_osregex_test_osregex_16_srcgeoip_n(self) -> None:
            log = '''Dec 19 17:20:08 ubuntu test_osregex_16[12345]:test_srcgeoip 194.69.224.10'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'test_osregex_16')
            self.assertEqual(response.rule_id, '999801')
            self.assertEqual(response.alert_level, 3)

            def test_osregex_test_osregex_17_dstgeoip(self) -> None:
            log = '''Dec 19 17:20:08 ubuntu test_osregex_17[12345]:test_dstgeoip 41.78.120.9'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'test_osregex_17')
            self.assertEqual(response.rule_id, '999802')
            self.assertEqual(response.alert_level, 3)

            def test_osregex_test_osregex_17_dstgeoip_n(self) -> None:
            log = '''Dec 19 17:20:08 ubuntu test_osregex_17[12345]:test_dstgeoip 194.69.224.10'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'test_osregex_17')
            self.assertEqual(response.rule_id, '999803')
            self.assertEqual(response.alert_level, 3)

    