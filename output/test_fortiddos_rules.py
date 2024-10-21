    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from fortiddos.ini
    class TestFortiddosRules(unittest.TestCase):
            def test_FortiGate_IPS_High_severity(self) -> None:
            log = '''2021-05-27T23:59:59.998837-03:00 12.34.56.78 devid=FGXXXXXXX date=2021-05-28 time=00:00:00 tz=ART type=attack subtype="ips" spp=4 evecode=2 evesubcode=27 description="TCP invalid flag combination " dir=1 protocol=6 sip=0.0.0.0 dip=12.34.56.79 dropcount=30 subnetid=95 facility=Local0 level=Notice direction=inbound spp_name="YYYYY" subnet_name="ZZZZZ" sppoperatingmode=detection severity="high"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'fortiddos-like')
            self.assertEqual(response.rule_id, '44629')
            self.assertEqual(response.alert_level, 7)

            def test_FortiGate_IPS_Low_severity(self) -> None:
            log = '''2021-05-27T23:59:59.998837-03:00 12.34.56.78 devid=FGXXXXXXX date=2021-05-28 time=00:00:00 tz=ART type=attack subtype="ips" spp=4 evecode=2 evesubcode=27 description="TCP invalid flag combination " dir=1 protocol=6 sip=0.0.0.0 dip=12.34.56.79 dropcount=30 subnetid=95 facility=Local0 level=Notice direction=inbound spp_name="YYYYY" subnet_name="ZZZZZ" sppoperatingmode=detection severity="low"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'fortiddos-like')
            self.assertEqual(response.rule_id, '44630')
            self.assertEqual(response.alert_level, 3)

            def test_FortiGate_IPS_medium_severity(self) -> None:
            log = '''2021-05-27T23:59:59.998837-03:00 12.34.56.78 devid=FGXXXXXXX date=2021-05-28 time=00:00:00 tz=ART type=attack subtype="ips" spp=4 evecode=2 evesubcode=27 description="TCP invalid flag combination " dir=1 protocol=6 sip=0.0.0.0 dip=12.34.56.79 dropcount=30 subnetid=95 facility=Local0 level=Notice direction=inbound spp_name="YYYYY" subnet_name="ZZZZZ" sppoperatingmode=detection severity="medium"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'fortiddos-like')
            self.assertEqual(response.rule_id, '44631')
            self.assertEqual(response.alert_level, 5)

    