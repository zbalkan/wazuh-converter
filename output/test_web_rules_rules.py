#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from web_rules.ini
class TestWebRulesRules(unittest.TestCase):

    def test_a_web_attack_returned_code_200_success(self) -> None:
        log = r'''
2014-12-20 21:34:37 W3SVC58 XXX-XXWEB-01 1.2.3.4 GET /search/programdetails.aspx id=3542&print=');declare%20@c%20cursor;declare%20@d%20varchar(4000);set%20@c=cursor%20for%20select%20'update%20%5B'%2BTABLE_NAME%2B'%5D%20set%20%5B'%2BCOLUMN_NAME%2B'%5D=%5B'%2BCOLUMN_NAME%2B'%5D%2Bcase%20ABS(CHECKSUM(NewId()))%257%20when%200%20then%20''''%2Bchar(60)%2B''div%20style=%22display:none%22''%2Bchar(62)%2B''abortion%20pill%20prescription%20''%2Bchar(60)%2B''a%20href=%22http:''%2Bchar(47)%2Bchar(47)%2BREPLACE(case%20ABS(CHECKSUM(NewId()))%253%20when%200%20then%20''www.yeronimo.com@template''%20when%201%20then%20''www.tula-point.ru@template''%20else%20''blog.tchami.com@template''%20end,''@'',char(47))%2B''%22''%2Bchar(62)%2Bcase%20ABS(CHECKSUM(NewId()))%253%20when%200%20then%20''online''%20when%201%20then%20''i%20need%20to%20buy%20the%20abortion%20pill''%20else%20''abortion%20pill''%20end%20%2Bchar(60)%2Bchar(47)%2B''a''%2Bchar(62)%2B''%20where%20to%20buy%20abortion%20pill''%2Bchar(60)%2Bchar(47)%2B''div''%2Bchar(62)%2B''''%20else%20''''%20end'%20FROM%20sysindexes%20AS%20i%20INNER%20JOIN%20sysobjects%20AS%20o%20ON%20i.id=o.id%20INNER%20JOIN%20INFORMATION_SCHEMA.COLUMNS%20ON%20o.NAME=TABLE_NAME%20WHERE(indid=0%20or%20indid=1)%20and%20DATA_TYPE%20like%20'%25varchar'%20and(CHARACTER_MAXIMUM_LENGTH=-1%20or%20CHARACTER_MAXIMUM_LENGTH=2147483647);open%20@c;fetch%20next%20from%20@c%20into%20@d;while%20@@FETCH_STATUS=0%20begin%20exec%20(@d);fetch%20next%20from%20@c%20into%20@d;end;close%20@c-- 80 - 173.201.216.6 HTTP/1.1 Mozilla/5.0+(Windows+NT+6.1;+WOW64;+rv:24.0)+Gecko/20100101+Firefox/24.0');declare+@c+cursor;declare+@d+varchar(4000);set+@c=cursor+for+select+'update+['+TABLE_NAME+']+set+['+COLUMN_NAME+']=['+COLUMN_NAME+']+case+ABS(CHECKSUM(NewId()))%7+when+0+then+''''+char(60)+''div+style="display:none"''+char(62)+''abortion+pill+prescription+''+char(60)+''a+href="http:''+char(47)+char(47)+REPLACE(case+ABS(CHECKSUM(NewId()))%3+when+0+then+''www.yeronimo.com@template''+when+1+then+''www.tula-point.ru@template''+else+''blog.tchami.com@template''+end,''@'',char(47))+''"''+char(62)+case+ABS(CHECKSUM(NewId()))%3+when+0+then+''online''+when+1+then+''i+need+to+buy+the+abortion+pill''+else+''abortion+pill''+end++char(60)+char(47)+''a''+char(62)+''+where+to+buy+abortion+pill''+char(60)+char(47)+''div''+char(62)+''''+else+''''+end'+FROM+sysindexes+AS+i+INNER+JOIN+sysobjects+AS+o+ON+i.id=o.id+INNER+JOIN+INFORMATION_SCHEMA.COLUMNS+ON+o.NAME=TABLE_NAME+WHERE(indid=0+or+indid=1)+and+DATA_TYPE+like+'%varchar'+and(CHARACTER_MAXIMUM_LENGTH=-1+or+CHARACTER_MAXIMUM_LENGTH=2147483647);open+@c;fetch+next+from+@c+into+@d;while+@@FETCH_STATUS=0+begin+exec+(@d);fetch+next+from+@c+into+@d;end;close+@c-- - http://google.com');declare+@c+cursor;declare+@d+varchar(4000);set+@c=cursor+for+select+'update+['+TABLE_NAME+']+set+['+COLUMN_NAME+']=['+COLUMN_NAME+']+case+ABS(CHECKSUM(NewId()))%7+when+0+then+''''+char(60)+''div+style="display:none"''+char(62)+''abortion+pill+prescription+''+char(60)+''a+href="http:''+char(47)+char(47)+REPLACE(case+ABS(CHECKSUM(NewId()))%3+when+0+then+''www.yeronimo.com@template''+when+1+then+''www.tula-point.ru@template''+else+''blog.tchami.com@template''+end,''@'',char(47))+''"''+char(62)+case+ABS(CHECKSUM(NewId()))%3+when+0+then+''online''+when+1+then+''i+need+to+buy+the+abortion+pill''+else+''abortion+pill''+end++char(60)+char(47)+''a''+char(62)+''+where+to+buy+abortion+pill''+char(60)+char(47)+''div''+char(62)+''''+else+''''+end'+FROM+sysindexes+AS+i+INNER+JOIN+sysobjects+AS+o+ON+i.id=o.id+INNER+JOIN+INFORMATION_SCHEMA.COLUMNS+ON+o.NAME=TABLE_NAME+WHERE(indid=0+or+indid=1)+and+DATA_TYPE+like+'%varchar'+and(CHARACTER_MAXIMUM_LENGTH=-1+or+CHARACTER_MAXIMUM_LENGTH=2147483647);open+@c;fetch+next+from+@c+into+@d;while+@@FETCH_STATUS=0+begin+exec+(@d);fetch+next+from+@c+into+@d;end;close+@c-- www.somesite.org 200 0 0 36560 3942 78
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog-iis6')
        self.assertEqual(response.rule_id, '31106')
        self.assertEqual(response.rule_level, 6)


    def test_not_a_web_attack_returned_code_200_success(self) -> None:
        log = r'''
10.0.0.5 - - [1/Apr/2014:00:00:01 -0500] "POST /wp-admin HTTP/1.1" 200 181 "-" "Mozilla/5.0 (X11)"
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '31106')


    def test_a_web_page_returned_code_302_code(self) -> None:
        log = r'''
2015-07-28 15:07:26 1.2.3.4 GET /QOsa/Browser/Default.aspx UISessionId=SN1234123&DeviceId=SN12312232SHARP+MX-4111N 80 - 31.3.3.7 OpenSystems/1.0;+product-family="85";+product-version="123ER123" 302 0 0 624
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog-iis-default')
        self.assertEqual(response.rule_id, '31108')
        self.assertEqual(response.rule_level, 0)


    def test_a_web_page_returned_code_404_not_found(self) -> None:
        log = r'''
2015-03-11 21:59:09 1.2.3.4 GET /console/faces/com_sun_web_ui/jsp/version/version_30.jsp - 80 - 31.3.3.7 Sun+Web+Console+Fingerprinter/7.15 - 404 0 2 0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog-iis-default')
        self.assertEqual(response.rule_id, '31101')
        self.assertEqual(response.rule_level, 5)


    def test_a_web_attacked_returned_code_404(self) -> None:
        log = r'''
2015-03-11 22:01:59 1.2.3.4 GET /CFIDE/adminapi/customtags/l10n.cfm attributes.id=test&attributes.file=../../administrator/mail/download.cfm&filename=../lib/password.properties&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=test 443 - 31.3.3.7 - - 404 0 2 0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog-iis-default')
        self.assertEqual(response.rule_id, '31104')
        self.assertEqual(response.rule_level, 6)


    def test_a_web_page_returned_code_404_not_found_syslog_format(self) -> None:
        log = r'''
Jan 11 10:13:05 web01 nginx: ::ffff:202.194.15.192 190.7.138.180 - [18/Oct/2010:10:48:55 -0500] "GET //php-my-admin/config/config.inc.php?p=phpinfo(); HTTP/1.1" 404 345 "-"  "Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog')
        self.assertEqual(response.rule_id, '31101')
        self.assertEqual(response.rule_level, 5)


    def test_a_web_attacked_returned_code_404_syslog_format(self) -> None:
        log = r'''
Jan 11 10:13:05 web01 nginx: 10.10.10.11 10.10.10.12 - - [10/Apr/2017:13:18:05 -0700] "GET /injection/%0d%0aSet-Cookie HTTP/1.1" 404 271 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog')
        self.assertEqual(response.rule_id, '31104')
        self.assertEqual(response.rule_level, 6)


    def test_sql_injection_attempt_syslog_format(self) -> None:
        log = r'''
Jan 11 10:13:05 web01 apache: 10.11.12.13 - - - [27/Mar/2017:13:40:40 -0700] "GET /modules.php?name=Search&type=stories&query=qualys&category=-1%20&categ=%20and%201=2%20UNION%20SELECT%200,0,aid,pwd,0,0,0,0,0,0%20from%20nuke_authors/* HTTP/1.0" 404 982 "-" "-"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog')
        self.assertEqual(response.rule_id, '31103')
        self.assertEqual(response.rule_level, 7)


    def test_sql_injection_attempt(self) -> None:
        log = r'''
www.example.com:80 1.1.1.1 - - [12/Mar/2019:10:09:09 +0000] "GET /example?dir=asc&order=if(now()=sysdate()%2csleep(19.406)%2c0)/*'XOR(if(now()=sysdate()%2csleep(19.406)%2c0))OR'\"XOR(if(now()=sysdate()%2csleep(19.406)%2c0))OR\"*/&example=5101 HTTP/1.1" 200 10869 "https://www.example.com" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21" "-" "XIeFRRmu6BzGhDFQJ1K@HwAAAAs"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog')
        self.assertEqual(response.rule_id, '31170')
        self.assertEqual(response.rule_level, 6)


    def test_sql_injection_attempt_2(self) -> None:
        log = r'''
www.example.com:80 1.1.1.1 - - [12/Mar/2019:10:09:12 +0000] "GET /example?dir=asc&order=Mcd6Pr9F';select%20pg_sleep(9.703);%20--%20&example=5101 HTTP/1.1" 200 10345 "https://www.example.com" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21" "-" "XIeFSOin2ac7y0KragEaGwAAAAM"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog')
        self.assertEqual(response.rule_id, '31171')
        self.assertEqual(response.rule_level, 6)

