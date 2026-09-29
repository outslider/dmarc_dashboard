import configparser
import gzip
import io
import json
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from email.message import EmailMessage
from http.server import ThreadingHTTPServer
from pathlib import Path

from dmarc_dashboard import analytics, db, ingest, server
from dmarc_dashboard.parser import ReportParseError, parse_any, parse_mail, parse_xml

XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name><email>noreply@google.com</email>
    <report_id>123456</report_id>
    <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
  </report_metadata>
  <policy_published><domain>Example.co.jp</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><pct>100</pct></policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>10</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.co.jp</header_from></identifiers>
    <auth_results><dkim><domain>example.co.jp</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.co.jp</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>198.51.100.1</source_ip><count>50</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
      <reason><type>forwarded</type><comment>x</comment></reason></policy_evaluated></row>
    <identifiers><header_from>example.co.jp</header_from></identifiers>
    <auth_results><dkim><domain>sendgrid.net</domain><result>pass</result></dkim>
      <spf><domain>sendgrid.net</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""


def zipped(data, name="r.xml"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, data)
    return buf.getvalue()


def mail_with(attachment, fname, ctype="application", sub="zip"):
    m = EmailMessage()
    m["From"] = "noreply@google.com"
    m["To"] = "dmarc@example.co.jp"
    m["Subject"] = "Report domain: example.co.jp"
    m.set_content("see attachment")
    m.add_attachment(attachment, maintype=ctype, subtype=sub, filename=fname)
    return m.as_bytes()


class ParserTest(unittest.TestCase):
    def test_parse_xml(self):
        r = parse_xml(XML)
        self.assertEqual(r.org_name, "google.com")
        self.assertEqual(r.domain, "example.co.jp")
        self.assertEqual(len(r.records), 2)
        self.assertTrue(r.records[0].dmarc_pass)
        self.assertFalse(r.records[1].dmarc_pass)
        self.assertEqual(r.records[1].reasons, ["forwarded: x"])
        self.assertEqual(r.records[1].auth_results[0].domain, "sendgrid.net")

    def test_namespaced_dmarcbis(self):
        ns = XML.replace(b"<feedback>", b'<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">')
        self.assertEqual(len(parse_xml(ns).records), 2)

    def test_compressed_and_mail(self):
        self.assertEqual(parse_any(gzip.compress(XML), "a.xml.gz")[0].report_id, "123456")
        self.assertEqual(parse_any(zipped(XML), "a.zip")[0].report_id, "123456")
        raw = mail_with(zipped(XML), "google.com!example.co.jp!1!2.zip")
        self.assertEqual(parse_mail(raw)[0].report_id, "123456")
        raw = mail_with(gzip.compress(XML), "r.xml.gz", "application", "gzip")
        self.assertEqual(parse_any(raw, "")[0].report_id, "123456")

    def test_rejects_entities(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><feedback>&a;</feedback>'
        with self.assertRaises(ReportParseError):
            parse_xml(evil)

    def test_rejects_non_report(self):
        with self.assertRaises(ReportParseError):
            parse_xml(b"<foo/>")


class StoreAndAnalyticsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = db.connect(str(Path(self.tmp.name) / "t.db"))

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_dedupe(self):
        s1 = ingest.import_bytes(self.conn, XML, "a.xml")
        s2 = ingest.import_bytes(self.conn, gzip.compress(XML), "a.xml.gz")
        self.assertEqual((s1.imported, s2.imported, s2.duplicates), (1, 0, 1))

    def test_dashboard(self):
        ingest.import_bytes(self.conn, XML, "a.xml")
        d = analytics.dashboard(self.conn)
        self.assertEqual(d["kpi"]["messages"], 60)
        self.assertEqual(d["kpi"]["pass"], 10)
        self.assertAlmostEqual(d["kpi"]["pass_rate"], 16.67)
        by_ip = {s["ip"]: s for s in d["sources"]}
        self.assertEqual(by_ip["192.0.2.1"]["status"], "ok")
        self.assertEqual(by_ip["198.51.100.1"]["status"], "misaligned")
        titles = " ".join(i["title"] for i in d["insights"])
        self.assertIn("アラインメント失敗", titles)
        self.assertIn("p=none", titles)
        # 期間フィルタ
        self.assertEqual(analytics.dashboard(self.conn, start=1800000000)["kpi"]["messages"], 0)
        self.assertEqual(analytics.dashboard(self.conn, domain="other.example")["kpi"]["messages"], 0)

    def test_per_domain_insights(self):
        ingest.import_bytes(self.conn, XML, "a.xml")
        other = (XML.replace(b"Example.co.jp", b"example-hd.co.jp").replace(b"example.co.jp", b"example-hd.co.jp")
                 .replace(b"<report_id>123456", b"<report_id>999").replace(b"<p>none</p>", b"<p>reject</p>")
                 .replace(b"<count>50</count>", b"<count>0</count>"))
        ingest.import_bytes(self.conn, other, "b.xml")
        # 終了日を指定 (フィクスチャが古い日付なので「レポートが届いていない」判定を外す)
        d = analytics.dashboard(self.conn, end=2_000_000_000)
        by_dom = {x["domain"]: x for x in d["domains"]}
        self.assertEqual(set(by_dom), {"example.co.jp", "example-hd.co.jp"})
        self.assertGreater(by_dom["example.co.jp"]["issues"]["serious"], 0)
        self.assertEqual(by_dom["example-hd.co.jp"]["issues"], {"critical": 0, "serious": 0, "warning": 0})
        self.assertEqual(len(by_dom["example.co.jp"]["daily"]), 1)
        # 送信元の診断も、問題のあるドメインにだけ付く
        mis = [i for i in d["insights"] if "アラインメント失敗" in i["title"]]
        self.assertEqual([i["domain"] for i in mis], ["example.co.jp"])
        self.assertTrue(all(i["domain"] for i in d["insights"]))

    def test_org_domain(self):
        self.assertEqual(analytics.org_domain("mail.shop.example.co.jp"), "example.co.jp")
        self.assertEqual(analytics.org_domain("bounce.example.com"), "example.com")


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cfg = configparser.ConfigParser()
        cfg.read_dict({"database": {"path": str(Path(self.tmp.name) / "t.db")},
                       "server": {"user": "admin", "password": "secret", "base_path": "/dmarc_dashboard/"},
                       "dns": {"resolve": "false"}, "imap": {}})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(server.App(cfg)))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def req(self, path, data=None, auth=True, headers=None):
        r = urllib.request.Request(self.base + path, data=data, headers=headers or {})
        if auth:
            r.add_header("Authorization", "Basic YWRtaW46c2VjcmV0")
        return urllib.request.urlopen(r)

    def test_auth_required(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.req("/api/dashboard", auth=False)
        self.assertEqual(cm.exception.code, 401)

    def test_upload_and_dashboard(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:  # CSRF ヘッダーなし
            self.req("/api/upload", data=XML)
        self.assertEqual(cm.exception.code, 403)
        res = json.load(self.req("/api/upload", data=zipped(XML),
                                 headers={"X-Requested-With": "dmarc-dashboard", "X-Filename": "r.zip"}))
        self.assertEqual(res["imported"], 1)
        d = json.load(self.req("/api/dashboard"))
        self.assertEqual(d["kpi"]["messages"], 60)
        self.assertEqual(d["all_domains"], ["example.co.jp"])
        rows = json.load(self.req("/api/source?ip=198.51.100.1"))
        self.assertEqual(rows[0]["count"], 50)

    def test_base_path(self):
        # プレフィックス付き (ProxyPass で /dmarc_dashboard/ を残して転送する構成)
        self.assertIn(b'href="style.css"', self.req("/dmarc_dashboard/").read())
        self.assertEqual(self.req("/dmarc_dashboard/app.js").status, 200)
        self.assertIn("kpi", json.load(self.req("/dmarc_dashboard/api/dashboard")))
        res = json.load(self.req("/dmarc_dashboard/api/upload", data=XML,
                                 headers={"X-Requested-With": "dmarc-dashboard", "X-Filename": "r.xml"}))
        self.assertEqual(res["imported"], 1)
        # 末尾スラッシュなしはリダイレクト
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        r = urllib.request.Request(self.base + "/dmarc_dashboard", headers={"Authorization": "Basic YWRtaW46c2VjcmV0"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            opener.open(r)
        self.assertEqual(cm.exception.code, 301)
        self.assertEqual(cm.exception.headers["Location"], "/dmarc_dashboard/")

    def test_static_traversal(self):
        self.assertEqual(self.req("/").status, 200)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.req("/../server.py")
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
