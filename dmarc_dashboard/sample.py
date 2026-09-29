"""デモ用のサンプルレポートを生成する (動作確認用)。"""

import gzip
import random
import time
import zipfile
from pathlib import Path

# (IP, 疑似 PTR, 1 日あたりの通数, spf_raw, spf_domain, dkim_raw, dkim_domain)
# IP は文書用アドレス帯 (RFC 5737) を使用
SENDERS = [
    ("192.0.2.10", "mail-sor-f41.google.com", 900, "pass", "{d}", "pass", "{d}"),
    ("192.0.2.11", "mail-sor-f65.google.com", 700, "pass", "{d}", "pass", "{d}"),
    ("198.51.100.20", "o1.ptr1234.sendgrid.net", 250, "pass", "sendgrid.net", "pass", "sendgrid.net"),
    ("198.51.100.30", "a48-93.smtp-out.amazonses.com", 120, "pass", "{d}", "pass", "{d}"),
    ("198.51.100.40", "mail.partner-mlist.example", 40, "fail", "partner-mlist.example", "pass", "{d}"),
    ("203.0.113.66", "", 35, "fail", "{d}", "none", ""),
    ("203.0.113.77", "unknown.dynamic.example.net", 18, "softfail", "{d}", "fail", "{d}"),
]
REPORTERS = [("google.com", "noreply-dmarc-support@google.com", 0.55),
             ("Enterprise Outlook", "dmarcreport@microsoft.com", 0.3),
             ("Yahoo! JAPAN", "dmarc-report@yahoo.co.jp", 0.15)]
PTRS = {ip: ptr for ip, ptr, *_ in SENDERS}


def _xml(org, mail, rid, begin, end, domain, p, rows):
    recs = []
    for ip, count, spf_raw, spf_dom, dkim_raw, dkim_dom in rows:
        spf_eval = "pass" if spf_raw == "pass" and spf_dom.endswith(domain) else "fail"
        dkim_eval = "pass" if dkim_raw == "pass" and dkim_dom.endswith(domain) else "fail"
        passed = spf_eval == "pass" or dkim_eval == "pass"
        disp = "none" if passed or p == "none" else p
        dkim_xml = (f"<dkim><domain>{dkim_dom}</domain><selector>s1</selector><result>{dkim_raw}</result></dkim>"
                    if dkim_dom else "")
        recs.append(f"""<record><row><source_ip>{ip}</source_ip><count>{count}</count>
<policy_evaluated><disposition>{disp}</disposition><dkim>{dkim_eval}</dkim><spf>{spf_eval}</spf></policy_evaluated></row>
<identifiers><header_from>{domain}</header_from><envelope_from>{spf_dom}</envelope_from></identifiers>
<auth_results>{dkim_xml}<spf><domain>{spf_dom}</domain><scope>mfrom</scope><result>{spf_raw}</result></spf></auth_results></record>""")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback><report_metadata><org_name>{org}</org_name><email>{mail}</email><report_id>{rid}</report_id>
<date_range><begin>{begin}</begin><end>{end}</end></date_range></report_metadata>
<policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>{p}</p><sp>{p}</sp><pct>100</pct></policy_published>
{''.join(recs)}</feedback>""".encode()


# ドメインごとの想定: (ポリシー, 通数の倍率, 利用する送信元 IP (None = すべて))
PROFILES = {
    "example.co.jp": ("none", 1.0, None),                        # 設定不備・なりすましあり
    "shop.example.co.jp": ("quarantine", 0.25, None),            # 強化済みだが正規メールが落ちている
    "example-hd.co.jp": ("reject", 0.1, {"192.0.2.10", "192.0.2.11"}),   # 良好
    "example-life.co.jp": ("none", 0.15, {"192.0.2.10", "198.51.100.30", "198.51.100.40"}),  # 強化できる
}


def generate(out_dir: str, days: int = 45, domains=tuple(PROFILES), seed: int = 7) -> int:
    rnd = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    today = int(time.time()) // 86400 * 86400
    n = 0
    for domain in domains:
        p, scale, allowed = PROFILES.get(domain, ("none", 1.0, None))
        for day in range(days, 0, -1):
            begin = today - day * 86400
            for org, mail, share in REPORTERS:
                rows = []
                for ip, _, per_day, spf_raw, spf_dom, dkim_raw, dkim_dom in SENDERS:
                    if allowed is not None and ip not in allowed:
                        continue
                    # 途中から SendGrid の独自ドメイン設定を修正した、という想定
                    if ip.startswith("198.51.100.20") and day < 10:
                        spf_dom, dkim_dom = "bounce.{d}", "{d}"
                    # 最近になって増えたなりすまし
                    boost = 4 if ip == "203.0.113.66" and day < 6 else 1
                    c = int(per_day * share * scale * boost * rnd.uniform(0.6, 1.4))
                    if c > 0:
                        rows.append((ip, c, spf_raw, spf_dom.format(d=domain), dkim_raw, dkim_dom.format(d=domain)))
                rid = f"{org.split()[0].lower()}-{domain}-{begin}"
                xml = _xml(org, mail, rid, begin, begin + 86399, domain, p, rows)
                stem = f"{org.split()[0].lower()}!{domain}!{begin}!{begin + 86399}"
                if n % 2:
                    (out / f"{stem}.xml.gz").write_bytes(gzip.compress(xml))
                else:
                    with zipfile.ZipFile(out / f"{stem}.zip", "w", zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr(f"{stem}.xml", xml)
                n += 1
    return n
