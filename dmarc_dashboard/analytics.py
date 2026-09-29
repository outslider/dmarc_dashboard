"""ダッシュボード用の集計と、自動診断 (インサイト) の生成。"""

import json
import sqlite3
import time
from collections import defaultdict
from typing import Dict, List, Optional

# PTR の末尾から既知の送信サービスを推定する (表示とインサイト用のヒント)
PROVIDERS = [
    ("google.com", "Google"), ("googleusercontent.com", "Google Cloud"),
    ("outlook.com", "Microsoft 365"), ("protection.outlook.com", "Microsoft 365"),
    ("amazonses.com", "Amazon SES"), ("amazonaws.com", "AWS"),
    ("sendgrid.net", "SendGrid"), ("mailgun.net", "Mailgun"), ("mailgun.org", "Mailgun"),
    ("mcsv.net", "Mailchimp"), ("mandrillapp.com", "Mailchimp"), ("rsgsv.net", "Mailchimp"),
    ("sparkpostmail.com", "SparkPost"), ("mktomail.com", "Marketo"),
    ("salesforce.com", "Salesforce"), ("exacttarget.com", "Salesforce MC"),
    ("hubspotemail.net", "HubSpot"), ("zendesk.com", "Zendesk"), ("freshdesk.com", "Freshdesk"),
    ("kagoya.net", "KAGOYA"), ("sakura.ne.jp", "さくら"), ("xserver.jp", "エックスサーバー"),
    ("secureserver.net", "GoDaddy"), ("yahoo.co.jp", "Yahoo! JAPAN"), ("yahoo.com", "Yahoo"),
    ("benchmarkemail.com", "Benchmark"), ("cuenote.jp", "Cuenote"), ("blastmail.jp", "blastmail"),
]

# 簡易的な組織ドメイン判定用 (PSL の代用。アラインメントの「ヒント」表示にのみ使う)
_SECOND_LEVEL = {"co", "ne", "or", "ac", "go", "ad", "ed", "gr", "lg", "com", "net", "org", "gov", "edu"}


def org_domain(d: str) -> str:
    parts = [p for p in (d or "").lower().strip(".").split(".") if p]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def provider_of(ptr: str) -> str:
    ptr = (ptr or "").lower()
    for suffix, name in PROVIDERS:
        if ptr == suffix or ptr.endswith("." + suffix):
            return name
    return ""


# policy_evaluated/reason (受信側が判定を上書きした理由) の表示名
OVERRIDE_LABELS = {
    "forwarded": "転送メールと判断",
    "sampled_out": "pct の対象外",
    "trusted_forwarder": "信頼済みの転送元",
    "mailing_list": "メーリングリスト",
    "local_policy": "受信側の独自ポリシー",
    "other": "その他",
}

# 失敗理由の分類コード → 一覧表示用の短いラベル
FAILURE_LABELS = {
    "spf_misaligned": "SPF ドメイン不一致",
    "spf_fail": "SPF 失敗",
    "spf_none": "SPF 評価なし",
    "spf_error": "SPF エラー",
    "dkim_misaligned": "DKIM ドメイン不一致",
    "dkim_fail": "DKIM 検証失敗",
    "dkim_none": "DKIM 署名なし",
    "dkim_error": "DKIM エラー",
    "other": "その他",
}


def _aligned(auth_domain: str, header_from: str, mode: str) -> bool:
    a, h = (auth_domain or "").lower().strip("."), (header_from or "").lower().strip(".")
    if not a or not h:
        return False
    return a == h if mode == "s" else org_domain(a) == org_domain(h)


def failure_reasons(header_from: str, spf_eval: str, dkim_eval: str, spf, dkims, adkim: str = "r",
                    aspf: str = "r", envelope_from: str = "") -> List[Dict]:
    """SPF / DKIM の生の認証結果とドメインの突き合わせから、DMARC 失敗の理由を推定する。

    spf: (domain, result) または None / dkims: [(domain, result), ...]
    DMARC に合格している (どちらかがアライメント込みで pass) 場合は空リスト。
    """
    if spf_eval == "pass" or dkim_eval == "pass":
        return []
    out = []

    def add(code, detail):
        out.append({"code": code, "label": FAILURE_LABELS[code], "detail": detail})

    strict_note = lambda mode, d: ("。adkim/aspf=s (厳格) のため完全一致が必要です"
                                   if mode == "s" and org_domain(d) == org_domain(header_from) else "")

    # SPF
    sd, sr = (spf or ("", "none"))
    sd = sd or envelope_from
    sr = (sr or "none").lower()
    if sr == "pass":
        if _aligned(sd, header_from, aspf) is False:
            add("spf_misaligned", f"SPF は {sd or '(不明)'} で合格しましたが、From ({header_from}) とドメインが一致しません"
                + strict_note(aspf, sd))
    elif sr in ("fail", "softfail", "neutral"):
        add("spf_fail", f"送信元 IP が {sd or '(不明)'} の SPF レコードで許可されていません ({sr})")
    elif sr == "permerror":
        add("spf_error", f"{sd or '(不明)'} の SPF レコードに誤りがあります (構文誤り、または DNS 参照 10 回の上限超過)")
    elif sr == "temperror":
        add("spf_error", f"{sd or '(不明)'} の SPF 確認中に DNS の一時エラーが発生しました")
    else:
        add("spf_none", f"{sd or 'エンベロープ送信者'} に SPF レコードがない、または評価されていません")

    # DKIM
    sigs = [(d.lower(), (r or "").lower()) for d, r in dkims if d]
    passed = [d for d, r in sigs if r == "pass"]
    if not sigs:
        add("dkim_none", "DKIM 署名が付いていません")
    elif passed and not any(_aligned(d, header_from, adkim) for d in passed):
        add("dkim_misaligned", f"DKIM 署名 ({', '.join(sorted(set(passed))[:3])}) は合格しましたが、From ({header_from}) とドメインが一致しません"
            + strict_note(adkim, passed[0]))
    elif not passed:
        failed = [d for d, r in sigs if r == "fail"]
        if failed:
            add("dkim_fail", f"{', '.join(sorted(set(failed))[:3])} の署名検証に失敗しました (転送・メーリングリストでの本文改変、または公開鍵の不一致)")
        else:
            d, r = sigs[0]
            add("dkim_error", f"{d} の DKIM を確認できませんでした ({r}: 公開鍵の DNS レコードが見つからない等)")
    if not out:
        # 認証結果上は一致しているのに、受信側は不合格と判定したケース (受信側のドメイン判定の差など)
        add("other", "認証結果からは原因を特定できません。受信側の評価では SPF / DKIM ともアライメント不合格です")
    return out


def override_reasons(reasons: str) -> List[str]:
    out = []
    for part in (reasons or "").split(";"):
        part = part.strip()
        if not part:
            continue
        typ, _, comment = part.partition(":")
        label = OVERRIDE_LABELS.get(typ.strip(), typ.strip())
        out.append(f"{label} ({typ.strip()})" + (f": {comment.strip()}" if comment.strip() else ""))
    return out


def _dkim_pairs(dkim_domains: str):
    return [tuple(x.rsplit(":", 1)) for x in (dkim_domains or "").split(",") if ":" in x]


def _where(domain: Optional[str], start: Optional[int], end: Optional[int]):
    sql, args = [], []
    if domain:
        sql.append("rp.domain = ?")
        args.append(domain)
    if start is not None:
        sql.append("rp.begin_ts >= ?")
        args.append(start)
    if end is not None:
        sql.append("rp.begin_ts < ?")
        args.append(end)
    return (" WHERE " + " AND ".join(sql)) if sql else "", args


def _rate(num: int, den: int) -> Optional[float]:
    return round(num * 100.0 / den, 2) if den else None


def domains(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT domain FROM reports ORDER BY domain")]


def dashboard(conn: sqlite3.Connection, domain: Optional[str] = None,
              start: Optional[int] = None, end: Optional[int] = None) -> Dict:
    where, args = _where(domain, start, end)
    base = f"FROM records r JOIN reports rp ON rp.id = r.report_pk{where}"

    k = conn.execute(f"""
        SELECT COALESCE(SUM(r.count),0) total,
               COALESCE(SUM(CASE WHEN r.dmarc_pass=1 THEN r.count END),0) pass,
               COALESCE(SUM(CASE WHEN r.spf_eval='pass' THEN r.count END),0) spf,
               COALESCE(SUM(CASE WHEN r.dkim_eval='pass' THEN r.count END),0) dkim,
               COALESCE(SUM(CASE WHEN r.disposition='quarantine' THEN r.count END),0) quarantine,
               COALESCE(SUM(CASE WHEN r.disposition='reject' THEN r.count END),0) reject,
               COUNT(DISTINCT r.source_ip) sources
        {base}""", args).fetchone()
    rk = conn.execute(f"SELECT COUNT(*), COUNT(DISTINCT rp.org_name), MIN(rp.begin_ts), MAX(rp.end_ts) "
                      f"FROM reports rp{where}", args).fetchone()
    total = k["total"]
    kpi = {
        "messages": total, "pass": k["pass"], "fail": total - k["pass"],
        "pass_rate": _rate(k["pass"], total),
        "spf_aligned_rate": _rate(k["spf"], total), "dkim_aligned_rate": _rate(k["dkim"], total),
        "quarantine": k["quarantine"], "reject": k["reject"], "sources": k["sources"],
        "reports": rk[0], "reporters": rk[1], "first_ts": rk[2], "last_ts": rk[3],
    }

    daily = [dict(row) for row in conn.execute(f"""
        SELECT date(rp.begin_ts, 'unixepoch', 'localtime') day,
               SUM(CASE WHEN r.dmarc_pass=1 THEN r.count ELSE 0 END) pass,
               SUM(CASE WHEN r.dmarc_pass=0 THEN r.count ELSE 0 END) fail
        {base} GROUP BY day ORDER BY day""", args)]

    auth_matrix = [dict(row) for row in conn.execute(f"""
        SELECT r.spf_eval spf, r.dkim_eval dkim, SUM(r.count) messages
        {base} GROUP BY r.spf_eval, r.dkim_eval""", args)]

    reporters = [dict(row) for row in conn.execute(f"""
        SELECT rp.org_name org, COUNT(DISTINCT rp.id) reports, SUM(r.count) messages,
               SUM(CASE WHEN r.dmarc_pass=1 THEN r.count ELSE 0 END) pass
        {base} GROUP BY rp.org_name ORDER BY messages DESC""", args)]

    # ドメイン別 (ポリシーは期間内で最新のレポートのもの)
    dom_rows = {}
    for row in conn.execute(f"""
        SELECT rp.domain, SUM(r.count) messages,
               SUM(CASE WHEN r.dmarc_pass=1 THEN r.count ELSE 0 END) pass,
               SUM(CASE WHEN r.spf_eval='pass' THEN r.count ELSE 0 END) spf,
               SUM(CASE WHEN r.dkim_eval='pass' THEN r.count ELSE 0 END) dkim
        {base} GROUP BY rp.domain ORDER BY messages DESC""", args):
        dom_rows[row["domain"]] = dict(row)
    for row in conn.execute(f"""
        SELECT rp.domain, rp.p, rp.sp, rp.pct, rp.adkim, rp.aspf, MAX(rp.begin_ts) latest, MAX(rp.end_ts) last_end
        FROM reports rp{where} GROUP BY rp.domain""", args):
        if row["domain"] in dom_rows:
            dom_rows[row["domain"]].update(p=row["p"], sp=row["sp"], pct=row["pct"],
                                           adkim=row["adkim"], aspf=row["aspf"], last_end=row["last_end"])
    domain_list = list(dom_rows.values())

    # ドメイン別の日次推移 (スパークライン用)
    dom_daily = defaultdict(list)
    for row in conn.execute(f"""
        SELECT rp.domain, date(rp.begin_ts, 'unixepoch', 'localtime') day,
               SUM(CASE WHEN r.dmarc_pass=1 THEN r.count ELSE 0 END) pass,
               SUM(CASE WHEN r.dmarc_pass=0 THEN r.count ELSE 0 END) fail
        {base} GROUP BY rp.domain, day ORDER BY day""", args):
        dom_daily[row["domain"]].append({"day": row["day"], "pass": row["pass"], "fail": row["fail"]})
    dom_errors = {row[0]: row[1] for row in conn.execute(
        f"SELECT rp.domain, COUNT(*) FROM reports rp{where}{' AND' if where else ' WHERE'} rp.errors NOT IN ('', '[]') "
        f"GROUP BY rp.domain", args)}

    # 送信元 IP 別 (全体の表示用と、ドメインごとの診断用を同時に集計する)
    src, dom_src = {}, defaultdict(dict)
    for row in conn.execute(f"""
        SELECT rp.domain, r.source_ip ip, r.count, r.dmarc_pass, r.spf_eval, r.dkim_eval, r.disposition,
               r.header_from, r.envelope_from, r.spf_domain, r.spf_result, r.dkim_domains,
               rp.adkim, rp.aspf, COALESCE(i.ptr, '') ptr
        FROM records r JOIN reports rp ON rp.id = r.report_pk
        LEFT JOIN ip_info i ON i.ip = r.source_ip{where}""", args):
        _accumulate(src, row)
        _accumulate(dom_src[row["domain"]], row)
    sources = _finish_sources(src)

    ins = []
    for d in domain_list:
        name = d["domain"]
        items = domain_insights(d, _finish_sources(dom_src[name]), dom_daily[name],
                                dom_errors.get(name, 0), end)
        d["daily"] = dom_daily[name]
        d["issues"] = {sev: sum(1 for i in items if i["severity"] == sev)
                       for sev in ("critical", "serious", "warning")}
        ins.extend(items)
    ins.sort(key=lambda o: SEVERITY_ORDER[o["severity"]])  # 安定ソート: 同じ重要度内はメッセージ数の多いドメイン順
    if not total:
        ins = [{"severity": "info", "domain": None, "title": "データがありません",
                "detail": "レポートを取り込むとここに診断結果が表示されます。"}]

    reports = [dict(row) for row in conn.execute(f"""
        SELECT rp.id, rp.org_name, rp.report_id, rp.domain, rp.begin_ts, rp.end_ts, rp.p, rp.errors,
               (SELECT SUM(count) FROM records WHERE report_pk = rp.id) messages,
               (SELECT SUM(count) FROM records WHERE report_pk = rp.id AND dmarc_pass = 1) pass
        FROM reports rp{where} ORDER BY rp.begin_ts DESC LIMIT 200""", args)]
    for r in reports:
        r["errors"] = json.loads(r["errors"] or "[]")

    return {
        "filter": {"domain": domain, "start": start, "end": end},
        "kpi": kpi, "daily": daily, "auth_matrix": auth_matrix, "reporters": reporters,
        "domains": domain_list, "sources": sources[:300], "reports": reports,
        "insights": ins,
    }


def _accumulate(src: Dict, row) -> None:
    s = src.setdefault(row["ip"], {
        "ip": row["ip"], "ptr": row["ptr"], "provider": provider_of(row["ptr"]),
        "messages": 0, "pass": 0, "spf_aligned": 0, "dkim_aligned": 0,
        "spf_raw_pass": 0, "dkim_raw_pass": 0, "header_from": set(), "spf_domains": set(),
        "dkim_domains": set(), "quarantine": 0, "reject": 0, "fail_reasons": defaultdict(int),
    })
    c = row["count"]
    if not row["dmarc_pass"]:
        for f in failure_reasons(row["header_from"], row["spf_eval"], row["dkim_eval"],
                                 (row["spf_domain"], row["spf_result"]), _dkim_pairs(row["dkim_domains"]),
                                 row["adkim"], row["aspf"], row["envelope_from"]):
            s["fail_reasons"][f["code"]] += c
    s["messages"] += c
    s["pass"] += c if row["dmarc_pass"] else 0
    s["spf_aligned"] += c if row["spf_eval"] == "pass" else 0
    s["dkim_aligned"] += c if row["dkim_eval"] == "pass" else 0
    s["spf_raw_pass"] += c if row["spf_result"] == "pass" else 0
    s["dkim_raw_pass"] += c if ":pass" in (row["dkim_domains"] or "") else 0
    s["quarantine"] += c if row["disposition"] == "quarantine" else 0
    s["reject"] += c if row["disposition"] == "reject" else 0
    if row["header_from"]:
        s["header_from"].add(row["header_from"])
    if row["spf_domain"]:
        s["spf_domains"].add(row["spf_domain"])
    for d in (row["dkim_domains"] or "").split(","):
        if d:
            s["dkim_domains"].add(d.rsplit(":", 1)[0])


def _finish_sources(src: Dict) -> List[Dict]:
    out = []
    for s in src.values():
        s = dict(s)
        s["fail"] = s["messages"] - s["pass"]
        s["pass_rate"] = _rate(s["pass"], s["messages"])
        s["status"] = _source_status(s)
        for key in ("header_from", "spf_domains", "dkim_domains"):
            s[key] = sorted(s[key])
        s["fail_reasons"] = [{"code": k, "label": FAILURE_LABELS[k], "messages": v}
                             for k, v in sorted(s["fail_reasons"].items(), key=lambda kv: -kv[1])]
        out.append(s)
    out.sort(key=lambda s: -s["messages"])
    return out


def _source_status(s: Dict) -> str:
    rate = s["pass"] / s["messages"] if s["messages"] else 0
    if rate >= 0.98:
        return "ok"
    if s["spf_raw_pass"] or s["dkim_raw_pass"]:
        return "misaligned"  # 認証自体は通るがドメインが一致していない → 設定不備の正規送信元の可能性
    if rate > 0:
        return "partial"
    return "unauthenticated"  # なりすまし / 未設定の送信元の可能性


def record_details(conn: sqlite3.Connection, ip: str, domain: Optional[str] = None,
                   start: Optional[int] = None, end: Optional[int] = None) -> List[Dict]:
    where, args = _where(domain, start, end)
    where = (where + " AND " if where else " WHERE ") + "r.source_ip = ?"
    rows = conn.execute(f"""
        SELECT rp.org_name, rp.begin_ts, rp.end_ts, rp.domain, r.count, r.disposition, r.dkim_eval,
               r.spf_eval, r.header_from, r.envelope_from, r.reasons, r.auth_json, rp.adkim, rp.aspf
        FROM records r JOIN reports rp ON rp.id = r.report_pk{where}
        ORDER BY rp.begin_ts DESC LIMIT 500""", args + [ip])
    out = []
    for row in rows:
        d = dict(row)
        d["auth"] = json.loads(d.pop("auth_json") or "[]")
        spf = next(((a["domain"], a["result"]) for a in d["auth"] if a["kind"] == "spf"), None)
        dkims = [(a["domain"], a["result"]) for a in d["auth"] if a["kind"] == "dkim"]
        d["failures"] = failure_reasons(d["header_from"], d["spf_eval"], d["dkim_eval"], spf, dkims,
                                        d.pop("adkim") or "r", d.pop("aspf") or "r", d["envelope_from"])
        d["overrides"] = override_reasons(d["reasons"])
        out.append(d)
    return out


SEVERITY_ORDER = {"critical": 0, "serious": 1, "warning": 2, "good": 3, "info": 4}


def domain_insights(d: Dict, sources: List[Dict], daily: List[Dict], error_reports: int,
                    end: Optional[int]) -> List[Dict]:
    """1 ドメイン分の状況から推奨アクションを生成する。
    severity: critical / serious / warning / good / info"""
    out = []
    name = d["domain"]

    def add(sev, title, detail):
        out.append({"severity": sev, "domain": name, "title": title, "detail": detail})

    total = d["messages"]
    if not total:
        return out
    rate = d["pass"] / total
    p = d.get("p") or "none"
    if p == "none":
        if rate >= 0.98 and total >= 100:
            add("good", "ポリシー強化を検討できます",
                f"DMARC 合格率 {rate*100:.1f}% と安定しています。p=none から p=quarantine (まずは pct を段階的に) への引き上げを検討してください。")
        else:
            add("warning", "p=none のため、なりすましメールは素通りします",
                f"合格率 {rate*100:.1f}%。「送信元」で失敗している正規の送信サービスを特定し、SPF/DKIM を整備してからポリシーを強化してください。")
    elif p in ("quarantine", "reject") and rate < 0.95:
        add("serious", f"p={p} で正規メールが隔離/拒否されている可能性",
            f"合格率 {rate*100:.1f}%。失敗している送信元に社内・委託先のサービスが含まれていないか確認してください。")
    if (d.get("pct") or 100) < 100:
        add("info", f"pct={d['pct']} が設定されています",
            "ポリシーは一部のメールにのみ適用されています。問題がなければ 100 に引き上げましょう。")
    if end is None and d.get("last_end") and d["last_end"] < time.time() - 4 * 86400:
        add("warning", "直近 4 日以上レポートが届いていません",
            "rua の宛先設定や取り込み処理 (IMAP 取得) が止まっていないか確認してください。")

    threshold = max(10, total * 0.005)
    mis = [s for s in sources if s["status"] == "misaligned" and s["fail"] >= threshold]
    for s in mis[:5]:
        label = s["provider"] or s["ptr"] or s["ip"]
        own = {org_domain(h) for h in s["header_from"]}
        foreign_spf = [x for x in s["spf_domains"] if org_domain(x) not in own]
        foreign_dkim = [x for x in s["dkim_domains"] if org_domain(x) not in own]
        hints = []
        if s["spf_raw_pass"] > s["spf_aligned"] and foreign_spf:
            hints.append(f"SPF は {', '.join(foreign_spf[:3])} で合格しているが From ドメインと不一致 (Return-Path を自ドメインに設定)")
        if s["dkim_raw_pass"] > s["dkim_aligned"] and foreign_dkim:
            hints.append(f"DKIM 署名ドメインが {', '.join(foreign_dkim[:3])} (自ドメインでの DKIM 署名を設定)")
        add("serious", f"{label}: 認証は通るがアラインメント失敗 ({s['fail']:,} 通)",
            "正規の送信サービスの設定不備の可能性が高いです。" + " / ".join(hints))

    unauth = [s for s in sources if s["status"] == "unauthenticated"]
    unauth_msgs = sum(s["messages"] for s in unauth)
    if unauth_msgs:
        big = [s for s in unauth if s["messages"] >= threshold]
        sev = "critical" if unauth_msgs >= total * 0.05 else "warning"
        add(sev, f"SPF/DKIM とも失敗している送信元: {len(unauth)} 件 ({unauth_msgs:,} 通)",
            "なりすまし、または未設定の送信元です。" +
            ("主な送信元: " + ", ".join(s["ptr"] or s["ip"] for s in big[:5]) + "。" if big else "") +
            "心当たりのないものはポリシー強化で遮断できます。")

    fwd = [s for s in sources if s["dkim_aligned"] and not s["spf_aligned"] and s["pass"] == s["messages"]]
    if fwd:
        add("info", f"DKIM のみで合格している送信元: {len(fwd)} 件",
            "転送やメーリングリスト経由の典型パターンです。DKIM が維持されていれば問題ありません。")

    if len(daily) >= 14:
        def r(rows):
            t = sum(x["pass"] + x["fail"] for x in rows)
            return (sum(x["pass"] for x in rows) / t) if t else None
        cur, prev = r(daily[-7:]), r(daily[-14:-7])
        if cur is not None and prev is not None and prev - cur >= 0.05:
            add("serious", "直近 7 日で合格率が低下しています",
                f"{prev*100:.1f}% → {cur*100:.1f}%。新しい送信サービスの追加や DNS 変更がなかったか確認してください。")

    if error_reports:
        add("info", f"エラー付きのレポート: {error_reports} 件",
            "レポーターが DNS レコードの取得等でエラーを報告しています。レポート一覧で内容を確認できます。")

    if rate >= 0.99 and not any(o["severity"] in ("critical", "serious", "good") for o in out):
        add("good", "認証状況は良好です", f"DMARC 合格率は {rate*100:.1f}% です。")

    out.sort(key=lambda o: SEVERITY_ORDER[o["severity"]])
    return out
