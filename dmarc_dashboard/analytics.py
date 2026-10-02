"""ダッシュボード用の集計と、自動診断 (インサイト) の生成。"""

import json
import sqlite3
import time
from collections import defaultdict
from typing import Dict, List, Optional

from . import advice

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
    "spf_helo": "SPF: エラーメール/自動返信",
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

    spf: (domain, result, scope) または None。scope は mfrom / helo / 空 (記載なし)
    dkims: [(domain, result), ...]
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
    sd, sr, scope = (tuple(spf) + ("", "", ""))[:3] if spf else ("", "none", "")
    sd = (sd or envelope_from or "").lower()
    sr = (sr or "none").lower()
    scope = (scope or "").lower()
    if scope == "helo":
        where = f"送信サーバー名 (HELO: {sd or '不明'})"
    elif scope == "mfrom" or envelope_from:
        where = f"Envelope From (Return-Path) のドメイン {sd or '(不明)'}"
    else:
        where = sd or "(不明)"
    if sr == "pass":
        if not _aligned(sd, header_from, aspf):
            if scope == "helo":
                add("spf_helo", f"Envelope From が空のメール (エラーメール・自動返信など) のため、SPF は{where}で検査されて合格しましたが、"
                                f"From ({header_from}) とドメインが一致しません")
            else:
                add("spf_misaligned", f"SPF は {where} で合格しましたが、From ({header_from}) とドメインが一致しません"
                    + strict_note(aspf, sd))
    elif sr in ("fail", "softfail", "neutral"):
        add("spf_fail", f"送信元 IP が {where} の SPF レコードで許可されていません ({sr})")
    elif sr == "permerror":
        add("spf_error", f"{where} の SPF レコードに誤りがあります (構文誤り、または DNS 参照 10 回の上限超過)")
    elif sr == "temperror":
        add("spf_error", f"{where} の SPF 確認中に DNS の一時エラーが発生しました")
    else:
        add("spf_none", f"{where if sd else 'エンベロープ送信者'} に SPF レコードがない、または評価されていません")

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
               r.header_from, r.envelope_from, r.spf_domain, r.spf_result, r.spf_scope, r.dkim_domains,
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
        ins = [{"severity": "info", "domain": None, "kind": "empty", "title": "データがありません",
                "detail": "レポートを取り込むと、ここに診断結果が表示されます。", "why": "", "actions": [], "target": None}]

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
        "glossary": advice.GLOSSARY,
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
                                 (row["spf_domain"], row["spf_result"], row["spf_scope"]), _dkim_pairs(row["dkim_domains"]),
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
        for key in ("header_from", "spf_domains", "dkim_domains"):
            s[key] = sorted(s[key])
        fr = [{"code": k, "label": FAILURE_LABELS[k], "messages": v, "help": advice.FAILURE_HELP[k]}
              for k, v in sorted(s["fail_reasons"].items(), key=lambda kv: -kv[1])]
        s["fail_reasons"] = fr
        s["status"] = _source_status(s)
        if s["status"] != "ok" and fr and fr[0]["code"] == "spf_helo" and fr[0]["messages"] >= s["fail"] * 0.5:
            s["status"] = "bounce"  # 失敗の大半がエラーメール / 自動返信
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
                   start: Optional[int] = None, end: Optional[int] = None) -> Dict:
    """送信元 1 件の詳細: 総評 (状態・失敗理由ごとの説明と対策) と、レポートの行。"""
    where, args = _where(domain, start, end)
    where = (where + " AND " if where else " WHERE ") + "r.source_ip = ?"
    src = {}
    for row in conn.execute(f"""
        SELECT r.source_ip ip, r.count, r.dmarc_pass, r.spf_eval, r.dkim_eval, r.disposition,
               r.header_from, r.envelope_from, r.spf_domain, r.spf_result, r.spf_scope, r.dkim_domains,
               rp.adkim, rp.aspf, COALESCE(i.ptr, '') ptr
        FROM records r JOIN reports rp ON rp.id = r.report_pk
        LEFT JOIN ip_info i ON i.ip = r.source_ip{where}""", args + [ip]):
        _accumulate(src, row)
    summary = _finish_sources(src)
    summary = summary[0] if summary else None
    if summary:
        summary["status_help"] = advice.STATUS_HELP[summary["status"]]
        summary["provider_hint"] = advice.provider_hint(summary["provider"]) if summary["fail"] else ""

    rows = conn.execute(f"""
        SELECT rp.org_name, rp.begin_ts, rp.end_ts, rp.domain, r.count, r.disposition, r.dkim_eval,
               r.spf_eval, r.header_from, r.envelope_from, r.spf_domain, r.spf_scope, r.reasons,
               r.auth_json, rp.adkim, rp.aspf
        FROM records r JOIN reports rp ON rp.id = r.report_pk{where}
        ORDER BY r.dmarc_pass, rp.begin_ts DESC LIMIT 500""", args + [ip])  # 失敗した行を先に
    out = []
    for row in rows:
        d = dict(row)
        d["auth"] = json.loads(d.pop("auth_json") or "[]")
        spf = next(((a["domain"], a["result"], a.get("scope", "")) for a in d["auth"] if a["kind"] == "spf"), None)
        dkims = [(a["domain"], a["result"]) for a in d["auth"] if a["kind"] == "dkim"]
        d["failures"] = failure_reasons(d["header_from"], d["spf_eval"], d["dkim_eval"], spf, dkims,
                                        d.pop("adkim") or "r", d.pop("aspf") or "r", d["envelope_from"])
        d["overrides"] = override_reasons(d["reasons"])
        out.append(d)
    return {"summary": summary, "records": out}


SEVERITY_ORDER = {"critical": 0, "serious": 1, "warning": 2, "good": 3, "info": 4}


def domain_insights(d: Dict, sources: List[Dict], daily: List[Dict], error_reports: int,
                    end: Optional[int]) -> List[Dict]:
    """1 ドメイン分の状況から、推奨アクションを生成する。

    各項目: severity (critical / serious / warning / good / info), domain, kind, title,
            detail (要約), why (理由), actions [{title, detail}], target (画面での参照先)
    """
    out = []
    name = d["domain"]

    def add(sev, kind, title, detail, why, actions, target=None):
        out.append({"severity": sev, "domain": name, "kind": kind, "title": title, "detail": detail,
                    "why": why, "actions": actions, "target": target})

    total = d["messages"]
    if not total:
        return out
    rate = d["pass"] / total
    p = d.get("p") or "none"
    dmarc_txt = f"_dmarc.{name}"
    step_find = {"title": "手順 1: 失敗している送信元を確認する",
                 "detail": "下の「送信元」一覧を「失敗あり」で絞り込み、件数の多い順に、自社や委託先が使っているサービスかどうかを確認します。"
                           "行をクリックすると、その送信元の失敗理由と対策が表示されます。"}

    # ---- ポリシー ----
    if p == "none":
        if rate >= 0.98 and total >= 100:
            add("good", "policy_ready", "ポリシーの強化を検討できます",
                f"DMARC 合格率が {rate*100:.1f}% で安定しています。",
                "今の p=none は「監視するだけ」の設定なので、なりすましメールも受信者に届いてしまいます。"
                "正規のメールがほぼすべて合格している今なら、ポリシーを強めても正規のメールへの影響は小さいと考えられます。",
                [{"title": "手順 1: まず一部のメールだけ迷惑メール扱いにする",
                  "detail": f"DNS の {dmarc_txt} の TXT レコードを「v=DMARC1; p=quarantine; pct=25; rua=mailto:(今の宛先)」のように変更します。"
                            "pct=25 は「失敗したメールの 25% だけに適用する」という意味で、影響を確かめながら進められます。"},
                 {"title": "手順 2: 様子を見ながら広げる",
                  "detail": "1〜2 週間ごとにこの画面で合格率を確認し、問題がなければ pct=50 → pct=100 と上げていきます。"},
                 {"title": "手順 3: 最終的には reject (受信拒否) にする",
                  "detail": "quarantine (pct=100) で問題が出なければ p=reject にします。なりすましメールを受信側で確実に止められるようになります。"},
                 {"title": "注意",
                  "detail": "変更する前に、「送信元」一覧の失敗している送信元に、自社や委託先のサービスが残っていないか確認してください。"
                            "残っていると、強化した後はそのメールが迷惑メールフォルダに入るようになります。"}])
        else:
            add("warning", "policy_none", "p=none のため、なりすましメールは素通りします",
                f"合格率は {rate*100:.1f}% です。失敗しているメールの中に、正規の送信元が残っています。",
                "p=none は監視だけの設定で、DMARC に失敗したメールも普通に配信されます。"
                "ただし、正規のメールが失敗している状態でポリシーを強めると、そのメールが届かなくなります。まず正規の送信元を直す必要があります。",
                [step_find,
                 {"title": "手順 2: 正規の送信元を直す",
                  "detail": "「設定不備疑い」の送信元は、そのサービスで自社ドメインの DKIM を設定すれば合格するようになります。"
                            "自社のサーバーなのに「なりすまし疑い」になっているものは、SPF への登録と DKIM 署名が必要です。"},
                 {"title": "手順 3: 合格率 98% 以上を目安にポリシーを強化する",
                  "detail": "正規の送信元が直ると合格率が上がります。安定すると、この診断が「ポリシーの強化を検討できます」に変わります。"}],
                {"filter": "fail"})
    elif rate < 0.95:
        verb = "迷惑メールフォルダに入れられ" if p == "quarantine" else "受信を拒否され"
        add("serious", "policy_blocking", f"p={p} の設定で、正規のメールが{'隔離' if p == 'quarantine' else '拒否'}されている可能性があります",
            f"合格率は {rate*100:.1f}% です。",
            f"p={p} では、DMARC に失敗したメールは受信側で{verb}ます。"
            "失敗している送信元に自社や委託先のサービスが含まれていると、そのメールが相手に届いていない可能性があります。",
            [step_find,
             {"title": "手順 2: 正規の送信元なら、すぐに設定を直す",
              "detail": "送信元の行をクリックすると、失敗の理由と対策が表示されます。多くの場合、送信サービスで自社ドメインの DKIM を設定すれば解決します。"},
             {"title": "急ぎの場合: 一時的にポリシーを緩める",
              "detail": f"業務への影響が大きい場合は、直すまでの間だけ {dmarc_txt} を p=none にする、または pct を小さくすることも検討してください。"
                        "なりすまし対策は弱まるので、直したら元に戻します。"}],
            {"filter": "fail"})
    if (d.get("pct") or 100) < 100:
        add("info", "pct", f"pct={d['pct']} が設定されています",
            "ポリシーは、失敗したメールの一部にだけ適用されています。",
            "pct はポリシーを段階的に導入するための設定です。適用されなかった残りのメールは、p=none と同じく普通に配信されます。",
            [{"title": "問題がなければ 100 にする",
              "detail": f"合格率が安定していれば、{dmarc_txt} の pct を 100 にする (または pct の記述を削除する) と、すべての失敗メールに適用されます。"}])
    if end is None and d.get("last_end") and d["last_end"] < time.time() - 4 * 86400:
        last = time.strftime("%Y/%m/%d", time.localtime(d["last_end"]))
        add("warning", "stale", "4 日以上レポートが届いていません",
            f"最後に受け取ったレポートは {last} 分です。",
            "通常、Google や Microsoft などからは毎日レポートが届きます。届かない場合は、DMARC の DNS 設定か、このシステムのメール取得が止まっている可能性があります。"
            "(このドメインからメールをほとんど送っていない場合は、届かないのが正常なこともあります)",
            [{"title": "確認 1: DMARC の DNS レコード",
              "detail": f"{dmarc_txt} の TXT レコードが残っていて、rua=mailto: の宛先が正しいかを確認します。"},
             {"title": "確認 2: レポート受信用のメールボックス",
              "detail": "メールボックスにレポートが届いているか、容量オーバーや迷惑メールフォルダへの振り分けがないかを確認します。"},
             {"title": "確認 3: このシステムの取り込み処理",
              "detail": "サーバーで「journalctl -u dmarc-dashboard」を実行し、IMAP 取得のエラーが出ていないかを確認します。"}])

    # ---- 送信元 ----
    threshold = max(10, total * 0.005)
    mis = [s for s in sources if s["status"] == "misaligned" and s["fail"] >= threshold]
    for s in mis[:5]:
        label = s["provider"] or s["ptr"] or s["ip"]
        own = {org_domain(h) for h in s["header_from"]}
        foreign = sorted({x for x in s["spf_domains"] + s["dkim_domains"] if org_domain(x) not in own})
        hint = advice.provider_hint(s["provider"])
        dkim_fix = advice.FAILURE_HELP["dkim_misaligned"]["actions"][0]["detail"]
        actions = [
            {"title": "対策 1 (おすすめ): 自社ドメインで DKIM 署名する",
             "detail": (hint + " " if hint else "") + dkim_fix},
            advice.FAILURE_HELP["spf_misaligned"]["actions"][1],
            advice.FAILURE_HELP["spf_misaligned"]["actions"][2],
        ]
        add("serious", "source_misaligned", f"{label}: 認証は通っているのに、ドメインが一致していません ({s['fail']:,} 通)",
            f"送信元 {s['ip']} ({s['ptr'] or '逆引きなし'}) からの {s['fail']:,} 通が DMARC に失敗しています。",
            advice.STATUS_HELP["misaligned"] +
            (f"このサービスは、SPF / DKIM の認証に {', '.join(foreign[:3])} のドメインを使っているため、From の {name} としては合格になりません。" if foreign else ""),
            actions, {"ip": s["ip"]})

    bounce = [s for s in sources if s["status"] == "bounce" and s["fail"] >= threshold]
    for s in bounce[:3]:
        label = s["provider"] or s["ptr"] or s["ip"]
        h = advice.FAILURE_HELP["spf_helo"]
        add("warning", "source_bounce", f"{label}: エラーメール・自動返信が DMARC に失敗しています ({s['fail']:,} 通)",
            f"送信元 {s['ip']} ({s['ptr'] or '逆引きなし'}) からの、Envelope From が空のメールです。",
            h["what"] + h["why"], h["actions"], {"ip": s["ip"]})

    unauth = [s for s in sources if s["status"] == "unauthenticated"]
    unauth_msgs = sum(s["messages"] for s in unauth)
    if unauth_msgs:
        big = [s for s in unauth if s["messages"] >= threshold]
        if p == "reject":
            sev, tail = "info", "すでに p=reject なので、これらのメールは受信側で拒否されています。自社の送信元でなければ、対応は不要です。"
        elif p == "quarantine":
            sev, tail = "warning", "p=quarantine なので、これらのメールは受信側で迷惑メール扱いになっています。なりすましを確実に止めるには、p=reject への強化を検討してください。"
        else:
            sev = "critical" if unauth_msgs >= total * 0.05 else "warning"
            tail = "今は p=none なので、これらのメールは受信者に普通に届いています。"
        add(sev, "source_unauth", f"SPF も DKIM も通っていない送信元が {len(unauth)} 件あります ({unauth_msgs:,} 通)",
            ("主な送信元: " + ", ".join(s["ptr"] or s["ip"] for s in big[:5]) + "。" if big else "") + tail,
            advice.STATUS_HELP["unauthenticated"] +
            "受信者には自社のドメインから届いたように見えるため、フィッシング詐欺などに悪用されるおそれがあります。",
            [{"title": "判断: 送信元を 1 つずつ確認する",
              "detail": "「送信元」一覧を「なりすまし疑い」で絞り込み、ホスト名 (PTR) から、自社や委託先のサーバーかどうかを確認します。"},
             {"title": "自社のサーバーだった場合",
              "detail": "SPF レコードへの追加と DKIM 署名の設定が必要です。送信元の行をクリックすると、詳しい手順が表示されます。"},
             {"title": "心当たりがない場合 (なりすまし)",
              "detail": "送信元を直接止めることはできませんが、受信側で止めてもらえます。正規の送信元をすべて直したうえで、"
                        f"{dmarc_txt} のポリシーを quarantine → reject と強化してください。SPF に追加してはいけません。"}],
            {"filter": "unauthenticated"})

    fwd = [s for s in sources if s["dkim_aligned"] and not s["spf_aligned"] and s["pass"] == s["messages"]]
    if fwd:
        add("info", "dkim_only", f"DKIM だけで合格している送信元が {len(fwd)} 件あります",
            "転送やメーリングリスト経由のメールによく見られるパターンです。",
            "メールが転送されると、転送サーバーの IP で SPF が検査されるため、SPF は失敗します。"
            "DKIM の署名は転送されても残るので、DMARC には合格できています。",
            [{"title": "対応は不要です",
              "detail": "DKIM が合格していれば問題ありません。このように SPF が使えない場面があるため、すべての送信元で DKIM 署名を設定しておくことが大切です。"}])

    # ---- 推移・レポート ----
    if len(daily) >= 14:
        def r(rows):
            t = sum(x["pass"] + x["fail"] for x in rows)
            return (sum(x["pass"] for x in rows) / t) if t else None
        cur, prev = r(daily[-7:]), r(daily[-14:-7])
        if cur is not None and prev is not None and prev - cur >= 0.05:
            add("serious", "rate_drop", "直近 7 日で合格率が下がっています",
                f"{prev*100:.1f}% → {cur*100:.1f}% に下がりました。",
                "新しく使い始めた配信サービス、DNS (SPF / DKIM) の変更や削除、なりすましの増加などで、合格率は下がります。",
                [{"title": "確認 1: 最近増えた送信元",
                  "detail": "画面上部の期間を「7日」にして「送信元」一覧を見ると、最近失敗している送信元が分かります。"},
                 {"title": "確認 2: DNS の変更",
                  "detail": "最近 SPF や DKIM の DNS レコードを変更・削除していないかを、DNS の管理者に確認します。"}],
                {"filter": "fail"})

    if error_reports:
        add("info", "report_errors", f"エラー付きのレポートが {error_reports} 件あります",
            "受信側が、レポートにエラーを書き添えています。",
            "受信側が DMARC レコードの読み取りなどで問題を見つけると、レポートにエラーを書き添えることがあります。",
            [{"title": "内容を確認する",
              "detail": f"「受信したレポート」一覧の「エラー」欄で内容を確認してください。同じエラーが続く場合は、{dmarc_txt} の TXT レコードの書き方を見直します。"}])

    if rate >= 0.99 and not any(o["severity"] in ("critical", "serious", "good") for o in out):
        nxt = ({"title": "次のステップ: reject まで強化する",
                "detail": f"{dmarc_txt} を p=reject にすると、なりすましメールを受信側で確実に拒否できます。"}
               if p != "reject" else
               {"title": "引き続き監視する",
                "detail": "新しい配信サービスを使い始めたときは、ここでそのメールが合格しているかを確認してください。"})
        add("good", "healthy", "認証状況は良好です", f"DMARC 合格率は {rate*100:.1f}% です。",
            "正規のメールのほとんどが DMARC に合格しています。", [nxt])

    out.sort(key=lambda o: SEVERITY_ORDER[o["severity"]])
    return out
