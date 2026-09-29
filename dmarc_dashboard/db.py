"""SQLite への保存。"""

import json
import sqlite3
import time
from typing import Iterable

from .parser import Report

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY,
    org_name    TEXT NOT NULL,
    email       TEXT,
    report_id   TEXT NOT NULL,
    begin_ts    INTEGER NOT NULL,
    end_ts      INTEGER NOT NULL,
    domain      TEXT NOT NULL,
    adkim       TEXT, aspf TEXT, p TEXT, sp TEXT, pct INTEGER, fo TEXT,
    errors      TEXT,
    source      TEXT,
    imported_at INTEGER NOT NULL,
    UNIQUE (org_name, report_id)
);
CREATE INDEX IF NOT EXISTS idx_reports_domain_begin ON reports (domain, begin_ts);

CREATE TABLE IF NOT EXISTS records (
    id            INTEGER PRIMARY KEY,
    report_pk     INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    source_ip     TEXT NOT NULL,
    count         INTEGER NOT NULL,
    disposition   TEXT,
    dkim_eval     TEXT,
    spf_eval      TEXT,
    dmarc_pass    INTEGER NOT NULL,
    header_from   TEXT,
    envelope_from TEXT,
    envelope_to   TEXT,
    reasons       TEXT,
    dkim_domains  TEXT,  -- "domain:result" をカンマ区切り
    dkim_result   TEXT,  -- 最初の DKIM 署名の生結果
    spf_domain    TEXT,
    spf_result    TEXT,  -- 生の SPF 結果
    auth_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_records_report ON records (report_pk);
CREATE INDEX IF NOT EXISTS idx_records_ip ON records (source_ip);

CREATE TABLE IF NOT EXISTS ip_info (
    ip          TEXT PRIMARY KEY,
    ptr         TEXT,
    resolved_at INTEGER
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    return conn


def save_report(conn: sqlite3.Connection, report: Report, source: str = "") -> bool:
    """レポートを保存する。既に同じ (org_name, report_id) があれば False。"""
    with conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO reports
               (org_name, email, report_id, begin_ts, end_ts, domain, adkim, aspf, p, sp, pct, fo,
                errors, source, imported_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (report.org_name, report.email, report.report_id, report.begin_ts, report.end_ts,
             report.domain, report.adkim, report.aspf, report.p, report.sp, report.pct, report.fo,
             json.dumps(report.errors, ensure_ascii=False), source, int(time.time())),
        )
        if cur.rowcount == 0:
            return False
        pk = cur.lastrowid
        rows = []
        for r in report.records:
            dkims = [a for a in r.auth_results if a.kind == "dkim"]
            spfs = [a for a in r.auth_results if a.kind == "spf"]
            rows.append((
                pk, r.source_ip, r.count, r.disposition, r.dkim_eval, r.spf_eval, int(r.dmarc_pass),
                r.header_from, r.envelope_from, r.envelope_to, "; ".join(r.reasons),
                ",".join(f"{d.domain}:{d.result}" for d in dkims),
                dkims[0].result if dkims else "none",
                spfs[0].domain if spfs else "",
                spfs[0].result if spfs else "none",
                json.dumps([a.__dict__ for a in r.auth_results], ensure_ascii=False),
            ))
        conn.executemany(
            """INSERT INTO records
               (report_pk, source_ip, count, disposition, dkim_eval, spf_eval, dmarc_pass,
                header_from, envelope_from, envelope_to, reasons, dkim_domains, dkim_result,
                spf_domain, spf_result, auth_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
    return True


def unresolved_ips(conn: sqlite3.Connection) -> Iterable[str]:
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT source_ip FROM records WHERE source_ip NOT IN (SELECT ip FROM ip_info)"
    )]


def save_ptr(conn: sqlite3.Connection, ip: str, ptr: str) -> None:
    with conn:
        conn.execute("INSERT OR REPLACE INTO ip_info (ip, ptr, resolved_at) VALUES (?,?,?)",
                     (ip, ptr, int(time.time())))
