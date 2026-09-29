"""ファイル / IMAP からの取り込みと、送信元 IP の逆引き。"""

import imaplib
import logging
import os
import socket
import ssl
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from . import db
from .parser import ReportParseError, parse_any, parse_mail

log = logging.getLogger(__name__)


@dataclass
class ImportStats:
    imported: int = 0
    duplicates: int = 0
    errors: List[str] = field(default_factory=list)

    def merge(self, other: "ImportStats") -> None:
        self.imported += other.imported
        self.duplicates += other.duplicates
        self.errors.extend(other.errors)

    def __str__(self) -> str:
        return f"取り込み {self.imported} 件 / 重複 {self.duplicates} 件 / エラー {len(self.errors)} 件"


def import_bytes(conn: sqlite3.Connection, data: bytes, name: str, mail: bool = False) -> ImportStats:
    stats = ImportStats()
    try:
        reports = parse_mail(data) if mail else parse_any(data, name)
    except ReportParseError as e:
        stats.errors.append(f"{name}: {e}")
        return stats
    if not reports:
        stats.errors.append(f"{name}: DMARC レポートが見つかりません")
    for rep in reports:
        if db.save_report(conn, rep, source=name):
            stats.imported += 1
        else:
            stats.duplicates += 1
    return stats


def import_paths(conn: sqlite3.Connection, paths: List[str]) -> ImportStats:
    stats = ImportStats()
    for p in paths:
        path = Path(p)
        files = sorted(f for f in path.rglob("*") if f.is_file()) if path.is_dir() else [path]
        for f in files:
            stats.merge(import_bytes(conn, f.read_bytes(), str(f)))
    return stats


def fetch_imap(conn: sqlite3.Connection, cfg) -> ImportStats:
    """IMAP のメールボックスからレポートメールを取り込む。

    取り込めたメールは既読にし、processed_folder が設定されていればそこへ移動する。
    解析に失敗したメールは未読のまま残す (次回再試行・手動確認のため)。
    """
    folder = cfg.get("imap", "folder", fallback="INBOX")
    processed = cfg.get("imap", "processed_folder", fallback="").strip()
    criteria = cfg.get("imap", "search", fallback="UNSEEN")

    stats = ImportStats()
    M = _imap_login(cfg)
    try:
        typ, _ = M.select(_quote(folder))
        if typ != "OK":
            raise RuntimeError(f"フォルダを開けません: {folder}")
        typ, data = M.uid("SEARCH", None, criteria)
        uids = data[0].split() if typ == "OK" and data and data[0] else []
        log.info("IMAP: %d 通の対象メール", len(uids))
        done = []
        for uid in uids:
            typ, msg = M.uid("FETCH", uid, "(BODY.PEEK[])")
            if typ != "OK" or not msg or not isinstance(msg[0], tuple):
                stats.errors.append(f"UID {uid.decode()}: 取得失敗")
                continue
            s = import_bytes(conn, msg[0][1], f"imap:{folder}:{uid.decode()}", mail=True)
            stats.merge(s)
            if not s.errors:
                done.append(uid)
        for uid in done:
            M.uid("STORE", uid, "+FLAGS", r"(\Seen)")
            if processed:
                typ, _ = M.uid("COPY", uid, _quote(processed))
                if typ == "OK":
                    M.uid("STORE", uid, "+FLAGS", r"(\Deleted)")
        if processed and done:
            M.expunge()
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return stats


def _imap_login(cfg) -> imaplib.IMAP4:
    host = cfg.get("imap", "host")
    port = cfg.getint("imap", "port", fallback=993)
    user = cfg.get("imap", "user")
    password = os.environ.get("DMARC_IMAP_PASSWORD") or cfg.get("imap", "password", fallback="")
    if cfg.getboolean("imap", "ssl", fallback=True):
        # imaplib の既定はサーバー証明書を検証しないため、検証ありのコンテキストを明示する
        M = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
    else:
        M = imaplib.IMAP4(host, port)
    M.login(user, password)
    return M


def list_imap_folders(cfg) -> List[str]:
    """IMAP のフォルダ一覧 (config の folder / processed_folder に指定する名前) を返す。"""
    M = _imap_login(cfg)
    try:
        typ, data = M.list()
        return [line.decode(errors="replace") for line in data or [] if line] if typ == "OK" else []
    finally:
        M.logout()


def _quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def resolve_ptrs(conn: sqlite3.Connection, workers: int = 16, timeout: float = 3.0) -> int:
    """未解決の送信元 IP を逆引きしてキャッシュする。"""
    ips = list(db.unresolved_ips(conn))
    if not ips:
        return 0
    socket.setdefaulttimeout(timeout)

    def lookup(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0].lower()
        except (OSError, UnicodeError):
            return ip, ""

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, ptr in ex.map(lookup, ips):
            db.save_ptr(conn, ip, ptr)
    return len(ips)
