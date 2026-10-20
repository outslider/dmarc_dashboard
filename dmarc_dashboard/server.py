"""ダッシュボードの Web サーバー (標準ライブラリのみ)。"""

import base64
import datetime as dt
import hmac
import json
import logging
import mimetypes
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import analytics, db, ingest

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"
MAX_UPLOAD = 30 * 1024 * 1024


def _day_ts(s, plus_days=0):
    if not s:
        return None
    d = dt.datetime.strptime(s, "%Y-%m-%d") + dt.timedelta(days=plus_days)
    return int(time.mktime(d.timetuple()))  # ローカルタイムの 0:00


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.db_path = cfg.get("database", "path", fallback="data/dmarc.sqlite3")
        self.user = cfg.get("server", "user", fallback="")
        self.password = cfg.get("server", "password", fallback="")
        # リバースプロキシのサブディレクトリ配下で動かす場合のパス (例: /dmarc_dashboard)
        self.base_path = "/" + cfg.get("server", "base_path", fallback="").strip().strip("/")
        if self.base_path == "/":
            self.base_path = ""
        self.fetch_lock = threading.Lock()
        db.connect(self.db_path).close()

    def conn(self):
        return db.connect(self.db_path)

    @property
    def imap_enabled(self):
        return bool(self.cfg.get("imap", "host", fallback="").strip())

    def run_fetch(self):
        if not self.fetch_lock.acquire(blocking=False):
            return {"ok": False, "message": "取得処理が実行中です"}
        try:
            conn = self.conn()
            stats = ingest.fetch_imap(conn, self.cfg)
            if self.cfg.getboolean("dns", "resolve", fallback=True):
                ingest.resolve_ptrs(conn)
            conn.close()
            log.info("IMAP 取得: %s", stats)
            return {"ok": True, "message": str(stats), "errors": stats.errors[:20]}
        except Exception as e:  # ネットワーク・認証エラー等は画面に返す
            log.exception("IMAP 取得に失敗")
            return {"ok": False, "message": f"IMAP 取得に失敗しました: {e}"}
        finally:
            self.fetch_lock.release()


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "dmarc-dashboard"

        def log_message(self, fmt, *args):
            log.info("%s %s", self.address_string(), fmt % args)

        def _authorized(self):
            if not app.user:
                return True
            h = self.headers.get("Authorization", "")
            if h.startswith("Basic "):
                try:
                    u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                except Exception:
                    return False
                return hmac.compare_digest(u, app.user) and hmac.compare_digest(p, app.password)
            return False

        def _send(self, status, body: bytes, ctype="application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status=HTTPStatus.OK):
            self._send(status, json.dumps(obj, ensure_ascii=False).encode())

        def _guard(self):
            if self._authorized():
                return True
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm="DMARC Dashboard"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def _route(self):
            """base_path を取り除いたパスを返す。プレフィックスなしのパスもそのまま受け付ける
            (Apache の ProxyPass でプレフィックスを外して転送する構成と、残す構成の両方に対応)。"""
            url = urlparse(self.path)
            bp = app.base_path
            if bp and url.path == bp:
                # 末尾スラッシュなしだと相対パスの CSS/JS/API が解決できないのでリダイレクト
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                self.send_header("Location", bp + "/" + (f"?{url.query}" if url.query else ""))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if bp and url.path.startswith(bp + "/"):
                url = url._replace(path=url.path[len(bp):])
            return url

        def do_GET(self):
            if not self._guard():
                return
            url = self._route()
            if url is None:
                return
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                if url.path == "/api/dashboard":
                    conn = app.conn()
                    try:
                        data = analytics.dashboard(conn, q.get("domain") or None,
                                                   _day_ts(q.get("from")), _day_ts(q.get("to"), 1))
                        data["all_domains"] = analytics.domains(conn)
                        data["imap_enabled"] = app.imap_enabled
                    finally:
                        conn.close()
                    return self._json(data)
                if url.path == "/api/system":
                    conn = app.conn()
                    try:
                        res = analytics.system_details(
                            conn, q.get("key", ""), q.get("kind", "mfrom"),
                            "org" if q.get("level") == "org" else "domain", q.get("domain") or None,
                            _day_ts(q.get("from")), _day_ts(q.get("to"), 1))
                    finally:
                        conn.close()
                    return self._json(res)
                if url.path == "/api/source":
                    conn = app.conn()
                    try:
                        rows = analytics.record_details(conn, q.get("ip", ""), q.get("domain") or None,
                                                        _day_ts(q.get("from")), _day_ts(q.get("to"), 1))
                    finally:
                        conn.close()
                    return self._json(rows)
            except ValueError as e:
                return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
            return self._static(url.path)

        def do_POST(self):
            if not self._guard():
                return
            url = self._route()
            if url is None:
                return
            # 簡易 CSRF 対策: 同一オリジンの fetch からのみ受け付ける
            if self.headers.get("X-Requested-With") != "dmarc-dashboard":
                return self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            if url.path == "/api/upload":
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0 or length > MAX_UPLOAD:
                    return self._json({"error": "ファイルサイズが不正です"}, HTTPStatus.BAD_REQUEST)
                data = self.rfile.read(length)
                name = unquote(self.headers.get("X-Filename", "upload"))[:200]
                conn = app.conn()
                try:
                    stats = ingest.import_bytes(conn, data, f"upload:{name}")
                    if app.cfg.getboolean("dns", "resolve", fallback=True):
                        ingest.resolve_ptrs(conn)
                finally:
                    conn.close()
                return self._json({"imported": stats.imported, "duplicates": stats.duplicates,
                                   "errors": stats.errors})
            if url.path == "/api/fetch":
                if not app.imap_enabled:
                    return self._json({"ok": False, "message": "IMAP が設定されていません"})
                return self._json(app.run_fetch())
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def _static(self, path):
            if path in ("", "/"):
                path = "/index.html"
            target = (STATIC / path.lstrip("/")).resolve()
            if STATIC.resolve() not in target.parents or not target.is_file():
                return self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._send(HTTPStatus.OK, target.read_bytes(), ctype)

    return Handler


def serve(cfg, host=None, port=None, fetch_interval=0):
    app = App(cfg)
    host = host or cfg.get("server", "host", fallback="127.0.0.1")
    port = port or cfg.getint("server", "port", fallback=8080)
    if fetch_interval and app.imap_enabled:
        def loop():
            while True:
                app.run_fetch()
                time.sleep(fetch_interval)
        threading.Thread(target=loop, daemon=True).start()
        log.info("IMAP 自動取得: %d 秒ごと", fetch_interval)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    print(f"ダッシュボード: http://{host}:{port}{app.base_path}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
