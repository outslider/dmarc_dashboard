"""コマンドライン:  python -m dmarc_dashboard <command>

  import <path...>   ファイル / ディレクトリ (.xml .gz .zip .eml) を取り込む
  fetch              IMAP からレポートメールを取り込む
  folders            IMAP のフォルダ一覧を表示する (接続確認にも)
  resolve            送信元 IP の逆引き (PTR) を更新する
  serve              ダッシュボードを起動する
  demo               サンプルデータを生成して取り込む (既定では別の DB: data/demo.sqlite3)
  delete-domain      指定したドメインのデータを削除する (--demo でサンプルデータを削除)
"""

import argparse
import configparser
import logging
import sys
from pathlib import Path

from . import db, ingest, sample, server


def load_config(path):
    cfg = configparser.ConfigParser(interpolation=None)
    for section in ("imap", "server", "database", "dns"):
        cfg.add_section(section)
    if path and Path(path).exists():
        cfg.read(path, encoding="utf-8")
    elif path != "config.ini":
        sys.exit(f"設定ファイルが見つかりません: {path}")
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dmarc_dashboard", description="DMARC レポート分析ダッシュボード")
    ap.add_argument("-c", "--config", default="config.ini", help="設定ファイル (既定: config.ini)")
    ap.add_argument("--db", help="使う DB ファイル (config.ini の [database] path より優先)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("import", help="ファイル / ディレクトリを取り込む")
    p.add_argument("paths", nargs="+")
    sub.add_parser("fetch", help="IMAP から取り込む")
    sub.add_parser("folders", help="IMAP のフォルダ一覧を表示 (接続確認)")
    sub.add_parser("resolve", help="送信元 IP の逆引きを更新")
    p = sub.add_parser("serve", help="ダッシュボードを起動")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--fetch-interval", type=int, default=0, help="IMAP を自動取得する間隔 (秒)")
    p = sub.add_parser("demo", help="サンプルデータを生成して取り込む (既定の DB は data/demo.sqlite3)")
    p.add_argument("--dir", default="data/sample")
    p = sub.add_parser("delete-domain", help="指定したドメインのデータを削除する")
    p.add_argument("domains", nargs="*", help="削除するドメイン (例: example.co.jp)")
    p.add_argument("--demo", action="store_true", help="demo コマンドで作ったサンプルドメインを削除する")
    p.add_argument("-y", "--yes", action="store_true", help="確認せずに削除する")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if args.db:
        cfg.set("database", "path", args.db)
    elif args.cmd == "demo":
        # サンプルデータが本番の DB に混ざらないよう、demo は既定で別の DB に書き込む
        cfg.set("database", "path", "data/demo.sqlite3")
    db_path = cfg.get("database", "path", fallback="data/dmarc.sqlite3")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    resolve = cfg.getboolean("dns", "resolve", fallback=True)

    if args.cmd == "folders":
        if not cfg.get("imap", "host", fallback=""):
            sys.exit("config.ini の [imap] を設定してください")
        for line in ingest.list_imap_folders(cfg):
            print(line)
        return
    if args.cmd == "serve":
        return server.serve(cfg, args.host, args.port, args.fetch_interval)

    conn = db.connect(db_path)
    if args.cmd == "import":
        stats = ingest.import_paths(conn, args.paths)
    elif args.cmd == "fetch":
        if not cfg.get("imap", "host", fallback=""):
            sys.exit("config.ini の [imap] を設定してください")
        stats = ingest.fetch_imap(conn, cfg)
    elif args.cmd == "resolve":
        print(f"{ingest.resolve_ptrs(conn)} 件の IP を逆引きしました")
        return
    elif args.cmd == "delete-domain":
        targets = list(args.domains) + (list(sample.PROFILES) if args.demo else [])
        if not targets:
            sys.exit("削除するドメインを指定してください (サンプルデータなら --demo)")
        found = db.domain_counts(conn, targets)
        if not found:
            print(f"{db_path} に該当するデータはありません: {', '.join(targets)}")
            return
        print(f"DB: {db_path}")
        for dom, n in found:
            print(f"  {dom}: レポート {n} 件")
        if not args.yes and input("これらのデータを削除します。よろしいですか? [y/N] ").strip().lower() != "y":
            print("中止しました")
            return
        print(f"レポート {db.delete_domains(conn, [d for d, _ in found])} 件を削除しました")
        return
    elif args.cmd == "demo":
        n = sample.generate(args.dir)
        stats = ingest.import_paths(conn, [args.dir])
        for ip, ptr in sample.PTRS.items():  # デモ用 IP は実在しないので PTR を直接登録
            db.save_ptr(conn, ip, ptr)
        resolve = False
        print(f"サンプル {n} ファイルを生成しました ({args.dir}) → DB: {db_path}")
        print(f"サンプルを表示するには: python3 -m dmarc_dashboard --db {db_path} serve")
    print(stats)
    for e in stats.errors[:50]:
        print("  -", e)
    if resolve:
        ingest.resolve_ptrs(conn)


if __name__ == "__main__":
    main()
