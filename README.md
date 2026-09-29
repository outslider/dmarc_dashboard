# DMARC ダッシュボード

DMARC 集計レポート (rua) のメールを取り込み、SQLite に蓄積・分析してダッシュボードで表示します。
**Python 3.8 以上の標準ライブラリだけで動きます** (pip install 不要)。

## できること

- **取り込み**: IMAP でレポートメールを自動取得 / 画面からファイルをドラッグ&ドロップ / CLI でファイル・フォルダを一括取り込み
  - 対応形式: `.xml` `.xml.gz` `.zip`、それらが添付された `.eml`。DMARCbis (名前空間付き XML) にも対応
  - 同じレポート (レポーター + report_id) は重複取り込みされません
- **ダッシュボード**: DMARC 合格率、SPF / DKIM アライン率、隔離・拒否数、日別推移、認証結果の内訳、レポーター別、ドメイン別 (公開ポリシー)、送信元 IP 別 (逆引きホスト名・送信サービス推定)、レポート一覧。期間・ドメインで絞り込み可能
- **複数ドメイン**: レポートのドメインごとに自動で分けて集計します。「ドメイン別」表で要対応の件数と合格率の推移を並べて比較でき、行をクリックするとそのドメインに絞り込みます
  - 絞り込み状態は URL に残るので、ブックマークや共有ができます
    (例: `…/dmarc_dashboard/?domain=example-hd.co.jp&range=30`、`range` は 7 / 30 / 90 / all。日付指定は `from=2026-09-01&to=2026-09-30`)
- **自動診断**: ドメインごとに状況を判定し、推奨アクションを表示
  - SPF/DKIM は通るがドメイン不一致 (SendGrid 等の設定不備) の送信元と、その直し方
  - SPF/DKIM とも失敗している送信元 (なりすまし疑い)
  - p=none からポリシー強化できるか / p=quarantine・reject で正規メールが落ちていないか
  - 合格率の急落、レポートが届かなくなったドメイン

## まず試す (サンプルデータ)

```bash
python3 -m dmarc_dashboard demo
python3 -m dmarc_dashboard serve
```

ブラウザで http://127.0.0.1:8080/ を開きます。

## 本番での使い方 (さくらのメール + Apache サブディレクトリ公開)

### 1. レポート受信用のメールアドレスを用意する

さくらのコントロールパネルで専用アドレス (例: `dmarc@example.co.jp`) を作成し、DNS の DMARC レコードの rua をそこに向けます。
```
_dmarc.example.co.jp.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.co.jp"
```
※ 別ドメインの宛先に送る場合は、宛先側に `example.co.jp._report._dmarc.<宛先ドメイン>` の TXT (`v=DMARC1`) が必要です。

- zip 添付のレポートが迷惑メールフィルタで「迷惑メール」フォルダに振り分けられることがあります。このアドレスはフィルタを無効にするか、`folder` に迷惑メールフォルダを指定して別途取り込んでください。
- レポートは毎日届くので、メールボックスの容量に注意してください。`processed_folder` に移動したメールは、定期的に削除して構いません (データは DB に保存済み)。

### 2. 設定する

```bash
cp config.example.ini config.ini
```

`config.ini` の主な設定:

```ini
[imap]
host = アカウント名.sakura.ne.jp  ; さくらの初期ドメイン (独自ドメインだと証明書エラー)
user = dmarc@example.co.jp       ; メールアドレス全体
password = ...                   ; または環境変数 DMARC_IMAP_PASSWORD

[server]
host = 127.0.0.1
port = 8080
base_path = /dmarc_dashboard
```

接続確認とフォルダ名の確認:
```bash
python3 -m dmarc_dashboard folders
```

### 3. 過去のレポートを取り込む (任意)

`search = ALL` にして `fetch` を 1 回実行するか、手元の添付ファイルを `import` で取り込みます。重複は自動で除外されます。

### 4. 常駐させる (systemd)

[deploy/dmarc-dashboard.service](deploy/dmarc-dashboard.service) を `/etc/systemd/system/` に置いて有効化します。1 時間ごとに IMAP を取得します (画面の「メールを取得」ボタンでも即時取得できます)。

### 5. Apache でサブディレクトリ公開する

[deploy/apache-dmarc_dashboard.conf](deploy/apache-dmarc_dashboard.conf) を HTTPS の VirtualHost に組み込みます (`mod_proxy` と `mod_proxy_http` が必要)。

```apache
ProxyPass        /dmarc_dashboard http://127.0.0.1:8080/dmarc_dashboard timeout=300
ProxyPassReverse /dmarc_dashboard http://127.0.0.1:8080/dmarc_dashboard
```

`https://<サーバー>/dmarc_dashboard/` でアクセスできます。末尾スラッシュなしで開くと、末尾スラッシュ付きに自動でリダイレクトされます。
画面の CSS・JS・API はすべて相対パスで参照しているので、`base_path` とプロキシ側のパスをそろえれば他のパス名でも動きます。
アクセス制限は Apache の Basic 認証 / IP 制限 (設定例に記載) か、アプリ側の `[server] user/password` のどちらかで行ってください。

### コマンド一覧

| コマンド | 内容 |
|---|---|
| `import <path...>` | ファイル / フォルダを取り込む (過去分の一括投入に) |
| `fetch` | IMAP から未読のレポートメールを取り込む |
| `folders` | IMAP のフォルダ一覧を表示 (接続確認) |
| `resolve` | 送信元 IP の逆引きを更新 |
| `serve [--host --port --fetch-interval 秒]` | ダッシュボードを起動 |
| `demo` | サンプルデータを生成して取り込む |

共通オプション: `-c config.ini` (設定ファイル), `-v` (詳細ログ)

### Docker

```bash
docker build -t dmarc-dashboard .
docker run -d -p 8080:8080 -v $PWD/config.ini:/app/config.ini:ro -v $PWD/data:/app/data dmarc-dashboard
```

## 注意事項

- **公開範囲**: アプリは既定で 127.0.0.1 でのみ待ち受けます。外部からは Apache 経由でのみアクセスさせてください。
- **IMAP**: SSL (993) でサーバー証明書を検証して接続します。ユーザー名 + パスワード認証に対応しています (OAuth2 は未対応)。
- IMAP で取り込めたメールは既読にし、`processed_folder` 指定時はそのフォルダへ移動します。解析できなかったメールは未読のまま残ります。
- 日別集計は各レポートの開始日時 (サーバーのローカルタイム) で行います。
- フォレンジックレポート (ruf) は対象外です。

## 構成

```
dmarc_dashboard/
  parser.py     レポートの解析 (XML / gzip / zip / メール)
  db.py         SQLite スキーマと保存
  ingest.py     ファイル・IMAP 取り込み、IP 逆引き
  analytics.py  集計と自動診断
  server.py     Web サーバー / JSON API
  static/       ダッシュボード画面 (HTML / CSS / JS、外部ライブラリ不使用)
deploy/         Apache 設定例 / systemd ユニット例
tests/          python3 -m unittest で実行
```
