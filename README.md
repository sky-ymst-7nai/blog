# 学習用 Webプロキシ

依存パッケージなし（Node.js 18以上）。`server.js` 1本で動きます。

## 使い方

```
npm start          # http://127.0.0.1:3000/ を開く
npm test           # 模擬ログインサイトでの自動テスト（実サイトには繋ぎません）
```

トップページのフォームにURLを入れるか、クイックリンクから開きます。

## 設定（環境変数）

| 変数 | 内容 |
|---|---|
| `PORT` | 待ち受けポート（既定 3000） |
| `HOST` | 既定 `127.0.0.1`（ローカル専用）。外部公開するなら `BASIC_AUTH` 必須 |
| `BASIC_AUTH` | `user:pass` 形式。設定するとプロキシ自体にBasic認証がかかる |
| `ALLOW_HOSTS` | 通過を許可するドメインの追加（カンマ区切り、末尾一致） |
| `LOG` | `0` にするとアクセスログを止める |

許可リスト外のホストは403になり、コンソールに `BLOCKED host: ...` と出ます。
ログインに必要な外部ドメイン（CDN等）が見つかったら `ALLOW_HOSTS` に足してください。

## 仕組み（読む順番）

1. `Cookie Jar` … Cookieをサーバー側で管理（ログイン維持の核心）
2. `rewriteHtml / rewriteCss` … HTML/CSS内のURL書き換え
3. `proxyRequest` … Origin/Referer復元、リダイレクト書き換え、CSP除去
4. `public/client.js` … ページ内のJS通信（fetch/XHR/フォーム/document.cookie）の補正

## 性能・機能（v2）

- 上流への接続を使い回し（keep-alive）、画像/JSは条件付きリクエスト(304)でキャッシュが効く
- 変換後のHTML/CSSをbrotli/gzipで圧縮して返す（Renderでの転送量を節約）
- WebSocket中継に対応（ページ内の `new WebSocket()` も自動でプロキシ経由）
- `Sec-Fetch-*` を本来のサイトとの関係に作り直す（リソース分離ポリシーのあるサイト対策）
- `Referrer-Policy: no-referrer` や `rel=noreferrer` を無効化（ログイン時のCSRFチェック対策）
- Basic認証は10回連続で失敗すると、そのIPを10分ロック（外部公開時のブルートフォース対策）

## 既知の限界

- **reCAPTCHA / Turnstile など**：サイトキーがドメインに紐づくため、プロキシ経由では動きません。ログイン画面で使われていると通りません。
- **ボット検知・不審ログイン検知**：IPやヘッダーの違いで追加認証（メール確認等）が出ることがあります。
- **JavaScriptの `location` 参照**：`location.hostname` などはプロキシのものが見えます（偽装は未対応）。
- WebSocketは中継のみ。サイト固有のハンドシェイク検査があると失敗することがあります。
- 書き換えは正規表現ベースなので、壊れたHTMLや特殊な書き方では漏れます（その場合は Referer を使ったフォールバックが働きます）。
- Cookie Jar はメモリ上のみ。再起動でログイン状態は消えます。

## Render へのデプロイ（自分専用）

1. このフォルダをGitHubの **Private** リポジトリにpush
2. Render で「New +」→ Blueprint（`render.yaml`を読む）または Web Service を選び、リポジトリを接続
3. 環境変数 `BASIC_AUTH` に `ユーザー名:12文字以上のパスワード` を設定（未設定だと起動しません）
   - Web Serviceで手動作成する場合は `HOST=0.0.0.0` も設定。Start Command は `npm start`
4. デプロイ後、発行されたURLを開くとBasic認証が出ます
5. 使わなくなったらサービスを削除（または停止）

注意
- 無料プランは一定時間アクセスがないとスリープし、**Cookie Jar（ログイン状態）が消えます**。再度ログインが必要です
- ログイン情報がRenderのサーバーを通ります。自分専用・Privateリポジトリ・強いパスワードが前提です
- サイト側から見たIPがデータセンターのものになるため、追加認証が出やすくなります
