# OpenBot Bridge

ローカルの OpenBot を MCP クライアントから参照するための Node.js サーバーです。この配布候補は、認証済みのクライアントに接続確認と許可済みエージェント一覧を提供します。

本プロジェクトは非公式で、OpenAI の承認・提携を受けていません。ChatGPT App Directory への掲載は対象外です。

## ライセンス

OpenBot Bridge には MIT ライセンスを採用しています。著作権者名は確定後に LICENSE の仮表記を差し替えます。[ライセンス全文](LICENSE)

直接依存の `@modelcontextprotocol/sdk` と `zod` はいずれも MIT ライセンスです。

OpenBot 本体は別ライセンスの PolyForm Noncommercial 1.0.0 で提供され、このリポジトリには同梱していません。

## ローカルでの確認

Node.js 24、npm、Git、Python 3 を使用します。Linux の OpenBot デスクトップと、その利用者が読める SQLite データベースが前提です。以下の初期化はこのプロジェクト内に専用の設定を作ります。

```sh
npm ci --ignore-scripts
sh scripts/setup.sh
npm test
npm run doctor
npm start
```

既定の待受はループバックのポート 8790、MCP のパスは `/mcp` です。稼働中のインスタンスと同じポートやデータディレクトリを使わずに確認してください。接続先のテストデータとポートの指定は[セットアップ手順](docs/INSTALL.md)を参照してください。

## 個別の書き込み承認

管理者が拡張モードと対象を明示した環境では、各操作の宛先と引数をローカルの承認カードで確認できます。初期状態は読み取り専用です。承認の期限は既定120秒で、承認済みの操作は1回だけ実行できます。[承認手順](docs/INSTALL.md#操作を1件承認する)・[再送と回数制限](SECURITY.md#再送と書き込み回数)

## 公開前の確認

```sh
python3 scripts/scan-secrets.py
```

検査対象は Git の登録候補とステージ済みのスナップショットです。終了値 0 は定義したパターンに一致しなかったことを示します。新規の認証情報形式、自然文中の個人情報、利用権は別途確認してください。公開判断に関わる既知の制約は [SECURITY.md](SECURITY.md)、ライセンスの採択記録は [LICENSE-CANDIDATES.md](LICENSE-CANDIDATES.md) にあります。

## Notifications (optional)

The bridge can send a signed webhook when a task needs a person, completes, or fails.
It is **off by default** and fails closed: an unset, unknown, or invalid configuration
turns notifications off and the bridge keeps running.

- `BRIDGE_NOTIFY=off|webhook` (`session` is reserved and treated as `off`)
- `BRIDGE_NOTIFY_WEBHOOK_URL` (HTTPS; plain HTTP only to loopback with an explicit test flag)
- `BRIDGE_NOTIFY_SECRET_FILE` (HMAC secret, mode `0600`)
- Enable per user in the bridge database (`notify_prefs`); a grant and its client must both be enabled.

**The bridge cannot push into a ChatGPT conversation.** If you want to be told inside
chat, ask for it: call `get_pending` (approvals and questions waiting) or `get_status`
(running and recent tasks), or set up ChatGPT Tasks yourself to ask on a schedule.
Combining the webhook with Slack or Gmail is possible in principle, but that setup is
untested here.

Payloads are limited to 512 bytes, signed with HMAC-SHA256
(`X-Bridge-Signature`, `X-Bridge-Timestamp`, `X-Bridge-Event`), de-duplicated for 24 hours,
and rate limited (20/min per grant, 100/min overall). No message text, arguments,
artifacts, paths, agent identifiers, or secrets are included.

