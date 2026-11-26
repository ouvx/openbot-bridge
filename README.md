# OpenBot Bridge

ローカルの OpenBot を MCP クライアントから参照するための Node.js サーバーです。この配布候補は、認証済みのクライアントに接続確認と許可済みエージェント一覧を提供します。

本プロジェクトは非公式で、OpenAI の承認・提携を受けていません。ChatGPT App Directory への掲載は対象外です。

## ライセンス

OpenBot Bridge には MIT ライセンスを採用しています。著作権者は MIT ライセンスの著作権表示に記載した `ouvx` です。[ライセンス全文](LICENSE)

直接依存の `@modelcontextprotocol/sdk` と `zod` はいずれも MIT ライセンスです。

OpenBot 本体は別ライセンスの PolyForm Noncommercial 1.0.0 で提供され、このリポジトリには同梱していません。

## ローカルでの確認

Node.js(`engines` は 22.5 以上。動作確認は 24.11.1)、npm、Git、Python 3 を使用します。Linux の OpenBot デスクトップと、その利用者が読める SQLite データベースが前提です。以下の初期化はこのプロジェクト内に専用の設定を作ります。

```sh
npm ci --ignore-scripts
sh scripts/setup.sh
npm test
npm run doctor
npm start
```

既定の待受はループバックのポート 8790、MCP のパスは `/mcp` です。稼働中のインスタンスと同じポートやデータディレクトリを使わずに確認してください。接続先のテストデータとポートの指定は[セットアップ手順](docs/INSTALL.md)を参照してください。

## 既知の制限(beta)

この配布候補は **beta** です。検証は Linux 上のローカル模擬環境(模擬 DB、模擬通信先、模擬認可サーバー)で行った範囲に限られ、実クライアントや実アカウントとの相互運用は未検証です。実環境での確認は [SECURITY.md](SECURITY.md#実環境での確認計画) の計画に沿って、合意のうえで行います。

- 単一テナント前提です。データ領域と承認用の端末を1人の管理者が占有する構成だけを対象にし、複数利用者での共用は想定していません。
- 通知は既定で OFF です。有効にしても **ChatGPT の会話へ直接 push することはできません**。届いたかどうかは `get_pending`・`get_status` の呼び出しで確認します。
- Events の購読は起動時に拒否し、設定では解除できません(実環境の配信が未検証のため)。
- 通知の `session` モードは予約で未対応です(`off` として扱います)。
- Slack・Gmail への転送は原理的に可能ですが、本リポジトリでは未検証です。

## 個別の書き込み承認

管理者が拡張モードと対象を明示した環境では、各操作の宛先と引数をローカルの承認カードで確認できます。初期状態は読み取り専用です。承認の期限は既定120秒で、承認済みの操作は1回だけ実行できます。[承認手順](docs/INSTALL.md#操作を1件承認する)・[再送と回数制限](SECURITY.md#再送と書き込み回数)

## 公開前の確認

```sh
python3 scripts/scan-secrets.py
```

検査対象は Git の登録候補とステージ済みのスナップショットで、**コミット履歴は対象外**です。終了値 0 は定義したパターンに一致しなかったことを示します。新規の認証情報形式、自然文中の個人情報、利用権は別途確認してください。公開する前に、履歴の全コミット・全ブランチも [SECURITY.md](SECURITY.md#公開前の走査) の手順で確認します。公開判断に関わる既知の制約は [SECURITY.md](SECURITY.md)、ライセンスの採択記録は [LICENSE-CANDIDATES.md](LICENSE-CANDIDATES.md) にあります。

## Notifications (optional)

The bridge can send a signed webhook when a task needs a person, completes, or fails.
It is **off by default** and fails closed: an unset, unknown, or invalid configuration
turns notifications off and the bridge keeps running.

- `BRIDGE_NOTIFY=off|webhook` (`session` is reserved and treated as `off`)
- `BRIDGE_NOTIFY_WEBHOOK_URL` (HTTPS; plain HTTP only to loopback with an explicit test flag)
- `BRIDGE_NOTIFY_SECRET_FILE` (HMAC secret, mode `0600`)
- Enable per user in the bridge database (`notify_prefs`); a grant and its client must both be enabled.

Turn it on per grant from a terminal (the script opens the same `notify.db` and never
reads the secret file):

```sh
node scripts/notify-prefs.mjs list
node scripts/notify-prefs.mjs enable --grant <grantId> --client <clientId> --events needs_approval,completed
node scripts/notify-prefs.mjs disable --grant <grantId> --client <clientId>
node scripts/notify-prefs.mjs include-task --grant <grantId> --client <clientId> --include-task on
```

Add `--dry-run` to see what would change. `--include-task` defaults to `off`; see the
payload note below before turning it on. Revoking a grant disables its rows at once.
These rows only take effect while the bridge itself has notifications enabled.

**The bridge cannot push into a ChatGPT conversation.** If you want to be told inside
chat, ask for it: call `get_pending` (approvals and questions waiting) or `get_status`
(running and recent tasks), or set up ChatGPT Tasks yourself to ask on a schedule.
Combining the webhook with Slack or Gmail is possible in principle, but that setup is
untested here.

Payloads are limited to 512 bytes, signed with HMAC-SHA256
(`X-Bridge-Signature`, `X-Bridge-Timestamp`, `X-Bridge-Event`), de-duplicated for 24 hours,
and rate limited (20/min per grant, 100/min overall). By default a payload carries only
the event id, the kind, the task state and the time: **no task name**. A task title can
hold secrets or personal data, so it is sent only when the grant explicitly opts in with
`notify-prefs.mjs include-task --include-task on`, and even then only a title the user
typed (never one derived from the message, the task text or a previous task), cut to 200
characters and still subject to the 512-byte limit — an over-long title is not sent at
all. No message text, arguments, artifacts, paths, agent identifiers, or secrets are
included in any case.

One webhook destination serves every grant on this bridge: it does not multiplex
per-tenant endpoints, so run one bridge per tenant.

