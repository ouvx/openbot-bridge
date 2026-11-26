# セキュリティと公開判断

この候補の検証範囲は Linux 上の単一管理者によるローカル利用です。基本モードはループバック待受、読み取り専用、許可エージェント0件で始まります。認証後に公開する基本ツールは接続確認と一覧の2件です。

| 保護対象 | 許可する根拠 |
|---|---|
| クライアントとセッション | 管理者の同意ごとに grant ID を発行。リクエストの Bearer を毎回検証し、MCP セッションの client ID・grant ID・スコープ・許可 ID を照合する。 |
| エージェント、会話・ログ | 同意時の対象と現在の運営設定の共通部分のみ。`BRIDGE_ALLOWED_AGENT_IDS` が全体の上限。`BRIDGE_CLIENT_AGENT_IDS` でクライアント別に絞れる。同じエージェントを許可されたクライアントは、そのエージェント所有の会話・ログを読める。利用者単位の私的な会話には別のエージェントを割り当てる。 |
| ジョブ・応答 | 保存した client ID・grant ID とエージェントがすべて一致したものだけ。新しい同意は別の grant になる。所有者のない旧ジョブ、DB で thread、turn、agent の関係を確認できないデータは拒否。 |
| 成果物 | 管理者が書き出した `OPENBOT_SHARED_DIR/bridge-artifacts/<agentId>/` のファイルだけ。専用ルート、実体パス、開いたファイル記述子、バイト数を検査。通常の単一リンクの UTF-8 テキストを対象とし、許可形式は md、txt、csv、tsv、diff、patch。隠しファイル、資格情報、DB、ログ、シンボリックリンクを拒否。エクスポート先を他の利用者に書き込み可能にしない。所有者を確認できないワークスペース差分・添付パスの推測は行わない。 |
| 通信元 | Host の許可検査に加え、Origin が付く全リクエストを `BRIDGE_ALLOWED_ORIGINS` と完全一致で照合。空リスト・不一致は403。Origin のないサーバー間通信にも Bearer 認証を適用。公開 /health は生存だけを返す。 |
| Events | 起動時の有効化拒否を維持。配送実装は読取スコープ、定義済み種別、許可された明示エージェント、ジョブの所有者、現に有効な grant を照合。HTTPS の公開 IPv4 アドレス集合を購読時に確定し、送信直前に一度再解決。一致した IP に直接 TLS 接続し、元ホストの SNI・証明書検証・Host と実際の対向 IP を確認して本文を渡す。名前解決失敗・変更・私用アドレス・リダイレクト・過大な応答を拒否する。実環境の配信や再起動後の購読を未検証のため、設定での解除は提供しない。 |

## OAuth と失効

認可、コード交換、refresh、MCP での利用時に対象リソースを確認します。リソースは `BRIDGE_PUBLIC_URL` に指定した origin（省略時はローカルの発行元）です。S256 と一回限りのコードを使用します。認可コード・access・refresh の値はハッシュで保存し、単一プロセス内の変更を直列化してからファイルを置き換えます。古い束縛なしの資格情報は再同意が必要です。複数プロセスでデータディレクトリを共用しないでください。

`POST /oauth/revoke` にフォーム形式で `client_id` と現在の access または refresh を `token` として送ると、その同意に属するコード・access・refresh を削除します。同じクライアントの別の同意は維持されます。古いトークンを持つ MCP リクエストは401になります。実行中の OpenBot ジョブの停止は、この失効操作の対象外です。

認可要求で明示した `redirect_uri` は認可コード交換で必須です。登録済み URI が1つだけなら認可要求で省略できます。refresh は `client_id` と `resource` を必須とし、`redirect_uri` は指定時に元の URI と照合します。RFC 6749 §4.1.3 はコード交換の規定で、§6 の更新要求には redirect URI がありません。公式 SDK 1.32.2 が URI を省略する更新、更新済みトークンによる再接続、旧 refresh の拒否を模擬環境で検証します。[RFC 6749 §4.1.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)・[§6](https://datatracker.ietf.org/doc/html/rfc6749#section-6)・[MCP 認可仕様](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

Streamable HTTP では Origin が付いたリクエストの送信元を検査します。SDK が Origin を省略した場合も、MCP の Host と Bearer の検証は維持します。Origin が許可リストと異なる場合は403を返します。[MCP 通信仕様](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

## 書き込みを承認する人と内容

拡張モードの送信・委任・修正・追跡中止・新規セッションの5操作に適用します。各要求でスコープ、読み取り専用設定、現在の対象・ジョブ所有者を確認します。操作を始める前に管理者が同じ PC の端末から期限付きの承認画面を開きます。カードには依頼した client と grant、操作名、実際の宛先 ID、正規化後の引数を全文表示します。手順は [セットアップ](docs/INSTALL.md) にあります。同じ OS ユーザーとして任意コードを実行できる相手は承認 DB や端末にアクセスできます。この運用は単一の信頼済み管理者を前提とします。

承認を照合する規則は次のとおりです。

1. `approval_id` と `idempotency_key` は処理を制御する別フィールドです。名前で指定した宛先は許可済み ID に解決し、ジョブは所有者を確認して宛先を取得します。
2. JSON の文字列とキーには trim と Unicode NFC を適用します。オブジェクトのキーは UTF-16 コード単位順、配列は入力順です。数値は有限の JSON 数値とし、正規化で重複するキーを拒否します。実行にも正規化後の引数を渡します。
3. `argsHash` は正規化 JSON の `[tool,args]` を UTF-8 にした SHA-256 です。カードは `{tool,targets,args}` を同じ規則でシリアライズし、宛先は重複を除いて昇順に並べます。見えない書式制御文字はエスケープします。表示文字列の SHA-256 が `summaryHash` です。管理者の決定時には画面上の全文、実行時には今回の引数から再計算した両ハッシュを照合します。
4. ローカル SQLite に approval ID、grant、client、tool、両ハッシュ、宛先、発行・失効・使用時刻、状態、監査 ID を保存します。有効期間は発行から既定120秒です。承認だけでは送信しません。実行時に書き込みトランザクション内で `approved`・未使用・期限内を条件に1件だけ取得し、回数枠と実行開始を記録してから OpenBot を呼び出します。
5. 拒否には個別コードがあります。例は `approval_not_approved`、`approval_used`、`approval_expired`、`approval_arguments_mismatch`、`approval_card_mismatch`、`target_denied` です。承認・監査を保存できない場合は新規実行を拒否します。監査は主体、日時、操作、ハッシュ、承認・監査 ID、結果を記録し、生の引数を含みません。承認待ちの表示文は決定時、または期限後の次回新規発行時に消去します。保存結果とジョブには私的な内容が含まれ得ます。DB とバックアップは管理者専用にしてください。

## 再送と書き込み回数

同じ grant・client 内で呼び出し側のキーを優先し、省略時は操作名と引数ハッシュからキーを導出します。完了後は同じ引数・キーで承認 ID を外すと保存結果を返します。使用済みの承認 ID の再提示、同じキーで別の引数を使うことは拒否します。通信切断・クラッシュなどで送達が確定しない操作も再実行しません。管理者が宛先の状態と監査記録を確認してください。

新規の承認カードには直近60秒間で同じ grant に8件、サービス全体に40件の発行上限があります。決定済み・期限切れのカードも発行から60秒間は計上します。既存カードや完了結果の再取得は枠を消費しません。超過するとカードを追加せず、`approval_issue_rate_limited` を返します。

実行前の DB ロック競合は `operation_store_busy`、それ以外のストレージ障害は `operation_store_unavailable` です。実行処理が戻った後に結果を保存できない場合は `operation_result_unrecorded` を返します。その場合は新しいキーで再送せず、管理者が宛先の処理結果を確認してください。監査も書けない障害では、最後の永続記録が実行開始のまま残る場合があります。

直近60秒間に取得した実行枠を grant・操作別と client・操作別に各12件、サービス全体で60件までに制限します。超過時は `write_rate_limited` を返し、OpenBot への送信は行いません。HTTP リクエスト全体の制限とは独立しています。設定名は `.env.example` に記載しています。

## 実環境での確認計画

独立レビュー後、Main Bot へ計画を報告し、実施の合意を得てから行います。専用のデータ領域と試験宛先1体で、まず ChatGPT の読み取り接続・OAuth 更新を確認します。次に、管理者が許可したテストメッセージ1件で、承認前の送信ゼロ、カードとの照合、承認後の応答、再送時の実行件数と監査を確認します。試験終了時は試験用接続を閉じます。現在の証拠はローカル模擬環境です。公開判断には実クライアントの相互運用、OS の管理者境界、ログの保管期間・容量、失敗時の運用確認も残っています。

## 配布の対象

OpenBot Bridge は OpenAI の承認・提携を受けていない非公式プロジェクトです。ChatGPT App Directory への掲載は対象外です。

このリポジトリの Bridge には MIT ライセンスを採用しています。OpenBot 本体は別ライセンスの PolyForm Noncommercial 1.0.0 で提供され、このリポジトリには同梱していません。

## Notification webhook

- Off by default. Any invalid configuration (missing URL, secret file not `0600`,
  unknown mode) only disables notifications; the bridge keeps serving.
- HTTPS only. Plain HTTP is accepted only for `127.0.0.1`/`[::1]` when
  `BRIDGE_NOTIFY_ALLOW_LOOPBACK_HTTP=1` is set for tests.
- The destination is resolved once and the connection is pinned to that address
  (same rules as the existing callback transport); private addresses are refused
  before any body is sent, and a changed DNS answer aborts the request.
- Requests carry an HMAC-SHA256 signature over `<timestamp>.<body>` plus
  `X-Bridge-Timestamp` (epoch seconds) so a receiver can reject anything older than
  ±300 seconds. Secrets are read from a `0600` file, never logged, and never placed
  in payloads, audit entries, or errors.
- Delivery is fire-and-forget with a short timeout and no queue: a failed or refused
  delivery never fails the bridge request that triggered it, and nothing is retried
  after a restart.
- The secret file is opened once with `O_NOFOLLOW` and checked with `fstat` on that
  same descriptor: a symlink, a non-regular file, or a mode other than `0600` turns
  notifications off.
- Payloads carry no task title by default. A grant may opt in with
  `include_task` in `notify_prefs`; only then is a title the user typed sent (200
  characters, inside the 512-byte budget), and a prompt-derived or bridge-generated
  title always stays in the local job record. Titles never reach the audit trail or
  the log.
- A revoked grant disables its `notify_prefs` rows immediately; while notifications are
  off the bridge neither reads nor creates `notify.db`.
- Audit lines record only the outcome, kind, event id and destination host.

