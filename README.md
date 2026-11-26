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

## 公開前の確認

```sh
python3 scripts/scan-secrets.py
```

検査対象は Git の登録候補とステージ済みのスナップショットです。終了値 0 は定義したパターンに一致しなかったことを示します。新規の認証情報形式、自然文中の個人情報、利用権は別途確認してください。公開判断に関わる既知の制約は [SECURITY.md](SECURITY.md)、ライセンスの採択記録は [LICENSE-CANDIDATES.md](LICENSE-CANDIDATES.md) にあります。
