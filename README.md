# DNS 委任チェッカー

DNS 委任チェーンをたどり、親ゾーンと子ゾーンの NS レコードや Glue 情報を照合する Web アプリです。

## 公開サイト

日本語版:

<https://www.on-link.jp/dns-delegation-check/>

英語版:

<https://www.on-link.jp/dns-delegation-check/en/>

画面上部のリンクから表示言語を切り替えられます。URL の `domain` パラメーターで調査対象を指定することもできます。

```text
https://www.on-link.jp/dns-delegation-check/?domain=example.com
```

## 機能

- ルートからゾーン頂点を探索し、親から子へ委任チェーンを追跡
- 親が委任する NS 情報と、子の権威サーバーが返す NS 情報を照合
- 親の Glue と、NS ホスト名から解決した IP アドレスを比較
- RFC 9471 / RFC 9499 に基づき、委任応答の A/AAAA レコードを `in-domain`、`sibling domain`、`unrelated` に分類
- strict-glue 方針に基づき、sibling glue と unrelated アドレスは追跡先に使わず、NS 名を解決
- UDP 応答が切り詰められた場合は TCP で再試行し、EDNS 非対応サーバーには EDNS を無効にして再試行
- IPv4 / IPv6 に対応し、DNS 応答を短時間キャッシュ
- ゾーン頂点探索と委任追跡の結果をツリー形式で表示
- 親の権威サーバーごとに ADDITIONAL SECTION を表示。応答は合算せず、空の応答と通信失敗を区別
- Glue 情報の表は名前、内容の順に自然順で並べ、OPT レコードを除外
- CNAME、DNAME、タイムアウト、通信エラーなどを表示。ゾーン頂点探索のタイムアウト時やクライアント切断時は、進行中の DNS 問い合わせを中断

## 判定結果

画面には、主に次のステータスが表示されます。

| ステータス | 意味 |
| --- | --- |
| `DELEGATED` | 親サーバーから次の委任先 NS を取得した |
| `SUCCESS` | 権威サーバーが応答し、比較対象の委任情報が一致した |
| `COLOCATED_DELEGATION` | 親子ゾーンが同じ権威サーバーで提供され、親側の委任情報を比較できない |
| `LAME_DELEGATION_NOT_MATCH` | 親子間で NS 情報または IP アドレスが一致しない |
| `LAME_DELEGATION_NO_ZONE` | 対象ゾーンの権威 NS が応答にない、または追跡済みサーバーへの紹介が繰り返される |
| `LAME_DELEGATION_NO_AUTHORITY_NS` | 委任応答の AUTHORITY セクションに NS レコードがない |
| `LAME_DELEGATION_NO_IP_ADDRESS` | 委任先 NS の IP アドレスを解決できない |
| `LAME_DELEGATION_NO_NS_IP_ADDRESS` | ゾーン頂点探索中に委任先 NS の IP アドレスを取得できず、探索を続けられない |
| `LAME_DELEGATION_NON_PUBLIC_ADDRESS` | 委任先にグローバルユニキャストではないアドレスが含まれているため、問い合わせを行わない |
| `LAME_DELEGATION_TIMEOUT` | DNS サーバーから応答がない |
| `LAME_DELEGATION_MAX_DEPTH` | 委任チェーンが追跡上限に達した |
| `NETWORK_ERROR` | DNS 通信または応答の処理中にエラーが発生した |
| `QUERY_LIMIT_EXCEEDED` | 1 回の検査で実行できる DNS 問い合わせ数の上限に達した |
| `ZONE_APEX_LOOKUP_TIMEOUT` | ゾーン頂点の探索が 30 秒以内に完了しなかった |
| `CNAME_FOUND` | 入力名が CNAME のため、委任検査を終了した |
| `DNAME_FOUND` | DNAME が見つかり、ゾーン頂点を確定できなかった |

## 必要な環境

- Node.js 18 以降（`.nvmrc` では Node.js 22 を指定）
- アプリケーションサーバーから DNS サーバーへ UDP/TCP の 53 番ポートで接続できるネットワーク

## セットアップと起動

リポジトリのルートで依存パッケージをインストールして、サーバーを起動します。

```bash
npm ci
npm start
```

`.nvmrc` に合わせる場合は、nvm で Node.js をインストールして使用します。

```bash
nvm install
nvm use
```

WSL2 を使う場合は、リポジトリを Windows 側ではなく Linux ファイルシステム上に配置し、Ubuntu のターミナルからコマンドを実行してください。

サーバーは `127.0.0.1:3001` で待ち受けます。ブラウザーで <http://localhost:3001/> を開いてください。PM2 を使う場合は、起動用の `server.js` を指定します。

```bash
pm2 start server.js --name dns-delegation-check
pm2 save
```

nginx をリバースプロキシとして使う場合は、Node.js サーバーがループバックで待ち受ける構成を維持してください。クライアント IP の判定に `X-Forwarded-For` を使うため、アプリはループバックからの転送だけを信頼します。

```nginx
location / {
   proxy_pass http://127.0.0.1:3001;
   proxy_set_header Host $host;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   proxy_set_header X-Forwarded-Proto $scheme;
}
```

## テスト

テストは `test/` にあります。委任判定と API のテストは固定応答を使うため、外部 DNS やネットワークの状態に依存しません。DNS ライブラリの統合テストでは、プロセス内の簡易 DNS サーバーを使って UDP/TCP の通信を確認します。

```bash
npm test
```

## 使い方

1. 「調査するドメイン名」にドメインを入力します。
2. 「解析スタート」をクリックします。
3. 「DNS委任の要点」で全体の判定を確認します。
4. 「ゾーン頂点探索ログ」と「委任追跡ログ」で、各 DNS サーバーの応答と NS/Glue の比較結果を確認します。

調査を開始したドメイン名はブラウザーの `localStorage` に保存され、次回表示時に復元されます。URL に `domain` パラメーターがある場合は、その値を優先します。

ドメイン名のほか、`https://example.com/path` のような URL も入力できます。URL の場合はホスト名だけを調査し、パスやクエリは使用しません。

## API

### `POST /api/trace`

指定したドメインの DNS 委任を調査します。

リクエスト例:

```http
POST /api/trace
Content-Type: application/json

{"domain":"example.com"}
```

成功時は、ゾーン頂点探索ログ `zoneApexLog`、委任追跡ログ `traceLog`、および親の権威サーバーごとのグルー情報 `parentGlueInfos` を含む JSON を返します。

```json
{
  "success": true,
  "parentDelegationUnavailable": false,
  "parentGlueInfos": [],
  "zoneApexLog": [],
  "traceLog": []
}
```

| HTTP ステータス | 発生条件 |
| --- | --- |
| `400` | ドメイン名が不正、またはリクエスト形式が不正 |
| `413` | リクエスト本文が 1 KB を超過 |
| `429` | クライアントごとのレート制限（1 分間に 10 件）に到達 |
| `503` | 同時実行数の上限（全体 8 件、クライアントごとに 2 件）に到達 |
| `500` | サーバー内部でエラーが発生 |

不正なドメイン名への `400` 応答は `{"error":"..."}`、その他のエラー応答は `{"success":false,"error":"..."}` 形式です。`429` と `503` には再試行の目安を示す `Retry-After` ヘッダーも含まれます。エラー応答に内部の詳細情報は含まれません。

## セキュリティ対策

- **内部ネットワークへの問い合わせ防止（SSRF 対策）**: 委任先 NS の Glue や名前解決で得た IP アドレスが、グローバルユニキャストではない場合は問い合わせず、`LAME_DELEGATION_NON_PUBLIC_ADDRESS` として記録します。この制限は TCP への再試行を含む DNS 問い合わせ先に適用されます。
- **問い合わせ数の制限**: 1 回の検査につき最大 1000 件、1 つの referral につき最大 32 個の NS アドレスを追跡します。問い合わせ数の上限に達すると `QUERY_LIMIT_EXCEEDED` を記録し、結果が不完全であることを示します。
- **レート・同時実行制限**: クライアントごとに 1 分間 10 件、同時 2 件まで、サーバー全体で同時 8 件までです。アプリはループバックからの転送だけを信頼するため、リバースプロキシから適切な `X-Forwarded-For` を設定してください。
- **HTTP セキュリティヘッダー**: CSP、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer` などを付与し、`X-Powered-By` は返しません。
- **XSS 対策**: DNS 応答由来の文字列は HTML として挿入せず、DOM のテキスト API で表示します。

## 構成

- `index.html`: 入力画面、結果表示、ブラウザー側の API 呼び出し
- `dns-delegation-check.js`: Express サーバー、DNS 問い合わせ、委任追跡、API
- `server.js`: Express サーバーの起動スクリプト
- `package.json`: 依存パッケージ、実行スクリプト、ES Modules 設定

## 注意事項

- DNS 問い合わせは利用者の端末ではなく、アプリケーションサーバーから実行されます。
- ゾーン頂点探索は 30 秒、個々の DNS 通信は 5 秒でタイムアウトします。ブラウザーから接続が切断された場合も、サーバーは進行中の DNS 問い合わせを中断します。HTTP サーバーのタイムアウトは 120 秒です。
- DNS サーバーの応答やネットワーク環境によっては、設定に問題がなくても通信エラーやタイムアウトが発生することがあります。
- 調査対象への問い合わせが、ネットワークおよび運用上許可されていることを確認して利用してください。
