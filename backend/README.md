# Microsoft Entraと連携するバックエンドの実装

このドキュメントでは、フロントエンドが呼び出すAPIを提供するバックエンドを実装する方法を説明します。

フロントエンドは、Microsoft Entra（以下、Entra ID）で認証を受け、このバックエンドを呼び出すアクセストークンを受け取ります。
フロントエンドは、アクセストークンを用いてこのバックエンドの保護されたAPIを呼び出します。

バックエンドは、フロントエンドからの受け取ったアクセストークンを検証し、検証に成功した場合は、Graph APIを呼び出し、その結果をフロントエンドに返します。

バックエンドは、Rustで実装し、Webフレームワークとして`axum`を使用しています。

バックエンドの実装は、<https://github.com/xjr1300/entra-id-sample/tree/main/backend>で確認できます。

## 利用しているクレート

このバックエンドでは、主に次のクレートを利用しています。

* `anyhow` / `thiserror`: エラーハンドリングとカスタムエラー定義
* `axum`: Webフレームワーク
* `jsonwebtoken`: JWT（JSON Web Token）の処理
* `rand`: 乱数生成
* `reqwest`: HTTPクライアント
* `secrecy`: 秘密情報の安全な取り扱い
* `serde` / `serde_json`: JSONのシリアライズ・デシリアライズ
* `tokio`: 非同期ランタイム

## バックエンドのエンドポイント

このバックエンドは、次のリクエストを受け付けます。

* 保護されていないエンドポイント
  * ヘルスチェック: `/api/health-check`
* 保護されたエンドポイント
  * ユーザー情報の取得: `/api/me`

保護されていないエンドポイントへは、Entra IDから受け取ったアクセストークンを使用せずにリクエストできます。

保護されたエンドポイントへは、Entra IDから受け取ったアクセストークンがBearerトークンであることを示し、Authorizationヘッダーに設定してリクエストする必要があります。

```http
GET /api/me HTTP/1.1
Host: your-backend.example.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1...
...
```

## JSON Web トークン (JWT) とは

JWTは、ドット（`.`）で区切られた3つのパーツから構成されます。
各パーツはBase64URL形式でエンコードされており、次の形式に従っています。

```text
header.payload.signature
```

### JWTのヘッダー（header）

ヘッダーには、JWTのメタデータが含まれます。主に次の情報（クレーム、Claims）が定義されます。

* `typ`: トークンの種類を示します。JWTの場合は通常JWTが指定されます。
* `alg`: 署名に使用されているアルゴリズムを示します。Entra IDが発行するアクセストークンは、通常、RS256（RSA署名＋SHA-256）が使用されます。
* `kid`: 署名の検証に使用する公開鍵を識別するためのキーIDです。

バックエンドは、ヘッダーに含まれる`alg`や`kid`を基に、どのアルゴリズムで署名されているか、どの公開鍵を使用して署名を検証するべきかを判断する必要があります。

> `typ`は、`typ`クレームであるため、`alg`クレームなどと合わせた全体は**Claims**と呼ばれます。

### JWTのペイロード（payload）

ペイロードには、アクセストークンの内容を表すクレームが含まれます。
代表的なクレームには次のようなものがあります。

* `iss`: トークンの発行者を示します。Entra IDのテナントを識別するURLが設定されます。
* `aud`: トークンの購読者を示します。このバックエンドのアプリケーションIDやAPI識別子が設定されます。
* `iat`: トークンの発行時刻を示します。
* `exp`: トークンの有効期限を示します。
* `nbf`: トークンが有効となる開始時刻を示します。
* `scp`: 委任されたアクセス許可のスコープを示します。
* `roles`: アプリケーション権限で付与されたロールを示します。

バックエンドは、これらのクレームを検証することで、リクエストが許可されているかどうかを判断します。

### JWTの署名（signature）

署名は、ヘッダーとペイロードをもとに生成されます。
これにより、トークンが改ざんされていないことを検証できます。

具体的には、次の手順で署名が作成されます。

1. Base64URLエンコードされたヘッダーとペイロードをドットで連結します。
2. 連結した文字列を、ヘッダーで指定されたアルゴリズムと秘密鍵で署名します。

バックエンドは、Entra IDが公開しているJWK（JSON Web Key）公開鍵を用いて署名を検証します。
署名が正しく検証できた場合、そのJWTはEntra IDによって発行され、かつ内容が改ざんされていないことが保証されます。

```text
# 署名の概念的なコード

# JWTのヘッダーとペイロードをBase64URLエンコードして、ドットで連結
m = base64url(header) + "." + base64url(payload)
# 連結した文字列をSHA-256でハッシュ化
h = sha_256(m)
# ハッシュ値を秘密鍵で署名
s = sign_private_key(h)
```

## JWT検証基盤

本リポジトリで実装したJWT検証基盤（EntraIdTokenVerifier）は、Entra IDが発行するアクセストークン（JWT）を検証します。
本基盤はマルチテナントに対応しており、JWK公開鍵のキャッシュ、定期的なJWK公開鍵の自動リフレッシュ、並行アクセス制御を組み合わせることで、実運用を考慮した設計および実装としています。

`EntraIdTokenVerifier`は、`entra_id`モジュールで実装しています。

### JWT検証基盤の構成

JWT検証基盤は、主に次の要素で構成されています。

* テナントレジストリ
* JWKsプロバイダ
* JWK公開鍵キャッシュ
* JWK公開鍵キャッシュのリフレッシュ制御
* バックグラウンドリフレッシュ
* JWT検証インターフェイス

### テナントレジストリ

テナントレジストリ（`TenantRegistry`）は、テナントID（`TenantId`）をキーとしてテナント情報を保持するハッシュマップ（`HashMap`、キーと値のペアのコレクション、Pythonの辞書（`dict`）に相当）です。
各テナントには、次の情報が紐づきます。

* テナントID
* JWKsエンドポイントのURI（`Uri`、Uniform Resource Identifierの略、リソースを一意に識別する文字列、URLはURIの一種）
* トークンの発行者（`iss`クレーム）
* トークンの購読者（`aud`クレーム）

これにより、JWTから特定したテナントIDに基づいて、正しい検証条件と公開鍵セットを選択できます。

### JWKsプロバイダ

JWKsプロバイダ（`JwksProvider`）は、Entra IDが公開しているJWKsエンドポイントからJWK公開鍵セットを取得する責務を持ちます。
JWKsプロバイダには、次の機能があります。

* Entra IDへの接続タイムアウトとレスポンスタイムアウトの設定
* Entra IDへのリクエストが失敗したときの再試行機構（指数バックオフとジッター付き）
  * タイムアウト、接続エラー、5xxエラー（サーバーエラー）、429エラー（Too Many Requests）のみを再試行

これにより、一時的なネットワーク障害やEntra IDからのレスポンスの遅延などに対して耐性を持たせています。

#### JWK公開鍵の取得

JWKsプロバイダには、Entra IDからJWK公開鍵を取得するときの試行回数を設定できます。
JWK公開鍵を取得する際にエラーが発生した場合、指数バックオフとジッターで計算した待機時間を経過した後、設定された試行回数まで再試行します。

待機時間は、次の式で計算されます。

```math
wait = initial * (multiplier ^ (attempt -1)) * jitter
```

上記式のそれぞれのパラメーターは次の通りです。

* `wait`: 待機時間（秒単位）
* `initial`: 初期遅延時間（秒単位）
* `multiplier`: 指数バックオフの計数
* `attempt`: 現在の試行回数（1から始まる整数）
* `jitter`: ジッター（1.0前後ののランダムな値）

ジッターを生成する範囲は、設定で指定します。

例えば、`multiplier`が2.0、`initial`が0.5秒の場合、ジッターを無視した待機時間は次のとおりです。

| 現在の試行回数 (`attempt`) | 待機時間 (`wait`、秒) |
| --: | --: |
| 1 | 0.5 |
| 2 | 1.0 |
| 3 | 2.0 |
| 4 | 4.0 |
| 5 | 8.0 |

実際の待機時間は、上記表の値にジッターを乗じた時間になります。
ジッターは、再度リクエストを試みるときに、同時に複数のクライアントが同じタイミングでリクエストを送信することを防ぐために、再試行するまでに待機する時間をランダム化する目的で使用しています。

なお、非常に長い時間待機することを防ぐために、待機時間の上限を設定できます。

### JWK公開鍵キャッシュ

JWK公開鍵はテナントごとにキャッシュされ、`kid`クレームをキーとして管理されます。
キャッシュされたそれぞれのJWKには、最後に確認された時刻（`last_seen_at`）が記録されます。

キャッシュの特徴は次の通りです。

* 複数のJWKを同時に保持可能（鍵ローテーション対応）
* TTLによる期限管理
* TTL超過時でも、最低1つのJWKを保持する安全策

これにより、鍵ローテーションの過渡期や設定ミスによる全鍵消失を防いでいます。

### JWK公開鍵キャッシュのリフレッシュ制御

テナントごとのJWK公開鍵リフレッシュ状態を管理します。

* 最後にリフレッシュした時刻
* 現在リフレッシュ中かどうか
* 他スレッドを待機させるための通知機構

アクセストークンを検証する際、当該テナントに`kid`クレームで識別される公開鍵が存在しなかった場合、複数のリクエストが同時に同一テナントにリフレッシュを要求しても、次の動作が保証されます。

* 最後にリフレッシュした時刻から設定された時間経過していない場合は、リフレッシュをスキップ
* すでに他スレッドがリフレッシュ中の場合は待機し、他のスレッドがリフレッシュを完了するまで待機
* 他のスレッドがリフレッシュしていない場合、現在のスレッドがリフレッシュ

上記により、常に1つのリクエストのみがリフレッシュするように制御しています。

これにより、Entra IDにJWK公開鍵の要求が集中することを防ぎます。

### バックグラウンドリフレッシュ

`EntraIdTokenVerifier`は、バックグラウンドタスクを起動し、設定された時間間隔で、定期的に全テナントのJWK公開鍵をリフレッシュします。

このタスクでは、次の処理が行われます。

* 各テナントのJWK公開鍵を条件付きでリフレッシュ
* TTLを超過したJWK公開鍵のクリーンアップ
* シャットダウントークンによる安全な停止

これにより、リクエスト処理とは独立して、定期的にJWK公開鍵キャッシュの鮮度を保ちます。

### JWT検証インターフェイス

`EntraIdTokenVerifier`は、`verify_token`メソッドで、JWTを検証する機能を提供しています。

## クライアントから受け取ったアクセストークンの処理

バックエンドがクライアントから受け取ったアクセストークンは、クライアントがバックエンドにアクセスするために、Entra IDから取得したものです。

### アクセストークンの検証

バックエンドがクライアントから受け取ったアクセストークンは、そのまま**信用して利用してはいけません**。
トークンが正当な発行者によって発行され、かつ当該バックエンドに対して有効なものであることを検証する必要があります。

アクセストークンの検証では、主に次の点を確認します。

* トークンの署名が正しいこと
* トークンの発行者（`iss`）が想定したEntra IDのテナントであること
* トークンの購読者（`aud`）がこのバックエンドを示していること
* トークンの発行時刻（`iat`）が妥当であること
* トークンが有効になる開始時刻（`nbf`）が過ぎていること
* トークンの有効期限（`exp`）が切れていないこと
* 必要に応じて、スコープ（`scp`）やロール（`roles`）が要求を満たしていること

バックエンドは、Entra IDから取得したJWK公開鍵を使用して、アクセストークンの署名を検証します。
これにより、第三者によって発行されたアクセストークンでないこと、アクセストークンが改ざんされていないことを確認します。

これらの検証がすべて成功した場合にのみ、バックエンドはアクセストークンを信頼し、保護されたエンドポイントへのリクエストを処理します。

### アクセストークンの検証処理の実装（スコープ以外の検証）

```rust
//
// jsonwebtokenクレートが提供する機能を使用して、JWTヘッダーをデコードします。
//

// JWTはまだ検証前であるため、ここで得られたヘッダーの内容を決して信用してはいけません。
let header =
    decode_header(token.0.expose_secret()).map_err(EntraIdError::TokenHeaderDecodeError)?;

// アルゴリズムを検証します。
//
// Entra IDは、基本的にRS256を署名アルゴリズムをサポートしているようです（未確認）。
if header.alg != Algorithm::RS256 {
    return Err(EntraIdError::UnsupportedTokenAlgorithm(header.alg));
}

// kidクレームをJWTヘッダーから取得します。
let kid = header.kid.ok_or_else(|| {
    EntraIdError::TokenHeaderMissingKid("JWT header missing 'kid'".into())
})?;

// 便宜的にJWTペイロードからクレームを抽出します。
//
// extract_payload関数は、JWTペイロードをデコードしてクレームを抽出します。
// ただし、JWTは検証前であるため、ここで得られたクレームの内容を決して信用してはいけません。
//
// ここでは、構造する処理のために、issクレームとkidクレームを抽出することを目的としています。
let unverified_claims = extract_payload(token)?;

// JWTのペイロード部分をデコードして発行者を特定します。
//
// specify_issuer関数は、JWTペイロードにtidクレームが含まれていればそれをテナントIDとして使用し、
// そうでなければissクレームからテナントIDを抽出します。
let issuer = specify_issuer(&unverified_claims)?;
let tenant_id = if let IssuerTenant::Tenant(tenant_id) = issuer {
    tenant_id
} else {
    return Err(EntraIdError::DisallowedIssuerTenant(issuer));
};

// 登録されているテナントの中から、テナントIDが一致するものを取得します。
let tenant = self
    .registry
    .get(&tenant_id)
    .ok_or_else(|| EntraIdError::TenantNotFound(tenant_id.clone()))?;

// 登録されているテナントごとのJWK公開鍵セットから、kidクレームに対応するJWK公開鍵を取得します。
let kid = Kid(kid);
let decoding_key = self.get_decoding_key(&tenant_id, &kid).await?;

// 検証パラメーターとして、アルゴリズム（algクレーム）、発行者（issクレーム）、購読者（audクレーム）を設定します。
let mut validation = Validation::new(Algorithm::RS256);
validation.set_audience(&[&tenant.audience]);
validation.set_issuer(&[&tenant.issuer]);

// jsonwebtokenクレートのdecode関数を使用して、JWTをデコードおよび検証します。
//
// ここでは、アルゴリズム、発行者、購読者、有効期限の検証が行われます。
// decode関数は、上記で設定した検証パラメーターに加えて、内部で現在時刻（UNIXエポック秒）を取得し、
// iat、nbf、expクレームを含めて検証します。
let token_data = decode::<Claims>(token.0.expose_secret(), &decoding_key, &validation)
    .map_err(EntraIdError::VerifyTokenError)?;
```

### アクセストークンの検証処理の実装（スコープの検証）

スコープは、アクセストークンで許可された操作の範囲を示すものであるため、一般的にはリクエストハンドラ側で検証します。

```rust
// meハンドラにおけるスコープの検証
#[tracing::instrument(skip(app_state, claims, access_token))]
pub async fn me(
    State(app_state): State<AppState>,
    AuthClaims {
        claims,
        access_token,
    }: AuthClaims,
) -> AppResult<impl IntoResponse> {
    match claims.scp {
        Some(ref scopes) => {
            // クレームからスコープ（scpクレーム）を取得し、"access_as_token"スコープが含まれているかを確認します。
            //
            // BACKEND_ACCESS_TOKEN_SCOPEは "access_as_token" を示す定数です。
            // Entra IDは、スコープをスペース区切りの文字列として提供します。
            // split_scopes関数は、scpクレームの文字列を空白で分割し、イテレータを返す関数です。
            //
            // ここではanyメソッドを使用して、イテレータ内にBACKEND_ACCESS_TOKEN_SCOPEが存在するかどうかを確認します。
            // クレームからスコープ（scpクレーム）を取得して、"access_as_token"スコープが含まれているか確認します。
            // 存在しない場合は、403 Forbiddenエラーを返します
            if !split_scopes(scopes).any(|scp| scp == BACKEND_ACCESS_TOKEN_SCOPE) {
                tracing::warn!(
                    "{} scopes not found present in token",
                    BACKEND_ACCESS_TOKEN_SCOPE
                );
                return Err(RequestError {
                    code: StatusCode::FORBIDDEN,
                    message: "Required scope not found in token".to_string(),
                });
            }
        }
        None => {
            // scpクレームが存在しない場合も、403 Forbiddenエラーを返します。
            tracing::warn!("No scopes present in token");
            return Err(RequestError {
                code: StatusCode::FORBIDDEN,
                message: "Required scope not found in token".to_string(),
            });
        }
    }

    //
    // ハンドラの本体処理をここに記述します。
    //

    // レスポンスを返す
    Ok((StatusCode::OK, axum::Json(response)).into_response())
}
```

## OBOによるGraph APIの呼び出し

`me`ハンドラは、Entra IDで認証されたユーザーのアクセストークンを受け取り、アクセストークンを検証した後、On-Behalf-Of（OBO）フローを用いてGraph APIを呼び出します。
これにより、フロントエンドで取得したユーザーのアクセストークンをバックエンドが引き継ぎ、そのユーザーの代理としてGraph APIを呼び出します。

なお、関数の引数である`AuthClaims`は、アクセストークンの検証を行い、検証に成功した場合にクレームとアクセストークンを提供する`axum`で実装可能なエクストラクタ（抽出器）です。

`axum`におけるエクストラクタは、リクエストから特定の情報を抽出するための仕組みです。

`AuthClaims`エクストラクが検証に失敗した場合、リクエストハンドラは即座に`401 Unauthorized`エラーを返すため、`me`ハンドラ関数本体は実行されません。
これにより、正当なアクセストークンを持つユーザーのみが`me`ハンドラにアクセスできるように、エンドポイントを保護します。

```rust
#[tracing::instrument(skip(app_state, claims, access_token))]
pub async fn me(
    State(app_state): State<AppState>,
    AuthClaims {
        claims,
        access_token,
    }: AuthClaims,   // AuthClaimsエクストラクタ
) -> AppResult<impl IntoResponse> {
    //
    // 前に示したスコープの検証処理
    //

    // issクレームとして記録されている、テナントIDを取得します。
    let tenant_id = extract_issuer_from_iss(&claims.iss).map_err(|e| {
        tracing::error!(error = %e, "Failed to extract tenant ID from iss");
        RequestError {
            code: StatusCode::UNAUTHORIZED,
            message: format!("Failed to extract tenant ID from iss: {e}"),
        }
    })?;

    // OBOでGraph APIを呼び出すためのアクセストークンを取得します。
    //
    // The user or administrator has not consented to use the application with ID ...
    //
    // 上記のようなエラーが発生した場合、Entra ID管理者がバックエンドアプリケーションに対してGraph API
    // へのアクセス許可に同意していない可能性があります。
    // また、バックエンドに対して、GraphのUser.Readなどのスコープを追加した後も、Entra ID管理者の同意が
    // 必要になります。
    //
    // Entra IDで、Entra ID管理者が同意したことは、User.Readの行に緑のチェックマークが付いていること
    // で確認できます。
    //
    // 次のURIは、テナントごとに存在するアクセストークンを取得するエンドポイントです。
    let uri = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id.0
    );
    // OBOフローでGraph APIのアクセストークンを取得するためのパラメーターを設定します。
    let params = [
        // Bearerトークンを使用したOAuth 2.0のグラントタイプを指定します。
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        // バックエンドのクライアントIDを指定します。
        ("client_id", &app_state.client_credentials.client_id.0),
        // バックエンドのクライアントシークレットを指定します。
        (
            "client_secret",
            app_state.client_credentials.client_secret.expose_secret(),
        ),
        // フロントエンドから受け取ったユーザーのアクセストークンを指定して、このユーザーの代理として主張します。
        ("assertion", access_token.0.expose_secret()),
        // Graph APIに対して、バックエンド用アプリケーションに事前に構成され、同意済みの委任されたアクセス許可（APIのアクセス許可）
        // をまとめて要求します。
        // ただし、OBOフローでは元のアクセストークンが持つ権限の範囲内でのみ発行されます。
        ("scope", "https://graph.microsoft.com/.default"),
        // このアクセストークンの要求がOBO（On-Behalf-Of）フローであることを指定しています。
        ("requested_token_use", "on_behalf_of"),
    ];
    // HTTPクライアントを作成し、フォーム形式でGraph APIのアクセストークンを取得します。
    let client = reqwest::Client::new();
    let response = client.post(&uri).form(&params).send().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to request Graph API access token");
        RequestError {
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to request Graph API access token: {e}"),
        }
    })?;
    // レスポンスのステータスコードがエラーの場合、エラーメッセージをログに記録して、エラーを返します。
    if response.status().is_client_error() || response.status().is_server_error() {
        tracing::error!(status = %response.status(), "Graph API access token request returned error status");
        // レスポンスボディを読み取ります。
        let message = response.text().await.map_err(|e| {
            // レスポンスボディが得られない場合は、ログに記録し、エラーを返します。
            tracing::error!(error = %e, "Failed to read Graph API access token error body");
            RequestError {
                code: StatusCode::BAD_GATEWAY,
                message: format!("Failed to read Graph API access token error body: {e}"),
            }
        })?;
        // レスポンスボディが得られた場合は、内容をログに記録し、エラーを返します。
        tracing::error!(body = %message, "Graph API access token request error body");
        return Err(RequestError {
            code: StatusCode::BAD_GATEWAY,
            message,
        });
    };

    // レスポンスを解析して、アクセストークンを取得します。
    let token_response = response.json::<TokenResponse>().await.map_err(|e| {
        // レスポンスの解析に失敗した場合は、ログに記録し、エラーを返します。
        tracing::error!(error = %e, "Failed to parse Graph API access token response");
        RequestError {
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to parse Graph API access token response: {e}"),
        }
    })?;

    // アクセストークンをAuthorizationヘッダにBearerトークンとして設定して、Graph APIの呼び出します。
    let response = client
        .get("https://graph.microsoft.com/v1.0/me")
        .bearer_auth(token_response.access_token)
        .send()
        .await
        .map_err(|e| {
            // Graph APIの呼び出しに失敗した場合は、ログに記録し、エラーを返します。
            tracing::error!(error = %e, "Failed to call Graph API");
            RequestError {
                code: StatusCode::BAD_GATEWAY,
                message: format!("Failed to call Graph API: {e}"),
            }
        })?
        .json::<MeResponse>()
        .await
        .map_err(|e| RequestError {
            // Graph APIのレスポンスの解析に失敗した場合は、ログに記録し、エラーを返します。
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to parse Graph API response: {e}"),
        })?;

    // 処理が成功したため、200 OKで、Graph APIのレスポンスをそのまま返します。
    Ok((StatusCode::OK, axum::Json(response)).into_response())
}
```
