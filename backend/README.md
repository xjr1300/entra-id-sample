# Entra IDと連携するバックエンドの実装

このドキュメントでは、Microsoft Entra（以下、Entra ID）と連携するバックエンド（Web API サーバー: Rust + axum）の実装方法について説明します。

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
各パーツはBase64URL形式でエンコードされており、次の形式担っています。

```text
header.payload.signature
```

### JWTのヘッダー（header）

ヘッダーには、JWTのメタデータが含まれます。主に次の情報が定義されます。

* `typ`: トークンの種類を示します。JWTの場合は通常JWTが指定されます。
* `alg`: 署名に使用されているアルゴリズムを示します。Entra IDが発行するアクセストークンは、RS256公開鍵暗号方式が使用されます。
* `kid`: 署名の検証に使用する公開鍵を識別するためのキーIDです。

バックエンドは、ヘッダーに含まれる`alg`や`kid`をもとに、どの公開鍵で署名を検証すべきかを判断します。

### JWTのペイロード（payload）

ペイロードには、アクセストークンの内容を表すクレーム（Claims）が含まれます。
クレームは、認証や認可の判断に必要な情報です。
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

バックエンドは、Entra IDが公開しているJWK公開鍵を用いて署名を検証します。
署名が正しく検証できた場合、そのJWTはEntra IDによって発行され、かつ内容が改ざんされていないことが保証されます。

## JWT検証基盤

本リポジトリで実装したJWT検証基盤（`EntraIdTokenVerifier`）は、Entra IDが発行するアクセストークン（JWT）を検証します。
JWK検証基盤は、マルチテナントを前提とし、JWK公開鍵のキャッシュ、自動リフレッシュ、並行アクセス制御を組み合わせることで、実運用に耐えることができるように設計および実装しています。

`EntraIdTokenVerifier`は、`entra_id`モジュールで実装しています。

### JWT検証基盤の構成

JWT検証基盤は、主に次の要素で構成されています。

* テナントレジストリ
* JWKsプロバイダ
* JWK公開鍵キャッシュ
* バックグラウンドリフレッシュ機構
* JWT検証

### テナントレジストリ

テナントレジストリ（`TenantRegistry`）は、テナントID（`TenantId`）をキーとしてテナント情報を保持するハッシュマップです。
各テナントには、次の情報が紐づきます。

* テナントID
* JWKsエンドポイントのURI
* トークンの発行者（`iss`クレーム）
* トークンの購読者（`aud`クレーム）

これにより、JWTから特定したテナントIDに基づいて、正しい検証条件と公開鍵セットを選択できます。

### JWKsプロバイダ

JWKsプロバイダ（`JwksProvider`）は、Entra IDが公開しているJWKsエンドポイントからJWK公開鍵セットを取得する責務を持ちます。
JWKsプロバイダが持つHTTPクライアントには、次の特性があります。

* 接続タイムアウトとレスポンスタイムアウトの設定
* 再試行機構（指数バックオフとジッター付き）
* タイムアウト、接続エラー、5xxエラー（サーバーエラー）、429エラー（Too Many Requests）のみを再試行対象とする判定

これにより、一時的なネットワーク障害やEntra IDからのレスポンスの遅延などに対して耐性を持たせています。

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

テナントに`kid`クレームで識別される公開鍵が存在しなかった場合、複数のリクエストが同時に同一テナントにリフレッシュを要求しても、次の動作が保証されます。

* 最後にリフレッシュした時刻から設定された時間経過していない場合は、リフレッシュをスキップ
* すでに他スレッドがリフレッシュ中の場合は待機
* 常に1つのリクエストのみがリフレッシュを実行

これにより、Entra IDに過度にJWK公開鍵を要求するリクエストの集中を防ぎます。

### バックグラウンドリフレッシュ

`EntraIdTokenVerifier`は、バックグラウンドタスクを起動し、設定された時間間隔で、定期的に全テナントのJWK公開鍵をリフレッシュします。

このタスクでは、次の処理が行われます。

* 各テナントのJWK公開鍵を条件付きでリフレッシュ
* TTLを超過したJWK公開鍵のクリーンアップ
* シャットダウントークンによる安全な停止

これにより、リクエスト処理とは独立して、定期的にJWK公開鍵キャッシュの鮮度を保ちます。

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

署名の検証は、Entra IDが公開しているJWK（JSON Web Key）を用いて行います。
バックエンドは、Entra IDからJWK公開鍵を取得し、アクセストークンの署名を検証します。
これにより、トークンが改ざんされておらず、Entra IDによって発行されたものであることを確認できます。

これらの検証がすべて成功した場合にのみ、バックエンドはアクセストークンを信頼し、保護されたエンドポイントへのリクエストを処理します。

### アクセストークンの検証処理の実装（スコープ以外の検証）

```rust
// jsonwebtokenクレートが提供する機能を使用して、JWTヘッダーをデコードします。
//
// JWTはまだ検証前であるため、ここで得られたヘッダーの内容を決して信用してはいけません。
let header =
    decode_header(token.0.expose_secret()).map_err(EntraIdError::TokenHeaderDecodeError)?;

// アルゴリズムを検証します。
//
// Entra IDは、現在RS256のみのRSA署名アルゴリズムをサポートしているようです（未確認）。
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
    // ハンドラの本体処理をここに記述しています。
    //

    // レスポンスを返す
    Ok((StatusCode::OK, axum::Json(response)).into_response())
```

## OBOによるGraph APIの呼び出し

`me`ハンドラは、Entra IDで認証されたユーザーのアクセストークンを受け取り、アクセストークンを検証した後、On-Behalf-Of（OBO）フローを用いてGraph APIを呼び出します。
これにより、フロントエンドで取得したユーザーのアクセストークンをバックエンドが引き継ぎ、そのユーザーの代理としてGraph APIを呼び出します。

なお、関数の引数である`AuthClaims`は、アクセストークンの検証を行い、検証に成功した場合にクレーム情報とアクセストークンを含むエクストラクタです。

`axum`におけるエクストラクタは、リクエストから特定の情報を抽出するための仕組みです。

`AuthClaims`エクストラクタは、アクセストークンの検証を行い、検証に成功した場合にクレーム情報とアクセストークンを提供します。
検証に失敗した場合は、401 Unauthorizedエラーを返すため、`me`ハンドラ関数本体は実行されません。

`AuthClaims`エクストラクタにより、正当なアクセストークンを持つユーザーのみが`me`ハンドラにアクセスできるように、エンドポイントを保護します。

```rust
#[tracing::instrument(skip(app_state, claims, access_token))]
pub async fn me(
    State(app_state): State<AppState>,
    AuthClaims {
        claims,
        access_token,
    }: AuthClaims,
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
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("client_id", &app_state.client_credentials.client_id.0),   // バックエンドのクライアントIDを指定
        (
            "client_secret",
            app_state.client_credentials.client_secret.expose_secret(), // バックエンドのクライアントシークレットを指定
        ),
        ("assertion", access_token.0.expose_secret()),  // リクエストで受け取ったアクセストークンを指定
        ("scope", "https://graph.microsoft.com/User.Read"), // Graphのスコープを指定
        ("requested_token_use", "on_behalf_of"),      // OBOフローを指定
    ];
    let client = reqwest::Client::new();
    let response = client.post(&uri).form(&params).send().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to request Graph API access token");
        RequestError {
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to request Graph API access token: {e}"),
        }
    })?;
    if response.status().is_client_error() || response.status().is_server_error() {
        tracing::error!(status = %response.status(), "Graph API access token request returned error status");
        let message = response.text().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to read Graph API access token error body");
            RequestError {
                code: StatusCode::BAD_GATEWAY,
                message: format!("Failed to read Graph API access token error body: {e}"),
            }
        })?;
        tracing::error!(body = %message, "Graph API access token request error body");
        return Err(RequestError {
            code: StatusCode::BAD_GATEWAY,
            message,
        });
    };
    // アクセストークン取得レスポンスを解析して、アクセストークンを取得します。
    let token_response = response.json::<TokenResponse>().await.map_err(|e| {
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
            tracing::error!(error = %e, "Failed to call Graph API");
            RequestError {
                code: StatusCode::BAD_GATEWAY,
                message: format!("Failed to call Graph API: {e}"),
            }
        })?
        .json::<MeResponse>()
        .await
        .map_err(|e| RequestError {
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to parse Graph API response: {e}"),
        })?;

    Ok((StatusCode::OK, axum::Json(response)).into_response())
}
```
