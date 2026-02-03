use crate::{
    common::{AppError, AppResult, ErrorBody},
    entra_id::{BearerToken, extract_issuer_from_iss},
    state::AppState,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

/// Entra IDのOBOで返されるGraph API用アクセストークンレスポンスの例
/// ```json
/// {
///     "token_type": "Bearer",
///     "scope": "https://graph.microsoft.com/user.read",
///     "expires_in": 3269,
///     "ext_expires_in": 0,
///     "access_token": "eyJhbGciO...",
///     "refresh_token": "OAQABAAAA...",
/// }
/// ```
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    // 他のフィールドは省略
}

/// フロントエンドからバックエンドへのアクセストークンがAuthorizationヘッダーに含まれている。
///
/// バックエンドからOBOでアクセストークンを取得する。
///     https://learn.microsoft.com/ja-jp/entra/identity-platform/v2-oauth2-auth-code-flow#request-an-access-token-with-a-certificate-credential
/// request:
///     POST https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
/// form-data:
///     grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
///     client_id=<backend-client-id>
///     client_secret=<backend-client-secret>
///     assertion=<frontendから来たアクセストークン>
///     scope=https://graph.microsoft.com/User.Read
///     requested_token_use=on_behalf_of
///
/// バックエンドからGraph APIを呼び出す。
/// request:
///     GET https://graph.microsoft.com/v1.0/me
/// headers:
///    Authorization: Bearer <access-token-from-obo>
///
pub async fn me(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    // AuthorizationヘッダーからBearerトークンを抽出
    // ここで得られるトークンは、バックエンドAPIを呼び出すためのアクセストークン
    let token = extract_bearer_token(&headers)?;

    // バックエンド用アクセストークンを検証
    let claims = app_state
        .token_verifier
        .verify_token(&token)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Token verification failed");
            AppError::Handler(ErrorBody {
                code: StatusCode::UNAUTHORIZED,
                message: format!("Token verification failed: {e}"),
            })
        })?;

    // テナントIDを取得
    let tenant_id = extract_issuer_from_iss(&claims.iss).map_err(|e| {
        tracing::error!(error = %e, "Failed to extract tenant ID from iss");
        AppError::Handler(ErrorBody {
            code: StatusCode::UNAUTHORIZED,
            message: format!("Failed to extract tenant ID from iss: {e}"),
        })
    })?;

    // OBOでGraph APIを呼び出すためのアクセストークンを取得
    // The user or administrator has not consented to use the application with ID ...
    // のようなエラーが出た場合、管理者がバックエンドアプリケーションに対して
    // Graph APIのアクセス許可を付与していない可能性がある。
    //
    // また、バックエンドアプリケーションに対して、Graph APIのUser.Readなどのアクセス許可を追加しても、管理者の同意が必要になる。
    // Entra ID画面でUser.Readの行に緑のチェックマークが付いていることを確認すること。
    let uri = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id.0
    );
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("client_id", &app_state.client_credentials.client_id.0),
        (
            "client_secret",
            app_state.client_credentials.client_secret.expose_secret(),
        ),
        ("assertion", token.0.expose_secret()),
        ("scope", "https://graph.microsoft.com/User.Read"),
        ("requested_token_use", "on_behalf_of"),
    ];
    let client = reqwest::Client::new();
    let response = client.post(&uri).form(&params).send().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to request Graph API access token");
        AppError::Handler(ErrorBody {
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to request Graph API access token: {e}"),
        })
    })?;
    if response.status().is_client_error() || response.status().is_server_error() {
        tracing::error!(status = %response.status(), "Graph API access token request returned error status");
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error body".into());
        tracing::error!(body = %message, "Graph API access token request error body");
        return Err(AppError::Handler(ErrorBody {
            code: StatusCode::BAD_GATEWAY,
            message,
        }));
    };
    let token_response = response.json::<TokenResponse>().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to parse Graph API access token response");
        AppError::Handler(ErrorBody {
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to parse Graph API access token response: {e}"),
        })
    })?;

    // Graph APIの呼び出し
    let response = client
        .get("https://graph.microsoft.com/v1.0/me")
        .bearer_auth(token_response.access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to call Graph API");
            AppError::Handler(ErrorBody {
                code: StatusCode::BAD_GATEWAY,
                message: format!("Failed to call Graph API: {e}"),
            })
        })?
        .json::<MeResponse>()
        .await
        .map_err(|e| {
            AppError::Handler(ErrorBody {
                code: StatusCode::BAD_GATEWAY,
                message: format!("Failed to parse Graph API response: {e}"),
            })
        })?;

    Ok((StatusCode::OK, axum::Json(response)).into_response())
}

fn extract_bearer_token(headers: &HeaderMap) -> AppResult<BearerToken> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            AppError::Handler(ErrorBody {
                code: StatusCode::UNAUTHORIZED,
                message: "Authorization header not found".into(),
            })
        })?
        .to_str()
        .map_err(|e| {
            AppError::Handler(ErrorBody {
                code: StatusCode::UNAUTHORIZED,
                message: format!("Invalid Authorization header: {e}"),
            })
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        AppError::Handler(ErrorBody {
            code: StatusCode::UNAUTHORIZED,
            message: "Bearer token not found".into(),
        })
    })?;

    Ok(BearerToken(SecretString::new(token.into())))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MeResponse {
    id: String,
    user_principal_name: Option<String>,
    surname: Option<String>,
    given_name: Option<String>,
    display_name: Option<String>,
    mail: Option<String>,
    job_title: Option<String>,
    office_location: Option<String>,
    business_phones: Option<Vec<String>>,
    mobile_phone: Option<String>,
    preferred_language: Option<String>,
}
