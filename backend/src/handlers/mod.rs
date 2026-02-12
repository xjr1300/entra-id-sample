mod extractors;
mod health_check;
mod me;

use axum::{Router, http::StatusCode, routing};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use self::health_check::health_check;
use self::me::me;

use crate::common::{AppResult, RequestError};
use crate::entra_id::{BearerToken, ClientId, TenantId};
use crate::state::AppState;

/// クライアントがバックエンドにアクセスするために必要なスコープ
pub const BACKEND_ACCESS_TOKEN_SCOPE: &str = "access_as_user";

/// ルートを作成する。
///
/// # Arguments
///
/// * `app_state` - アプリケーションの状態
///
/// # Returns
///
/// 作成したルーター
pub fn create_routes() -> Router<AppState> {
    Router::new().nest("/api", create_api_routes())
}

/// 公開ルートと保護されたルートをまとめて返す。
///
/// # Arguments
///
/// * `app_state` - アプリケーションの状態
///
/// # Returns
///
/// 作成したルーター
fn create_api_routes() -> Router<AppState> {
    Router::new()
        .merge(create_public_api_routes())
        .merge(create_protected_api_routes())
}

/// 公開ルートを作成する。
///
/// # Arguments
///
/// * `app_state` - アプリケーションの状態
///
/// # Returns
///
/// 作成したルーター
fn create_public_api_routes() -> Router<AppState> {
    Router::new().route("/health-check", routing::get(health_check))
}

/// 保護されたルートを作成する。
///
/// # Arguments
///
/// * `app_state` - アプリケーションの状態
///
/// # Returns
///
/// 作成したルーター
fn create_protected_api_routes() -> Router<AppState> {
    Router::new().route("/me", routing::get(me))
}

/// Entra IDのOBOで返されるGraph API用アクセストークンレスポンスの例
///
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

/// OBOでGraph APIを呼び出すためのアクセストークンを取得する。
///
/// # Arguments
///
/// * `client` - HTTPクライアント
/// * `tenant_id` - テナントID
/// * `client_id` - クライアントID
/// * `client_secret` - クライアントシークレット
/// * `access_token` - ユーザーのアクセストークン
///
/// # Returns
///
/// Graph API用アクセストークン
///
/// # Notes
///
/// The user or administrator has not consented to use the application with ID ...
/// のようなエラーが出た場合、管理者がバックエンドアプリケーションに対してGraph APIのアクセス許可を
/// 付与していない可能性がある。
///
/// また、バックエンドアプリケーションに対して、Graph APIのUser.Readなどのアクセス許可を追加しても、
/// 管理者の同意が必要になる。
/// Entra ID画面でUser.Readの行に緑のチェックマークが付いていることを確認すること。
pub async fn retrieve_graph_access_token(
    client: &reqwest::Client,
    tenant_id: &TenantId,
    client_id: &ClientId,
    client_secret: &SecretString,
    access_token: &BearerToken,
) -> AppResult<BearerToken> {
    let uri = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id.0
    );
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("client_id", &client_id.0),
        ("client_secret", client_secret.expose_secret()),
        ("assertion", access_token.0.expose_secret()),
        ("scope", "https://graph.microsoft.com/User.Read"),
        ("requested_token_use", "on_behalf_of"),
    ];
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
    let token_response = response.json::<TokenResponse>().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to parse Graph API access token response");
        RequestError {
            code: StatusCode::BAD_GATEWAY,
            message: format!("Failed to parse Graph API access token response: {e}"),
        }
    })?;

    Ok(BearerToken(SecretString::new(
        token_response.access_token.into(),
    )))
}

/// スコープ文字列を分割してイテレータを返す。
///
/// # Arguments
///
/// * `scopes` - スコープ文字列
///
/// # Returns
///
/// * スコープのイテレータ
pub fn split_scopes(scopes: &str) -> impl Iterator<Item = &str> {
    scopes.split_whitespace()
}

/// スコープが存在するか確認する。
///
/// # Arguments
///
/// * `scp` - `scp`クレーム、スペース区切りのスコープ
/// * `required_scope` - 確認するスコープ
///
/// # Returns
///
/// スコープが存在する場合は`Ok(())`、存在しない場合は`Err(AppError)`を返す。
pub fn exists_scope(scp: &Option<String>, required_scope: &str) -> AppResult<()> {
    if let Some(scp) = scp
        && split_scopes(scp).any(|s| s == required_scope)
    {
        Ok(())
    } else {
        Err(RequestError {
            code: StatusCode::FORBIDDEN,
            message: format!("Required scope '{}' not found in token", required_scope),
        })
    }
}
