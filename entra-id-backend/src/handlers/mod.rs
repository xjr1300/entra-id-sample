mod health_check;
mod me;
pub mod middleware;

use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    routing,
};
use secrecy::SecretString;

use self::health_check::health_check;
use self::me::me;
use self::middleware::auth_middleware;

use crate::{
    common::{AppError, AppResult, ErrorBody},
    entra_id::BearerToken,
    state::AppState,
};

/// ルートを作成する。
///
/// # Arguments
///
/// * `app_state` - アプリケーションの状態
///
/// # Returns
///
/// 作成したルーター
pub fn create_routes(app_state: AppState) -> Router<AppState> {
    Router::new().nest("/api", create_api_routes(app_state.clone()))
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
fn create_api_routes(app_state: AppState) -> Router<AppState> {
    Router::new()
        .merge(create_public_api_routes())
        .merge(create_protected_api_routes(app_state.clone()))
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
fn create_protected_api_routes(app_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/me", routing::get(me))
        .layer(axum::middleware::from_fn_with_state(
            app_state,
            auth_middleware,
        ))
}

/// AuthorizationヘッダーからBearerトークンを抽出する。
///
/// # Arguments
///
/// * `headers` - HTTPヘッダー
///
/// # Returns
///
/// 抽出したBearerトークン
///
/// # Notes
///
/// 抽出したBearerトークンは検証されていないため、呼び出し側で検証する必要がある。
pub fn extract_bearer_token(headers: &HeaderMap) -> AppResult<BearerToken> {
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
