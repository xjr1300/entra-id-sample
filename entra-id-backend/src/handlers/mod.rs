mod extractors;
mod health_check;
mod me;

use axum::{Router, routing};

use self::health_check::health_check;
use self::me::me;

use crate::state::AppState;

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
