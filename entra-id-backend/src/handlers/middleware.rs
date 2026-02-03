use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{Request, StatusCode, request::Parts},
    middleware::Next,
    response::Response,
};

use crate::{
    common::{AppError, AppResult, ErrorBody},
    entra_id::Claims,
    handlers::extract_bearer_token,
    state::AppState,
};

/// 認証ミドルウェア
pub async fn auth_middleware(
    State(app_state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    // AuthorizationヘッダーからBearerトークンを抽出
    // ここで得られるトークンは、バックエンドAPIを呼び出すためのアクセストークン
    let token = extract_bearer_token(request.headers()).map_err(|e| {
        tracing::error!(error = %e, "Failed to extract bearer token");
        AppError::Handler(ErrorBody {
            code: StatusCode::UNAUTHORIZED,
            message: "Bearer token not found".into(),
        })
    })?;

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

    // ハンドラで取得できるようにクレームをリクエストに埋め込み
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// 認証済みクレームをリクエストから抽出するエクストラクタ
#[derive(Clone)]
pub struct AuthClaims(pub Claims);

impl<S> FromRequestParts<S> for AuthClaims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .map(AuthClaims)
            .ok_or(AppError::Handler(ErrorBody {
                code: StatusCode::UNAUTHORIZED,
                message: "Bearer token not found".into(),
            }))
    }
}
