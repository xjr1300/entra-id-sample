use axum::{
    RequestPartsExt as _,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use axum_extra::{
    TypedHeader,
    headers::authorization::{Authorization, Bearer},
};
use secrecy::SecretString;

use crate::{
    common::{AppError, ErrorBody},
    entra_id::{BearerToken, Claims},
    state::AppState,
};

/// 認証済みクレームをリクエストから抽出するエクストラクタ
#[derive(Clone)]
pub struct AuthClaims {
    pub claims: Claims,
    pub token: BearerToken,
}

impl FromRequestParts<AppState> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        app_state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                AppError::Handler(ErrorBody {
                    code: StatusCode::UNAUTHORIZED,
                    message: "Bearer token not found".into(),
                })
            })?;
        let token = BearerToken(SecretString::new(bearer.token().into()));

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

        Ok(AuthClaims { claims, token })
    }
}
