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
    common::RequestError,
    entra_id::{BearerToken, Claims},
    state::AppState,
};

/// 認証済みクレームをリクエストから抽出するエクストラクタ
#[derive(Clone)]
pub struct AuthClaims {
    pub claims: Claims,
    pub access_token: BearerToken,
}

impl FromRequestParts<AppState> for AuthClaims {
    type Rejection = RequestError;

    async fn from_request_parts(
        parts: &mut Parts,
        app_state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| RequestError {
                code: StatusCode::UNAUTHORIZED,
                message: "Authorization header with Bearer token is required".into(),
            })?;
        let token = BearerToken(SecretString::new(bearer.token().into()));

        // バックエンド用アクセストークンを検証
        let claims = app_state
            .token_verifier
            .verify_token(&token)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Token verification failed");
                RequestError {
                    code: StatusCode::UNAUTHORIZED,
                    message: "Invalid access token".into(),
                }
            })?;

        Ok(AuthClaims {
            claims,
            access_token: token,
        })
    }
}
