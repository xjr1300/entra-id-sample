use axum::{extract::State, http::StatusCode, response::IntoResponse};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use crate::{
    common::{AppResult, RequestError},
    entra_id::{BearerToken, extract_issuer_from_iss},
    handlers::{
        BACKEND_ACCESS_TOKEN_SCOPE, exists_scope, extractors::AuthClaims,
        retrieve_graph_access_token,
    },
    state::AppState,
};

#[tracing::instrument(skip(app_state, claims, access_token))]
pub async fn me(
    State(app_state): State<AppState>,
    AuthClaims {
        claims,
        access_token,
    }: AuthClaims,
) -> AppResult<impl IntoResponse> {
    // スコープを確認
    exists_scope(&claims.scp, BACKEND_ACCESS_TOKEN_SCOPE)?;

    // テナントIDを取得
    let tenant_id = extract_issuer_from_iss(&claims.iss).map_err(|e| {
        tracing::error!(error = %e, "Failed to extract tenant ID from iss");
        RequestError {
            code: StatusCode::UNAUTHORIZED,
            message: format!("Failed to extract tenant ID from iss: {e}"),
        }
    })?;

    // HTTPクライアントをステートから取得

    let client = &app_state.http_client;
    // OBOでGraph APIを呼び出すためのアクセストークンを取得
    let client_id = &app_state.client_credentials.client_id;
    let client_secret = &app_state.client_credentials.client_secret;
    let access_token =
        retrieve_graph_access_token(client, &tenant_id, client_id, client_secret, &access_token)
            .await?;

    // Graph APIの呼び出し
    let response = fetch_graph_me(client, &access_token).await?;

    // レスポンスを返す
    Ok((StatusCode::OK, axum::Json(response)).into_response())
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
    department: Option<String>,
    office_location: Option<String>,
    business_phones: Option<Vec<String>>,
    mobile_phone: Option<String>,
    preferred_language: Option<String>,
}

async fn fetch_graph_me(
    client: &reqwest::Client,
    access_token: &BearerToken,
) -> AppResult<MeResponse> {
    client
        .get("https://graph.microsoft.com/v1.0/me")
        .bearer_auth(access_token.0.expose_secret())
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
        })
}
