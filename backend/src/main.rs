use std::{sync::Arc, time::Duration};

use axum::http::{HeaderName, Response};
use axum::{body::Body, http::Request};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::request_id::{MakeRequestUuid, RequestId};
use tower_http::{request_id::SetRequestIdLayer, trace::TraceLayer};
use tracing::Span;
use tracing::subscriber::set_global_default;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt};

mod common;
mod config;
mod entra_id;
mod handlers;
mod state;

use crate::config::AppConfig;
use crate::entra_id::{EntraIdTokenVerifier, EntraIdTokenVerifierBuilder, RetryConfig};
use crate::handlers::create_routes;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // アプリケーション設定の読み込み
    let app_config = AppConfig::load()?;
    let web_server_port = app_config.web.port;
    let client_credentials = app_config.client_credentials.clone();
    let retry_config = RetryConfig::new(
        app_config.entra_id.jwks_request_max_attempts,
        Duration::from_millis(app_config.entra_id.jwks_request_retry_initial_wait),
        app_config.entra_id.jwks_request_retry_backoff_multiplier,
        Duration::from_secs(app_config.entra_id.jwks_request_retry_max_wait),
    )?;

    // ログの設定
    LogTracer::init().map_err(|e| {
        tracing::error!(error = %e, "Failed to initialize LogTracer");
        e
    })?;
    let subscriber = create_subscriber("entra-id-backend", &app_config.log_level);
    set_global_default(subscriber).map_err(|e| {
        tracing::error!(error = %e, "Failed to set global default subscriber");
        e
    })?;
    tracing::info!("Starting the application...");

    // Entra IDトークン検証者の構築
    let shutdown_token = CancellationToken::new();
    let token_verifier =
        build_token_verifier(app_config, retry_config, shutdown_token.clone()).await?;

    // ルーターの作成
    let app_state = AppState {
        token_verifier,
        client_credentials,
    };
    let x_request_id = HeaderName::from_static("x-request-id");
    let router = create_routes()
        .with_state(app_state.clone())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_span)
                .on_response(on_response),
        )
        .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid));

    // Webサーバーの起動
    tracing::info!("Starting the web server on port {}", web_server_port);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", web_server_port)).await?;
    axum::serve(listener, router)
        // `shutdown_signal`関数は、非同期関数であり`impl Future<Output = ()>`を返す。
        // したがって、axumは、`with_graceful_shutdown`で渡された`Future`が完了したとき、
        // axumサーバーをシャットダウンする。
        .with_graceful_shutdown(shutdown_signal(shutdown_token.clone()))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to start the web server");
            e
        })?;

    // Webサーバーが優雅にシャットダウンされたかをログに出力
    if shutdown_token.is_cancelled() {
        tracing::info!("Application has been shut down gracefully");
    } else {
        tracing::warn!("Application has been shut down unexpectedly");
    }

    Ok(())
}

/// ログ購読者を作成する。
///
/// # Arguments
///
/// * `name` - アプリケーション名
/// * `level` - ログレベル
///
/// # Returns
///
/// 作成したログ購読者
fn create_subscriber(name: &str, level: &str) -> impl tracing::Subscriber + Send + Sync {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let formatting_layer = BunyanFormattingLayer::new(name.into(), std::io::stdout);
    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

async fn build_token_verifier(
    mut app_config: AppConfig,
    retry_config: RetryConfig,
    shutdown_token: CancellationToken,
) -> anyhow::Result<Arc<EntraIdTokenVerifier>> {
    EntraIdTokenVerifierBuilder::default()
        .tenants(std::mem::take(&mut app_config.entra_id.tenants))?
        .jwk_cache_ttl(Duration::from_secs(app_config.entra_id.jwk_cache_ttl))?
        .refresh_jwks_interval(Duration::from_secs(
            app_config.entra_id.refresh_jwks_interval,
        ))?
        .refresh_tenant_jwks_interval(Duration::from_secs(
            app_config.entra_id.refresh_tenant_jwks_interval,
        ))?
        .entra_id_connection_timeout(Duration::from_secs(app_config.entra_id.connection_timeout))?
        .entra_id_timeout(Duration::from_secs(app_config.entra_id.timeout))?
        .retry_config(retry_config)
        .shutdown(shutdown_token)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!(e))
}

/// シャットダウンシグナルを受け取るまで待機する非同期関数
///
/// # Arguments
///
/// * `token` - シャットダウン用のキャンセレーショントークン
async fn shutdown_signal(token: CancellationToken) {
    use tokio::signal;

    // Ctrl+Cシグナルの待機
    let ctrl_c = async {
        // Ctrl+C（SIGINT: Signal Interrupt）シグナルを待機
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(error = %e, "Failed to install Ctrl+C handler");
        }
    };

    // SIGTERMシグナルの待機（Unix系OSのみ）
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                // SIGTERMシグナルを待機
                sigterm.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
            }
        }
    };

    // Windowsやその他のOSではSIGTERMが利用できないため、永遠に完了しないFutureを使用
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // `ctrl_c`と`terminate`のいずれかが完了するまで待機
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
    token.cancel();
}

fn make_span(request: &Request<Body>) -> Span {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("unknown");
    tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri().path(),
    )
}

fn on_response(response: &Response<Body>, latency: Duration, _span: &Span) {
    let status = response.status();
    if status.is_server_error() {
        tracing::error!(%status, latency_ms = latency.as_millis(), "request failed");
    } else if status.is_client_error() {
        tracing::warn!(%status, latency_ms = latency.as_millis(), "client error");
    } else {
        tracing::info!(%status, latency_ms = latency.as_millis(), "request completed");
    }
}
