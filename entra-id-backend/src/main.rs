use std::time::Duration;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
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
use crate::entra_id::EntraIdTokenVerifier;
use crate::handlers::create_routes;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app_config = AppConfig::load()?;

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
    let token_verifier = EntraIdTokenVerifier::new(
        // テナント
        app_config.entra_id.tenants.clone(),
        // JWKキャッシュのTTL
        Duration::from_secs(app_config.entra_id.jwk_cache_ttl),
        // 定期的にJWKsをリフレッシュする間隔
        Duration::from_secs(app_config.entra_id.refresh_jwks_interval),
        // テナントのJWKsをリフレッシュする最小間隔
        Duration::from_secs(app_config.entra_id.refresh_tenant_jwks_interval),
        // シャットダウン用トークン
        shutdown_token.clone(),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to initialize Entra ID Token Verifier service");
        e
    })?;

    // ルーターの作成
    let app_state = AppState {
        token_verifier,
        client_credentials: app_config.client_credentials,
    };
    let router = create_routes().with_state(app_state.clone());

    // Webサーバーの起動
    tracing::info!("Starting the web server on port {}", app_config.web.port);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", app_config.web.port)).await?;
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
