use std::time::Duration;

use axum::{Router, routing};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::subscriber::set_global_default;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt};

pub mod common;
pub mod config;
pub mod entra_id;
mod handlers;
pub mod state;

use crate::config::AppConfig;
use crate::entra_id::EntraIdTokenVerifier;
use crate::handlers::{health_check, me};
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    LogTracer::init().map_err(|e| {
        tracing::error!(error = %e, "Failed to initialize LogTracer");
        e
    })?;
    let subscriber = create_subscriber("entra-id-backend", "info");
    set_global_default(subscriber).map_err(|e| {
        tracing::error!(error = %e, "Failed to set global default subscriber");
        e
    })?;

    tracing::info!("Starting the application...");

    let app_config = AppConfig::load().map_err(|e| {
        tracing::error!(error = %e, "Failed to load application configuration");
        e
    })?;
    tracing::info!("Loaded application config");

    let shutdown_token = CancellationToken::new();
    let token_verifier = EntraIdTokenVerifier::new(
        app_config.entra_id.tenants.clone(),
        Duration::from_secs(app_config.entra_id.jwk_cache_ttl),
        Duration::from_secs(app_config.entra_id.refresh_jwks_interval),
        Duration::from_secs(app_config.entra_id.refresh_tenant_jwks_interval),
        shutdown_token.clone(),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to initialize Entra ID Token Verifier service");
        e
    })?;

    let app_state = AppState {
        token_verifier,
        client_credentials: app_config.client_credentials,
    };
    let router = create_router(app_state.clone());

    tracing::info!("Starting the web server on port {}", app_config.web.port);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", app_config.web.port)).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(shutdown_token.clone()))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to start the web server");
            e
        })?;
    if shutdown_token.is_cancelled() {
        tracing::info!("Application has been shut down gracefully");
    }

    Ok(())
}

fn create_subscriber(name: &str, level: &str) -> impl tracing::Subscriber + Send + Sync {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let formatting_layer = BunyanFormattingLayer::new(name.into(), std::io::stdout);
    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

async fn shutdown_signal(token: CancellationToken) {
    use tokio::signal;

    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(error = %e, "Failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
    token.cancel();
}

fn create_router(app_state: AppState) -> Router {
    Router::new().nest("/api", api_routes(app_state))
}

fn api_routes(app_state: AppState) -> Router {
    Router::new()
        .merge(unprotected_api_routes(app_state.clone()))
        .merge(protected_api_routes(app_state.clone()))
}

fn unprotected_api_routes(app_state: AppState) -> Router {
    Router::new()
        .route("/health-check", routing::get(health_check))
        .with_state(app_state)
}

fn protected_api_routes(app_state: AppState) -> Router {
    Router::new()
        .route("/me", routing::get(me))
        .with_state(app_state)
}
