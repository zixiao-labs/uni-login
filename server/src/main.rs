//! Zixiao Labs Cloud Account — standalone OAuth 2.0 provider.
//!
//! Runs as a single Axum service behind the SPA at ./src. The frontend
//! exchanges user credentials for a session JWT via /api/login, then uses
//! that session to authorize downstream clients at /api/oauth/authorize.
//! Relying parties complete the flow at /oauth/token and /oauth/userinfo.

mod app_state;
mod auth;
mod config;
mod db;
mod error;
mod oauth;

use std::sync::Arc;

use anyhow::Result;
use app_state::AppState;
use axum::{
    Router,
    http::HeaderValue,
    routing::{get, post},
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::oauth::AuthCodeStore;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zxcloud_account_server=info,tower_http=info".into()),
        )
        .init();

    let cfg = Arc::new(config::Config::from_env()?);
    let db = db::connect(&cfg.database_url).await?;
    db::run_migrations(&db).await?;

    let state = AppState {
        config: cfg.clone(),
        db,
        codes: Arc::new(AuthCodeStore::new()),
    };

    let cors = build_cors_layer(cfg.cors_allowed_origins.as_deref())?;

    let app = Router::new()
        .route("/api/register", post(auth::register))
        .route("/api/login", post(auth::login))
        .route("/api/me", get(auth::me))
        .route("/api/oauth/authorize", post(oauth::authorize))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/userinfo", get(oauth::userinfo))
        .route("/health", get(|| async { "ok" }))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!(bind = %cfg.bind, "zxcloud-account-server listening");
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_cors_layer(raw: Option<&str>) -> Result<CorsLayer> {
    use axum::http::Method;
    use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
        .allow_credentials(false);
    let layer = match raw {
        None | Some("") => base,
        Some("*") => base.allow_origin(AllowOrigin::any()),
        Some(list) => {
            let origins: Vec<HeaderValue> = list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<HeaderValue>()
                        .map_err(|e| anyhow::anyhow!("invalid CORS origin {s:?}: {e}"))
                })
                .collect::<Result<_>>()?;
            base.allow_origin(origins)
        }
    };
    Ok(layer)
}
