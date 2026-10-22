use std::{net::SocketAddr, path::Path, sync::Arc};

use axum::Router;
use axum::http::HeaderValue;
use tower_http::cors::{Any, AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::{EnvFilter, fmt};

mod auth;
mod db;
mod envelope;
mod routes;
mod state;

use state::AppState;

#[tokio::main]
async fn main() {
    // Load .env file (best-effort)
    dotenvy::dotenv().ok();

    // Initialise tracing
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // ── Config from env ────────────────────────────────────────────────
    let db_path =
        std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./data/ghostbin.sqlite".to_string());
    let reset_db = std::env::var("RESET_DB")
        .map(|value| value == "1")
        .unwrap_or(false);
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8788);
    let dist_dir = std::env::var("DIST_DIR").unwrap_or_else(|_| "./dist".to_string());
    let uploads_dir = std::env::var("UPLOADS_DIR").unwrap_or_else(|_| "./data/uploads".to_string());
    let max_file_size: usize = std::env::var("MAX_FILE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(52_428_800); // 50 MB default
    let max_text_size: usize = std::env::var("MAX_TEXT_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(524_288); // 512 KB default

    // ALLOWED_ORIGINS controls the CORS policy.
    // Set to your public URL (e.g. https://paste.example.com) to restrict
    // cross-origin access and protect the /unlock endpoint from CPU-exhaustion
    // attacks via malicious third-party pages.
    // If unset, defaults to "*" (allow all origins) — fine for local dev,
    // but a WARNING is logged to remind self-hosters to configure this.
    let allowed_origins_raw = std::env::var("ALLOWED_ORIGINS").unwrap_or_default();
    let cors_layer = build_cors_layer(&allowed_origins_raw);

    // ── Database ───────────────────────────────────────────────────────
    if let Some(parent) = Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent).expect("Failed to create database directory");
    }

    let pool = db::init_pool(&db_path)
        .await
        .expect("Failed to connect to SQLite database");
    db::init_schema(&pool, reset_db)
        .await
        .expect("Failed to initialize database schema");
    tracing::info!("Database ready at {db_path}");

    // ── Uploads directory ──────────────────────────────────────────────
    std::fs::create_dir_all(&uploads_dir).expect("Failed to create uploads directory");
    tracing::info!("Uploads directory ready at {uploads_dir}");

    // ── Shared state ───────────────────────────────────────────────────
    let state = Arc::new(AppState::new(
        pool,
        dist_dir,
        uploads_dir,
        max_file_size,
        max_text_size,
    ));

    tracing::info!(
        "Limits: text={} KB, file={} MB",
        max_text_size / 1_024,
        max_file_size / 1_048_576
    );

    if let Err(error) = routes::files::reconcile_uploads(&state).await {
        tracing::warn!("Upload reconciliation failed: {error}");
    }

    // ── Periodic cleanup ──────────────────────────────────────────────
    // Burned pastes and expired share state are swept every minute. Sessions
    // are swept hourly; they are also rejected inline on every request.
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut session_sweep = 0u32;
        loop {
            interval.tick().await;
            if let Err(error) = routes::pastes::burn_due_pastes(&cleanup_state).await {
                tracing::warn!("Failed to sweep burned pastes: {error}");
            }
            if let Err(error) = routes::shares::cleanup_share_state(&cleanup_state.db).await {
                tracing::warn!("Failed to clean share state: {error}");
            }
            session_sweep += 1;
            if session_sweep >= 60 {
                session_sweep = 0;
                if let Err(error) =
                    auth::delete_expired_sessions(&cleanup_state.db, auth::now_unix()).await
                {
                    tracing::warn!("Failed to delete expired sessions: {error}");
                }
            }
        }
    });

    // ── Router ─────────────────────────────────────────────────────────
    let app = Router::new()
        .nest("/api", routes::api_router())
        .fallback_service(
            tower_http::services::ServeDir::new(&state.dist_dir).not_found_service(
                tower_http::services::ServeFile::new(format!("{}/index.html", state.dist_dir)),
            ),
        )
        .layer(RequestBodyLimitLayer::new(state.max_file_size))
        .layer(cors_layer)
        .with_state(state);

    // ── Start ──────────────────────────────────────────────────────────
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("GhostBin server listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server error");
}

/// Build a CORS layer from the ALLOWED_ORIGINS environment variable.
///
/// - A non-empty value is treated as the single allowed origin (exact match).
///   Multiple origins are not supported intentionally — use a reverse proxy
///   for that case.
/// - An empty value falls back to `*` with a startup warning, preserving
///   zero-config local development while nudging self-hosters to set it.
fn build_cors_layer(allowed_origins: &str) -> CorsLayer {
    let trimmed = allowed_origins.trim().trim_end_matches('/');

    if trimmed.is_empty() {
        tracing::warn!(
            "ALLOWED_ORIGINS is not set — CORS is open to all origins (*).
             This is fine for local development, but you should set
             ALLOWED_ORIGINS=https://your-domain.com in production to protect
             the /unlock endpoint from cross-origin CPU-exhaustion attacks."
        );
        return CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
    }

    match trimmed.parse::<HeaderValue>() {
        Ok(origin) => {
            tracing::info!("CORS restricted to origin: {trimmed}");
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(origin))
                .allow_methods(Any)
                .allow_headers(Any)
        }
        Err(_) => {
            tracing::error!(
                "ALLOWED_ORIGINS value '{}' is not a valid HTTP origin. \
                 Falling back to restrictive CORS (no allowed origins).",
                trimmed
            );
            CorsLayer::new().allow_methods(Any).allow_headers(Any)
        }
    }
}
