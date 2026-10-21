use axum::{
    Router,
    routing::{get, post},
};

use crate::state::SharedState;

pub mod auth;
pub mod file;
pub mod paste;
pub mod ping;
pub mod stream;

/// Build the API sub-router (mounted at `/api`).
pub fn api_router() -> Router<SharedState> {
    Router::new()
        .route("/ping", get(ping::handle_ping))
        .route("/stream", get(stream::handle_stream))
        .route("/auth/params", get(auth::handle_params))
        .route("/auth/setup", post(auth::handle_setup))
        .route("/auth/login", post(auth::handle_login))
        .route("/auth/logout", post(auth::handle_logout))
        .route(
            "/auth/change-passphrase",
            post(auth::handle_change_passphrase),
        )
        .route("/vault", get(auth::handle_vault))
        // Legacy paste/file routes are replaced in the next build phase.
        .route("/paste", get(paste::handle_list).post(paste::handle_create))
        .route(
            "/paste/",
            get(paste::handle_list).post(paste::handle_create),
        )
        .route(
            "/paste/{slug}",
            get(paste::handle_get)
                .put(paste::handle_update)
                .delete(paste::handle_delete),
        )
        .route("/paste/{slug}/unlock", post(paste::handle_unlock))
        .route("/file/upload", post(file::handle_upload))
        .route(
            "/file/{slug}",
            get(file::handle_download).delete(file::handle_delete),
        )
}
