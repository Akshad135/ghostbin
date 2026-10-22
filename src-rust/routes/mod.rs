use axum::{
    Router,
    routing::{get, post},
};

use crate::state::SharedState;

pub mod auth;
pub mod events;
pub mod files;
pub mod pastes;
pub mod ping;
pub mod shares;
pub mod util;

/// Build the API sub-router (mounted at `/api`).
pub fn api_router() -> Router<SharedState> {
    Router::new()
        .route("/ping", get(ping::handle_ping))
        .route("/events", get(events::handle_events))
        .route("/auth/params", get(auth::handle_params))
        .route("/auth/setup", post(auth::handle_setup))
        .route("/auth/login", post(auth::handle_login))
        .route("/auth/logout", post(auth::handle_logout))
        .route(
            "/auth/change-passphrase",
            post(auth::handle_change_passphrase),
        )
        .route("/vault", get(auth::handle_vault))
        .route(
            "/pastes",
            get(pastes::handle_list).post(pastes::handle_create),
        )
        .route(
            "/pastes/{id}",
            get(pastes::handle_get)
                .put(pastes::handle_update)
                .delete(pastes::handle_delete),
        )
        .route(
            "/pastes/{id}/share",
            get(shares::handle_status)
                .post(shares::handle_create)
                .delete(shares::handle_delete),
        )
        .route("/files", post(files::handle_upload))
        .route("/files/{id}", get(files::handle_download))
        .route("/shares/{id}/params", get(shares::handle_params))
        .route("/shares/{id}/challenge", post(shares::handle_challenge))
        .route("/shares/{id}/unlock", post(shares::handle_unlock))
        .route("/shares/{id}/view", post(shares::handle_view))
}
