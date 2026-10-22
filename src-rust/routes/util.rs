use std::sync::Arc;

use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::auth;
use crate::envelope;
use crate::state::AppState;

pub fn api_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    let mut response = (
        status,
        Json(json!({
            "error": message,
            "code": code,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers
}

pub fn require_csrf(headers: &HeaderMap) -> Result<(), Response> {
    if auth::check_csrf(headers) {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Invalid CSRF token",
        ))
    }
}

pub async fn require_owner(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<auth::Session, Response> {
    match auth::current_session(&state.db, headers).await {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Authentication required",
        )),
        Err(error) => {
            tracing::error!("Session lookup failed: {error}");
            Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Database error",
            ))
        }
    }
}

pub fn is_paste_id(value: &str) -> bool {
    envelope::decode_b64_exact(value, 16).is_some()
}

pub fn is_file_id(value: &str) -> bool {
    envelope::decode_b64_exact(value, 16).is_some()
}

pub fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
}
