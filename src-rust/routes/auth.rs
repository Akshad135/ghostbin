use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::{FromRow, SqlitePool};

use crate::auth::{self, KdfParams};
use crate::state::{AppState, LoginAttempts};

const MAX_LOGIN_ATTEMPTS: u32 = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
/// Account-wide cap on login failures per window (plan §7.3: "per IP and
/// per account"). Single-account app, so this is a global counter that
/// throttles distributed guessing across many IPs.
const MAX_ACCOUNT_LOGIN_FAILURES: u32 = 30;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupBody {
    auth_key: String,
    kdf_salt: String,
    kdf_params: KdfParams,
    wrapped_vault_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginBody {
    auth_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePassphraseBody {
    old_auth_key: String,
    new_auth_key: String,
    new_kdf_salt: String,
    new_kdf_params: KdfParams,
    new_wrapped_vault_key: String,
}

#[derive(FromRow)]
struct SettingsRow {
    kdf_salt: Vec<u8>,
    kdf_params: String,
    auth_hash: Vec<u8>,
    wrapped_vault_key: Vec<u8>,
}

fn api_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": message,
            "code": code,
        })),
    )
        .into_response()
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
}

async fn load_settings(pool: &SqlitePool) -> Result<Option<SettingsRow>, sqlx::Error> {
    sqlx::query_as::<_, SettingsRow>(
        "SELECT kdf_salt, kdf_params, auth_hash, wrapped_vault_key
         FROM settings WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
}

fn login_retry_after(state: &AppState, ip: std::net::IpAddr) -> Option<u64> {
    let mut attempts = state.login_attempts.lock().unwrap();
    let entry = attempts.get_mut(&ip)?;
    if entry.window_start.elapsed() > LOGIN_WINDOW {
        entry.count = 0;
        entry.window_start = Instant::now();
    }
    if entry.count >= MAX_LOGIN_ATTEMPTS {
        Some(
            LOGIN_WINDOW
                .saturating_sub(entry.window_start.elapsed())
                .as_secs()
                .max(1),
        )
    } else {
        None
    }
}

fn record_login_failure(state: &AppState, ip: std::net::IpAddr) {
    let mut attempts = state.login_attempts.lock().unwrap();
    let entry = attempts.entry(ip).or_insert_with(|| LoginAttempts {
        count: 0,
        window_start: Instant::now(),
        locked_until: None,
    });
    if entry.window_start.elapsed() > LOGIN_WINDOW {
        entry.count = 0;
        entry.window_start = Instant::now();
    }
    entry.count += 1;
    if attempts.len() > 10_000 {
        attempts.retain(|_, entry| entry.window_start.elapsed() < LOGIN_WINDOW);
    }
}

fn clear_login_failures(state: &AppState, ip: std::net::IpAddr) {
    state.login_attempts.lock().unwrap().remove(&ip);
}

/// Account-wide failure window (plan §7.3 "per account" limit).
fn account_login_retry_after(state: &AppState) -> Option<u64> {
    let mut failures = state
        .account_login_failures
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if failures.window_start.elapsed() > LOGIN_WINDOW {
        failures.count = 0;
        failures.window_start = Instant::now();
    }
    if failures.count >= MAX_ACCOUNT_LOGIN_FAILURES {
        Some(
            LOGIN_WINDOW
                .saturating_sub(failures.window_start.elapsed())
                .as_secs()
                .max(1),
        )
    } else {
        None
    }
}

fn record_account_login_failure(state: &AppState) {
    let mut failures = state
        .account_login_failures
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if failures.window_start.elapsed() > LOGIN_WINDOW {
        failures.count = 0;
        failures.window_start = Instant::now();
    }
    failures.count = failures.count.saturating_add(1);
}

fn clear_account_login_failures(state: &AppState) {
    let mut failures = state
        .account_login_failures
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    failures.count = 0;
    failures.window_start = Instant::now();
}

fn rate_limited(retry_after: u64) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string()).expect("retry-after is numeric"),
    );
    (
        StatusCode::TOO_MANY_REQUESTS,
        headers,
        Json(serde_json::json!({
            "error": "Too many login attempts",
            "code": "RATE_LIMITED",
            "retryAfter": retry_after,
        })),
    )
        .into_response()
}

/// GET /api/auth/params — public KDF parameters for setup/login.
pub async fn handle_params(State(state): State<Arc<AppState>>) -> Response {
    match load_settings(&state.db).await {
        Ok(Some(settings)) => {
            let params = match serde_json::from_str::<KdfParams>(&settings.kdf_params) {
                Ok(params) => params,
                Err(error) => {
                    tracing::error!("Stored KDF params are invalid: {error}");
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL",
                        "Stored KDF parameters are invalid",
                    );
                }
            };
            (
                StatusCode::OK,
                no_store(),
                Json(serde_json::json!({
                    "configured": true,
                    "kdfSalt": auth::encode_base64url(&settings.kdf_salt),
                    "kdfParams": params,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::OK,
            no_store(),
            Json(serde_json::json!({ "configured": false })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!("Failed to load auth parameters: {error}");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to load auth parameters",
            )
        }
    }
}

/// POST /api/auth/setup — one-time vault setup.
pub async fn handle_setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SetupBody>,
) -> Response {
    if !auth::check_fetch_site(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Cross-site setup request rejected",
        );
    }

    let Some(auth_key) = auth::decode_base64url(&body.auth_key, auth::AUTH_KEY_BYTES) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "authKey must be 32 base64url bytes",
        );
    };
    let Some(kdf_salt) = auth::decode_base64url(&body.kdf_salt, auth::KDF_SALT_BYTES) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "kdfSalt must be 16 base64url bytes",
        );
    };
    if let Err(message) = body.kdf_params.validate() {
        return api_error(StatusCode::BAD_REQUEST, "INVALID_REQUEST", message);
    }
    let Some(wrapped_vault_key) = auth::decode_vault_envelope(&body.wrapped_vault_key) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "wrappedVaultKey must be a v1 AES-GCM envelope",
        );
    };

    match load_settings(&state.db).await {
        Ok(Some(_)) => {
            return api_error(
                StatusCode::CONFLICT,
                "ALREADY_CONFIGURED",
                "This server is already configured",
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!("Failed to check setup state: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to check setup state",
            );
        }
    }

    let auth_hash = auth::hash_auth_key(&auth_key);
    let kdf_params = match serde_json::to_string(&body.kdf_params) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("Failed to serialize KDF params: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to store KDF parameters",
            );
        }
    };
    let now = auth::now_unix();

    let result = sqlx::query(
        "INSERT INTO settings
            (id, kdf_salt, kdf_params, auth_hash, wrapped_vault_key, created_at, updated_at)
         VALUES (1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&kdf_salt)
    .bind(&kdf_params)
    .bind(auth_hash.as_slice())
    .bind(&wrapped_vault_key)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await;

    if let Err(error) = result {
        if is_unique_violation(&error) {
            return api_error(
                StatusCode::CONFLICT,
                "ALREADY_CONFIGURED",
                "This server is already configured",
            );
        }
        tracing::error!("Failed to create settings: {error}");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Failed to save setup",
        );
    }

    let created = match auth::create_session(&state.db).await {
        Ok(session) => session,
        Err(error) => {
            tracing::error!("Failed to create setup session: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Setup saved, but session creation failed",
            );
        }
    };

    let mut headers = no_store();
    auth::append_auth_cookies(&mut headers, &created.session.token, &created.csrf_token);

    (
        StatusCode::CREATED,
        headers,
        Json(serde_json::json!({
            "success": true,
            "csrfToken": created.csrf_token,
        })),
    )
        .into_response()
}

/// POST /api/auth/login — verify the client-derived auth key.
pub async fn handle_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    if !auth::check_fetch_site(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Cross-site login request rejected",
        );
    }

    let ip = state.client_ip(addr.ip(), &headers);

    if let Some(retry_after) = login_retry_after(&state, ip) {
        return rate_limited(retry_after);
    }
    if let Some(retry_after) = account_login_retry_after(&state) {
        return rate_limited(retry_after);
    }

    let Some(auth_key) = auth::decode_base64url(&body.auth_key, auth::AUTH_KEY_BYTES) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "authKey must be 32 base64url bytes",
        );
    };

    let settings = match load_settings(&state.db).await {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            return api_error(
                StatusCode::CONFLICT,
                "SETUP_REQUIRED",
                "This server has not been set up",
            );
        }
        Err(error) => {
            tracing::error!("Failed to load auth settings: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to load auth settings",
            );
        }
    };

    if !auth::auth_key_matches(&settings.auth_hash, &auth_key) {
        record_login_failure(&state, ip);
        record_account_login_failure(&state);
        return api_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_AUTH",
            "Invalid authentication key",
        );
    }

    clear_login_failures(&state, ip);
    clear_account_login_failures(&state);

    if let Some(old_token) = auth::session_token_from_headers(&headers)
        && let Err(error) = auth::revoke_session(&state.db, &old_token).await
    {
        tracing::warn!("Failed to revoke old session during login: {error}");
    }

    let created = match auth::create_session(&state.db).await {
        Ok(session) => session,
        Err(error) => {
            tracing::error!("Failed to create login session: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to create session",
            );
        }
    };

    if let Err(error) = auth::delete_expired_sessions(&state.db, auth::now_unix()).await {
        tracing::warn!("Failed to clean expired sessions: {error}");
    }

    let mut response_headers = no_store();
    auth::append_auth_cookies(
        &mut response_headers,
        &created.session.token,
        &created.csrf_token,
    );

    (
        StatusCode::OK,
        response_headers,
        Json(serde_json::json!({
            "success": true,
            "csrfToken": created.csrf_token,
        })),
    )
        .into_response()
}

/// POST /api/auth/logout — revoke the current session.
pub async fn handle_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !auth::check_csrf(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Missing or invalid CSRF token",
        );
    }

    if let Some(token) = auth::session_token_from_headers(&headers)
        && let Err(error) = auth::revoke_session(&state.db, &token).await
    {
        tracing::warn!("Failed to delete session during logout: {error}");
    }

    let mut response_headers = no_store();
    auth::append_clear_cookies(&mut response_headers);

    (
        StatusCode::OK,
        response_headers,
        Json(serde_json::json!({ "success": true })),
    )
        .into_response()
}

/// POST /api/auth/change-passphrase — replace the auth key and wrapped vault.
pub async fn handle_change_passphrase(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ChangePassphraseBody>,
) -> Response {
    if !auth::check_csrf(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Missing or invalid CSRF token",
        );
    }

    let session = match auth::current_session(&state.db, &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication required",
            );
        }
        Err(error) => {
            tracing::error!("Failed to load session: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to load session",
            );
        }
    };

    let Some(old_auth_key) = auth::decode_base64url(&body.old_auth_key, auth::AUTH_KEY_BYTES)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "oldAuthKey must be 32 base64url bytes",
        );
    };
    let Some(new_auth_key) = auth::decode_base64url(&body.new_auth_key, auth::AUTH_KEY_BYTES)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "newAuthKey must be 32 base64url bytes",
        );
    };
    let Some(new_kdf_salt) = auth::decode_base64url(&body.new_kdf_salt, auth::KDF_SALT_BYTES)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "newKdfSalt must be 16 base64url bytes",
        );
    };
    if let Err(message) = body.new_kdf_params.validate() {
        return api_error(StatusCode::BAD_REQUEST, "INVALID_REQUEST", message);
    }
    let Some(new_wrapped_vault_key) = auth::decode_vault_envelope(&body.new_wrapped_vault_key)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "newWrappedVaultKey must be a v1 AES-GCM envelope",
        );
    };

    let settings = match load_settings(&state.db).await {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            return api_error(
                StatusCode::CONFLICT,
                "SETUP_REQUIRED",
                "This server has not been set up",
            );
        }
        Err(error) => {
            tracing::error!("Failed to load auth settings: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to load auth settings",
            );
        }
    };

    if !auth::auth_key_matches(&settings.auth_hash, &old_auth_key) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_AUTH",
            "Invalid authentication key",
        );
    }

    let new_auth_hash = auth::hash_auth_key(&new_auth_key);
    let new_kdf_params = match serde_json::to_string(&body.new_kdf_params) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("Failed to serialize new KDF params: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to store KDF parameters",
            );
        }
    };
    let now = auth::now_unix();

    let mut transaction = match state.db.begin().await {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!("Failed to begin passphrase change: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to change passphrase",
            );
        }
    };

    let updated = sqlx::query(
        "UPDATE settings
         SET kdf_salt = ?, kdf_params = ?, auth_hash = ?, wrapped_vault_key = ?, updated_at = ?
         WHERE id = 1",
    )
    .bind(&new_kdf_salt)
    .bind(&new_kdf_params)
    .bind(new_auth_hash.as_slice())
    .bind(&new_wrapped_vault_key)
    .bind(now)
    .execute(&mut *transaction)
    .await;

    match updated {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            let _ = transaction.rollback().await;
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to update settings",
            );
        }
        Err(error) => {
            tracing::error!("Failed to update settings: {error}");
            let _ = transaction.rollback().await;
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to change passphrase",
            );
        }
    }

    if let Err(error) = sqlx::query("DELETE FROM sessions WHERE id != ?")
        .bind(&session.id)
        .execute(&mut *transaction)
        .await
    {
        tracing::error!("Failed to revoke other sessions: {error}");
        let _ = transaction.rollback().await;
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Failed to revoke other sessions",
        );
    }

    if let Err(error) = transaction.commit().await {
        tracing::error!("Failed to commit passphrase change: {error}");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Failed to change passphrase",
        );
    }

    (
        StatusCode::OK,
        no_store(),
        Json(serde_json::json!({ "success": true })),
    )
        .into_response()
}

/// GET /api/vault — return the owner's wrapped vault key.
pub async fn handle_vault(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match auth::current_session(&state.db, &headers).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication required",
            );
        }
        Err(error) => {
            tracing::error!("Failed to load session: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to load session",
            );
        }
    }

    let settings = match load_settings(&state.db).await {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            return api_error(
                StatusCode::CONFLICT,
                "SETUP_REQUIRED",
                "This server has not been set up",
            );
        }
        Err(error) => {
            tracing::error!("Failed to load vault: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Failed to load vault",
            );
        }
    };

    let kdf_params = match serde_json::from_str::<KdfParams>(&settings.kdf_params) {
        Ok(params) => params,
        Err(error) => {
            tracing::error!("Stored KDF params are invalid: {error}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Stored KDF parameters are invalid",
            );
        }
    };

    let Some(wrapped_vault_key) = auth::encode_vault_envelope(&settings.wrapped_vault_key) else {
        tracing::error!("Stored wrapped vault key has an invalid length");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Stored vault key is invalid",
        );
    };

    (
        StatusCode::OK,
        no_store(),
        Json(serde_json::json!({
            "kdfSalt": auth::encode_base64url(&settings.kdf_salt),
            "kdfParams": kdf_params,
            "wrappedVaultKey": wrapped_vault_key,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_state() -> Arc<AppState> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite");
        crate::db::init_schema(&pool, false)
            .await
            .expect("schema init");
        Arc::new(AppState::new(
            pool,
            "dist".to_string(),
            "uploads".to_string(),
            1024,
            1024,
            Vec::new(),
        ))
    }

    fn setup_body() -> SetupBody {
        SetupBody {
            auth_key: auth::encode_base64url(&[1u8; auth::AUTH_KEY_BYTES]),
            kdf_salt: auth::encode_base64url(&[2u8; auth::KDF_SALT_BYTES]),
            kdf_params: KdfParams::default(),
            wrapped_vault_key: format!(
                "v1:{}",
                auth::encode_base64url(&[3u8; auth::WRAPPED_VAULT_KEY_BYTES])
            ),
        }
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body");
        serde_json::from_slice(&bytes).expect("JSON response")
    }

    fn set_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| {
                let pair = value.split(';').next()?;
                pair.strip_prefix(&format!("{name}=")).map(str::to_string)
            })
    }

    fn session_headers(session_token: &str, csrf_token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}={session_token}; {}={csrf_token}",
                auth::SESSION_COOKIE_NAME,
                auth::CSRF_COOKIE_NAME,
            ))
            .unwrap(),
        );
        headers.insert("x-csrf-token", HeaderValue::from_str(csrf_token).unwrap());
        headers
    }

    #[tokio::test]
    async fn setup_login_and_vault() {
        let state = test_state().await;
        let setup = setup_body();
        let auth_key = setup.auth_key.clone();

        let response = handle_setup(State(state.clone()), HeaderMap::new(), Json(setup)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let setup_csrf = response_json(response).await["csrfToken"]
            .as_str()
            .unwrap()
            .to_string();

        let response = handle_login(
            State(state.clone()),
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))),
            HeaderMap::new(),
            Json(LoginBody {
                auth_key: auth_key.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookies = response.headers().clone();
        let session_token = set_cookie_value(&cookies, auth::SESSION_COOKIE_NAME).unwrap();
        let csrf_token = set_cookie_value(&cookies, auth::CSRF_COOKIE_NAME).unwrap();
        assert_ne!(setup_csrf, csrf_token);

        let response = handle_vault(
            State(state.clone()),
            session_headers(&session_token, &csrf_token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert!(body["wrappedVaultKey"].as_str().unwrap().starts_with("v1:"));
        assert_eq!(body["kdfParams"]["hashLength"], 32);
    }

    #[tokio::test]
    async fn setup_is_one_time() {
        let state = test_state().await;
        let response = handle_setup(State(state.clone()), HeaderMap::new(), Json(setup_body())).await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = handle_setup(State(state), HeaderMap::new(), Json(setup_body())).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response_json(response).await["code"], "ALREADY_CONFIGURED");
    }

    #[tokio::test]
    async fn login_failures_are_rate_limited() {
        let state = test_state().await;
        let response = handle_setup(State(state.clone()), HeaderMap::new(), Json(setup_body())).await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let bad_key = auth::encode_base64url(&[9u8; auth::AUTH_KEY_BYTES]);
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            let response = handle_login(
                State(state.clone()),
                ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))),
                HeaderMap::new(),
                Json(LoginBody {
                    auth_key: bad_key.clone(),
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let response = handle_login(
            State(state),
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))),
            HeaderMap::new(),
            Json(LoginBody { auth_key: bad_key }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn login_failures_are_rate_limited_per_account() {
        let state = test_state().await;
        let response = handle_setup(State(state.clone()), HeaderMap::new(), Json(setup_body())).await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let bad_key = auth::encode_base64url(&[9u8; auth::AUTH_KEY_BYTES]);
        // Spread failures across many IPs so only the account-wide counter
        // can trip (plan §7.3: per IP and per account).
        for index in 0..MAX_ACCOUNT_LOGIN_FAILURES {
            let response = handle_login(
                State(state.clone()),
                ConnectInfo(SocketAddr::from((
                    [127, 0, 0, 1 + (index % 200) as u8],
                    1234,
                ))),
                HeaderMap::new(),
                Json(LoginBody {
                    auth_key: bad_key.clone(),
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // A different, previously clean IP must still be throttled.
        let response = handle_login(
            State(state.clone()),
            ConnectInfo(SocketAddr::from(([127, 0, 0, 2], 1234))),
            HeaderMap::new(),
            Json(LoginBody { auth_key: bad_key }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));

        // A correct login from a clean IP is throttled too while the
        // account-wide window is saturated.
        let good_key = auth::encode_base64url(&[1u8; auth::AUTH_KEY_BYTES]);
        let response = handle_login(
            State(state),
            ConnectInfo(SocketAddr::from(([127, 0, 0, 3], 1234))),
            HeaderMap::new(),
            Json(LoginBody { auth_key: good_key }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn change_passphrase_keeps_current_session_and_revokes_others() {
        let state = test_state().await;
        let setup = setup_body();
        let old_auth_key = setup.auth_key.clone();
        let response = handle_setup(State(state.clone()), HeaderMap::new(), Json(setup)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let setup_cookies = response.headers().clone();
        let setup_session = set_cookie_value(&setup_cookies, auth::SESSION_COOKIE_NAME).unwrap();
        let setup_csrf = set_cookie_value(&setup_cookies, auth::CSRF_COOKIE_NAME).unwrap();

        let response = handle_login(
            State(state.clone()),
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))),
            HeaderMap::new(),
            Json(LoginBody {
                auth_key: old_auth_key.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookies = response.headers().clone();
        let session_token = set_cookie_value(&cookies, auth::SESSION_COOKIE_NAME).unwrap();
        let csrf_token = set_cookie_value(&cookies, auth::CSRF_COOKIE_NAME).unwrap();

        let new_auth_key = auth::encode_base64url(&[4u8; auth::AUTH_KEY_BYTES]);
        let response = handle_change_passphrase(
            State(state.clone()),
            session_headers(&session_token, &csrf_token),
            Json(ChangePassphraseBody {
                old_auth_key,
                new_auth_key: new_auth_key.clone(),
                new_kdf_salt: auth::encode_base64url(&[5u8; auth::KDF_SALT_BYTES]),
                new_kdf_params: KdfParams::default(),
                new_wrapped_vault_key: format!(
                    "v1:{}",
                    auth::encode_base64url(&[6u8; auth::WRAPPED_VAULT_KEY_BYTES])
                ),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = handle_vault(
            State(state.clone()),
            session_headers(&session_token, &csrf_token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = handle_vault(
            State(state.clone()),
            session_headers(&setup_session, &setup_csrf),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = handle_login(
            State(state),
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))),
            HeaderMap::new(),
            Json(LoginBody {
                auth_key: new_auth_key,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
