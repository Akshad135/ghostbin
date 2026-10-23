use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use sqlx::{FromRow, Sqlite, SqlitePool};

use super::files::FileMetaDto;
use super::pastes::{burn_if_due, delete_paste};
use super::util::{api_error, is_paste_id, no_store_headers, require_csrf, require_owner};
use crate::auth::{self, KdfParams};
use crate::envelope;
use crate::state::{AppState, LoginAttempts};

type HmacSha256 = Hmac<Sha256>;

const SHARE_SALT_BYTES: usize = 16;
const SHARE_AUTH_KEY_BYTES: usize = 32;
const WRAPPED_PASTE_KEY_BYTES: usize = 60;
const SHARE_TOKEN_BYTES: usize = 32;
const CHALLENGE_NONCE_BYTES: usize = 32;
const SHARE_TOKEN_TTL_SECONDS: i64 = 10 * 60;
const CHALLENGE_TTL_SECONDS: i64 = 2 * 60;
const MAX_ACTIVE_CHALLENGES: i64 = 20;
const MAX_UNLOCK_ATTEMPTS: u32 = 5;
const UNLOCK_WINDOW: Duration = Duration::from_secs(60);
const UNLOCK_BASE_LOCKOUT: Duration = Duration::from_secs(60);
const UNLOCK_MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Secondary per-IP cap across all share endpoints (plan §7.4): stops one
/// IP from getting a fresh 5/min budget per share it probes.
const MAX_SHARE_IP_ATTEMPTS: u32 = 30;
const SHARE_IP_WINDOW: Duration = Duration::from_secs(60);
const MAX_SHARE_UNLOCKS: i64 = 1_000_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareBody {
    share_salt: String,
    share_auth_key: String,
    wrapped_paste_key: String,
    expires_at: Option<i64>,
    max_unlocks: Option<i64>,
    replace: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockBody {
    nonce: String,
    proof: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewBody {
    share_token: String,
}

#[derive(FromRow, Clone)]
struct ShareRow {
    paste_id: String,
    share_salt: Vec<u8>,
    share_auth_key: Vec<u8>,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
    unlocks_used: i64,
    max_unlocks: Option<i64>,
    created_at: i64,
    burn_mode: Option<String>,
    burn_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GuestPaste {
    id: String,
    title_ct: String,
    content_ct: String,
    language_ct: Option<String>,
    pinned: bool,
    burn_mode: Option<String>,
    burn_after: Option<i64>,
    burn_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GuestShare {
    share_salt: String,
    wrapped_paste_key: String,
}

#[derive(FromRow)]
struct GuestPasteRow {
    id: String,
    title_ct: Vec<u8>,
    content_ct: Vec<u8>,
    language_ct: Option<Vec<u8>>,
    pinned: i64,
    burn_mode: Option<String>,
    burn_after: Option<i64>,
    burn_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

struct GuestPayload {
    paste: GuestPaste,
    share: GuestShare,
    files: Vec<FileMetaDto>,
}

impl GuestPasteRow {
    fn into_guest(self) -> GuestPaste {
        GuestPaste {
            id: self.id,
            title_ct: envelope::encode_envelope(&self.title_ct),
            content_ct: envelope::encode_envelope(&self.content_ct),
            language_ct: self.language_ct.as_deref().map(envelope::encode_envelope),
            pinned: self.pinned != 0,
            burn_mode: self.burn_mode,
            burn_after: self.burn_after,
            burn_at: self.burn_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// Load the guest-visible ciphertext, share envelope, and file metadata.
/// Callers must only return this payload after a counted `/view` transaction.
async fn load_guest_payload(
    connection: &mut sqlx::SqliteConnection,
    paste_id: &str,
) -> Result<Option<GuestPayload>, sqlx::Error> {
    let paste = sqlx::query_as::<_, GuestPasteRow>(
        "SELECT id, title_ct, content_ct, language_ct, pinned, burn_mode,
                burn_after, burn_at, created_at, updated_at
         FROM pastes WHERE id = ?",
    )
    .bind(paste_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(paste) = paste else {
        return Ok(None);
    };

    let share: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT share_salt, wrapped_paste_key FROM shares WHERE paste_id = ?")
            .bind(paste_id)
            .fetch_optional(&mut *connection)
            .await?;
    let Some((share_salt, wrapped_paste_key)) = share else {
        return Ok(None);
    };

    let files: Vec<FileMetaDto> = sqlx::query_as(
        "SELECT id, enc_meta, size, created_at FROM files
         WHERE paste_id = ? ORDER BY created_at ASC, id ASC",
    )
    .bind(paste_id)
    .fetch_all(&mut *connection)
    .await?;

    Ok(Some(GuestPayload {
        paste: paste.into_guest(),
        share: GuestShare {
            share_salt: envelope::encode_b64(&share_salt),
            wrapped_paste_key: envelope::encode_envelope(&wrapped_paste_key),
        },
        files,
    }))
}

fn random_token(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill(&mut bytes[..]);
    envelope::encode_b64(&bytes)
}

fn invalid(message: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "INVALID_REQUEST", message)
}

fn rate_limited(retry_after: u64) -> Response {
    let mut response = api_error(
        StatusCode::TOO_MANY_REQUESTS,
        "RATE_LIMITED",
        "Too many unlock attempts",
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after.max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn share_is_usable(row: &ShareRow, now: i64) -> bool {
    row.revoked_at.is_none()
        && row.expires_at.is_none_or(|expires_at| expires_at > now)
        && row.max_unlocks.is_none_or(|max| row.unlocks_used < max)
}

async fn load_share(state: &AppState, paste_id: &str) -> Result<Option<ShareRow>, sqlx::Error> {
    sqlx::query_as::<_, ShareRow>(
        "SELECT s.paste_id, s.share_salt, s.share_auth_key,
                s.expires_at, s.revoked_at, s.unlocks_used, s.max_unlocks, s.created_at,
                p.burn_mode, p.burn_at
         FROM shares s JOIN pastes p ON p.id = s.paste_id
         WHERE s.paste_id = ?",
    )
    .bind(paste_id)
    .fetch_optional(&state.db)
    .await
}

async fn delete_share(state: &AppState, paste_id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM shares WHERE paste_id = ?")
        .bind(paste_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() > 0 {
        let _ = state.ws_sender.send(
            json!({ "type": "share_revoked", "pasteId": paste_id }).to_string(),
        );
    }
    Ok(result.rows_affected() > 0)
}

async fn apply_unlock_limit(state: &Arc<AppState>, row: &ShareRow) -> Result<(), sqlx::Error> {
    if row.burn_mode.as_deref() == Some("unlock_count") {
        let _ = delete_paste(state, &row.paste_id).await?;
        let _ = state.ws_sender.send(
            json!({ "type": "paste_burned", "pasteId": row.paste_id }).to_string(),
        );
    } else {
        let _ = delete_share(state, &row.paste_id).await?;
    }
    Ok(())
}

async fn retire_share(
    state: &Arc<AppState>,
    row: &ShareRow,
    now: i64,
) -> Result<(), sqlx::Error> {
    if row.revoked_at.is_some() || row.expires_at.is_some_and(|expires_at| expires_at <= now) {
        let _ = delete_share(state, &row.paste_id).await?;
    } else if row.max_unlocks.is_some_and(|max| row.unlocks_used >= max) {
        apply_unlock_limit(state, row).await?;
    }
    Ok(())
}

/// Check the per-(client IP, paste) limiter (plan §7.4): 5 attempts per
/// minute, then an exponential lockout — each further attempt doubles the
/// remaining lock time, capped at 15 minutes. The lockout always expires;
/// there is no permanent lock.
fn unlock_retry_after(state: &AppState, ip: IpAddr, paste_id: &str) -> Option<u64> {
    let mut attempts = state
        .unlock_attempts
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let key = (ip, paste_id.to_string());
    let now = Instant::now();
    let Some(entry) = attempts.get_mut(&key) else {
        return None;
    };

    if let Some(locked_until) = entry.locked_until {
        if now < locked_until {
            let remaining = locked_until.saturating_duration_since(now);
            let extended = (remaining.saturating_mul(2)).min(UNLOCK_MAX_LOCKOUT);
            entry.locked_until = Some(now + extended);
            // Round up so sub-second drift never shortens the advertised wait.
            let secs = extended.as_secs() + u64::from(extended.subsec_nanos() != 0);
            return Some(secs.max(1));
        }
        // Lockout served in full: start a clean window.
        entry.locked_until = None;
        entry.count = 0;
        entry.window_start = now;
    }

    if entry.window_start.elapsed() >= UNLOCK_WINDOW {
        entry.count = 0;
        entry.window_start = now;
    }
    if entry.count >= MAX_UNLOCK_ATTEMPTS {
        entry.locked_until = Some(now + UNLOCK_BASE_LOCKOUT);
        return Some(UNLOCK_BASE_LOCKOUT.as_secs());
    }
    None
}

fn record_unlock_attempt(state: &AppState, ip: IpAddr, paste_id: &str) {
    let mut attempts = state
        .unlock_attempts
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let key = (ip, paste_id.to_string());
    let now = Instant::now();
    match attempts.get_mut(&key) {
        Some(entry) if entry.window_start.elapsed() < UNLOCK_WINDOW => {
            entry.count = entry.count.saturating_add(1);
        }
        Some(entry) => {
            entry.count = 1;
            entry.window_start = now;
            entry.locked_until = None;
        }
        None => {
            attempts.insert(
                key,
                LoginAttempts {
                    count: 1,
                    window_start: now,
                    locked_until: None,
                },
            );
        }
    }
    if attempts.len() > 10_000 {
        // Keep entries that are still locked out; an attacker must not be
        // able to trigger this prune to drop their own lock.
        attempts.retain(|_, entry| {
            entry
                .locked_until
                .is_some_and(|locked_until| locked_until > now)
                || entry.window_start.elapsed() < UNLOCK_WINDOW
        });
    }
}

fn clear_unlock_failures(state: &AppState, ip: IpAddr, paste_id: &str) {
    let mut attempts = state
        .unlock_attempts
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    attempts.remove(&(ip, paste_id.to_string()));
}

/// Secondary per-IP control across all share endpoints (plan §7.4): a
/// fixed window over challenge and unlock attempts regardless of paste.
fn share_ip_retry_after(state: &AppState, ip: IpAddr) -> Option<u64> {
    let mut attempts = state
        .share_ip_attempts
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let now = Instant::now();
    let Some(entry) = attempts.get_mut(&ip) else {
        return None;
    };
    if entry.window_start.elapsed() >= SHARE_IP_WINDOW {
        entry.count = 0;
        entry.window_start = now;
    }
    if entry.count >= MAX_SHARE_IP_ATTEMPTS {
        Some((SHARE_IP_WINDOW - entry.window_start.elapsed()).as_secs().max(1))
    } else {
        None
    }
}

fn record_share_ip_attempt(state: &AppState, ip: IpAddr) {
    let mut attempts = state
        .share_ip_attempts
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let now = Instant::now();
    let entry = attempts.entry(ip).or_insert(LoginAttempts {
        count: 0,
        window_start: now,
        locked_until: None,
    });
    if entry.window_start.elapsed() >= SHARE_IP_WINDOW {
        entry.count = 0;
        entry.window_start = now;
    }
    entry.count = entry.count.saturating_add(1);
    if attempts.len() > 10_000 {
        attempts.retain(|_, entry| entry.window_start.elapsed() < SHARE_IP_WINDOW);
    }
}

fn verify_proof(share_auth_key: &[u8], nonce: &str, paste_id: &str, proof: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(share_auth_key) else {
        return false;
    };
    mac.update(format!("{nonce}|{paste_id}").as_bytes());
    mac.verify_slice(proof).is_ok()
}

/// POST /api/pastes/:id/share
pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(paste_id): Path<String>,
    Json(body): Json<CreateShareBody>,
) -> Response {
    if let Err(response) = require_csrf(&headers) {
        return response;
    }
    if let Err(response) = require_owner(&state, &headers).await {
        return response;
    }
    if !is_paste_id(&paste_id) {
        return invalid("Invalid paste ID");
    }
    match burn_if_due(&state, &paste_id).await {
        Ok(true) => {
            return api_error(StatusCode::GONE, "PASTE_BURNED", "This paste has burned");
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let share_salt = match envelope::decode_b64_exact(&body.share_salt, SHARE_SALT_BYTES) {
        Some(value) => value,
        None => return invalid("Invalid share salt"),
    };
    let share_auth_key =
        match envelope::decode_b64_exact(&body.share_auth_key, SHARE_AUTH_KEY_BYTES) {
            Some(value) => value,
            None => return invalid("Invalid share auth key"),
        };
    let wrapped_paste_key =
        match envelope::decode_envelope_exact(&body.wrapped_paste_key, WRAPPED_PASTE_KEY_BYTES) {
            Some(value) => value,
            None => return invalid("Invalid wrapped paste key"),
        };
    let now = auth::now_unix();
    if let Some(expires_at) = body.expires_at {
        if expires_at <= now {
            return invalid("Share expiry must be in the future");
        }
    }
    if let Some(max_unlocks) = body.max_unlocks {
        if !(1..=MAX_SHARE_UNLOCKS).contains(&max_unlocks) {
            return invalid("maxUnlocks is out of range");
        }
    }

    let paste: Option<(Option<String>, Option<i64>)> =
        match sqlx::query_as("SELECT burn_mode, burn_after FROM pastes WHERE id = ?")
            .bind(&paste_id)
            .fetch_optional(&state.db)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                tracing::error!("Failed to load paste burn settings: {error}");
                return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
            }
        };
    let Some((burn_mode, burn_after)) = paste else {
        return api_error(StatusCode::NOT_FOUND, "PASTE_NOT_FOUND", "Paste not found");
    };
    let max_unlocks = if burn_mode.as_deref() == Some("unlock_count") {
        burn_after
    } else {
        body.max_unlocks
    };

    let mut transaction = match state.db.begin().await {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!("Failed to start share transaction: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    let existing: Option<String> = match sqlx::query_scalar("SELECT paste_id FROM shares WHERE paste_id = ?")
        .bind(&paste_id)
        .fetch_optional(&mut *transaction)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("Failed to check existing share: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    if existing.is_some() {
        if !body.replace.unwrap_or(false) {
            return api_error(
                StatusCode::CONFLICT,
                "SHARE_EXISTS",
                "A share already exists; replace it explicitly",
            );
        }
        if let Err(error) = sqlx::query("DELETE FROM shares WHERE paste_id = ?")
            .bind(&paste_id)
            .execute(&mut *transaction)
            .await
        {
            tracing::error!("Failed to replace share: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let result = sqlx::query(
        "INSERT INTO shares
            (paste_id, share_salt, share_auth_key, wrapped_paste_key,
             expires_at, revoked_at, unlocks_used, max_unlocks, created_at)
         VALUES (?, ?, ?, ?, ?, NULL, 0, ?, ?)",
    )
    .bind(&paste_id)
    .bind(&share_salt)
    .bind(&share_auth_key)
    .bind(&wrapped_paste_key)
    .bind(body.expires_at)
    .bind(max_unlocks)
    .bind(now)
    .execute(&mut *transaction)
    .await;

    if let Err(error) = result {
        if super::util::is_unique_violation(&error) {
            return api_error(
                StatusCode::CONFLICT,
                "SHARE_EXISTS",
                "A share already exists; replace it explicitly",
            );
        }
        tracing::error!("Failed to create share: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }

    if let Err(error) = transaction.commit().await {
        tracing::error!("Failed to commit share: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }

    let _ = state.ws_sender.send(
        json!({ "type": if existing.is_some() { "share_updated" } else { "share_created" }, "pasteId": paste_id })
            .to_string(),
    );

    (
        StatusCode::CREATED,
        no_store_headers(),
        Json(json!({
            "success": true,
            "share": {
                "createdAt": now,
                "expiresAt": body.expires_at,
                "maxUnlocks": max_unlocks,
            }
        })),
    )
        .into_response()
}

/// GET /api/pastes/:id/share
pub async fn handle_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(paste_id): Path<String>,
) -> Response {
    if let Err(response) = require_owner(&state, &headers).await {
        return response;
    }
    if !is_paste_id(&paste_id) {
        return invalid("Invalid paste ID");
    }
    match burn_if_due(&state, &paste_id).await {
        Ok(true) => {
            return api_error(StatusCode::GONE, "PASTE_BURNED", "This paste has burned");
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let row = match load_share(&state, &paste_id).await {
        Ok(row) => row,
        Err(error) => {
            tracing::error!("Failed to load share: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    let Some(row) = row else {
        return (no_store_headers(), Json(json!({ "exists": false }))).into_response();
    };
    let now = auth::now_unix();
    if !share_is_usable(&row, now) {
        if let Err(error) = retire_share(&state, &row, now).await {
            tracing::error!("Failed to retire share: {error}");
        }
        return (no_store_headers(), Json(json!({ "exists": false }))).into_response();
    }

    (
        no_store_headers(),
        Json(json!({
            "exists": true,
            "share": {
                "createdAt": row.created_at,
                "expiresAt": row.expires_at,
                "unlocksUsed": row.unlocks_used,
                "maxUnlocks": row.max_unlocks,
            }
        })),
    )
        .into_response()
}

/// DELETE /api/pastes/:id/share
pub async fn handle_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(paste_id): Path<String>,
) -> Response {
    if let Err(response) = require_csrf(&headers) {
        return response;
    }
    if let Err(response) = require_owner(&state, &headers).await {
        return response;
    }
    if !is_paste_id(&paste_id) {
        return invalid("Invalid paste ID");
    }
    match delete_share(&state, &paste_id).await {
        Ok(_) => (no_store_headers(), Json(json!({ "success": true }))).into_response(),
        Err(error) => {
            tracing::error!("Failed to delete share: {error}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error")
        }
    }
}

/// GET /api/shares/:id/params
pub async fn handle_params(
    State(state): State<Arc<AppState>>,
    Path(paste_id): Path<String>,
) -> Response {
    if !is_paste_id(&paste_id) {
        return invalid("Invalid paste ID");
    }
    match burn_if_due(&state, &paste_id).await {
        Ok(true) => {
            return api_error(StatusCode::GONE, "SHARE_INVALID", "This share is no longer available");
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let row = match load_share(&state, &paste_id).await {
        Ok(row) => row,
        Err(error) => {
            tracing::error!("Failed to load share: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    let Some(row) = row else {
        return api_error(StatusCode::NOT_FOUND, "SHARE_INVALID", "Share not found");
    };
    let now = auth::now_unix();
    if !share_is_usable(&row, now) {
        if let Err(error) = retire_share(&state, &row, now).await {
            tracing::error!("Failed to retire share: {error}");
        }
        return api_error(StatusCode::GONE, "SHARE_INVALID", "This share is no longer available");
    }

    (
        no_store_headers(),
        Json(json!({
            "shareSalt": envelope::encode_b64(&row.share_salt),
            "kdfParams": KdfParams::default(),
            "expiresAt": row.expires_at,
            "unlocksUsed": row.unlocks_used,
            "maxUnlocks": row.max_unlocks,
        })),
    )
        .into_response()
}

/// POST /api/shares/:id/challenge
pub async fn handle_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(paste_id): Path<String>,
) -> Response {
    if !auth::check_fetch_site(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Cross-site share request rejected",
        );
    }
    if !is_paste_id(&paste_id) {
        return invalid("Invalid paste ID");
    }
    let ip = state.client_ip(addr.ip(), &headers);
    if let Some(retry_after) = share_ip_retry_after(&state, ip) {
        return rate_limited(retry_after);
    }
    if let Some(retry_after) = unlock_retry_after(&state, ip, &paste_id) {
        return rate_limited(retry_after);
    }
    match burn_if_due(&state, &paste_id).await {
        Ok(true) => {
            return api_error(StatusCode::GONE, "SHARE_INVALID", "This share is no longer available");
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let row = match load_share(&state, &paste_id).await {
        Ok(row) => row,
        Err(error) => {
            tracing::error!("Failed to load share: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    let Some(row) = row else {
        return api_error(StatusCode::NOT_FOUND, "SHARE_INVALID", "Share not found");
    };
    let now = auth::now_unix();
    if !share_is_usable(&row, now) {
        if let Err(error) = retire_share(&state, &row, now).await {
            tracing::error!("Failed to retire share: {error}");
        }
        return api_error(StatusCode::GONE, "SHARE_INVALID", "This share is no longer available");
    }

    if let Err(error) = sqlx::query("DELETE FROM share_challenges WHERE expires_at <= ?")
        .bind(now)
        .execute(&state.db)
        .await
    {
        tracing::error!("Failed to clean expired challenges: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }
    let active: i64 =
        match sqlx::query_scalar("SELECT COUNT(*) FROM share_challenges WHERE share_id = ?")
            .bind(&paste_id)
            .fetch_one(&state.db)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                tracing::error!("Failed to count challenges: {error}");
                return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
            }
        };
    if active >= MAX_ACTIVE_CHALLENGES {
        // Evict the oldest pending challenge instead of rejecting new ones.
        // Rejecting would let one client lock a share out for the challenge TTL.
        if let Err(error) = sqlx::query(
            "DELETE FROM share_challenges WHERE nonce_hash = (
                SELECT nonce_hash FROM share_challenges
                WHERE share_id = ? ORDER BY created_at ASC, nonce_hash ASC LIMIT 1
             )",
        )
        .bind(&paste_id)
        .execute(&state.db)
        .await
        {
            tracing::error!("Failed to evict old challenge: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let nonce = random_token(CHALLENGE_NONCE_BYTES);
    let nonce_hash = auth::hash_token(&nonce);
    let expires_at = now + CHALLENGE_TTL_SECONDS;
    if let Err(error) = sqlx::query(
        "INSERT INTO share_challenges (nonce_hash, share_id, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(nonce_hash.as_slice())
    .bind(&paste_id)
    .bind(expires_at)
    .bind(now)
    .execute(&state.db)
    .await
    {
        tracing::error!("Failed to create share challenge: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }

    record_unlock_attempt(&state, ip, &paste_id);
    record_share_ip_attempt(&state, ip);

    (
        no_store_headers(),
        Json(json!({ "nonce": nonce, "expiresAt": expires_at })),
    )
        .into_response()
}

/// POST /api/shares/:id/unlock
pub async fn handle_unlock(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(paste_id): Path<String>,
    Json(body): Json<UnlockBody>,
) -> Response {
    if !auth::check_fetch_site(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Cross-site share request rejected",
        );
    }
    if !is_paste_id(&paste_id) {
        return invalid("Invalid paste ID");
    }
    let ip = state.client_ip(addr.ip(), &headers);
    if let Some(retry_after) = share_ip_retry_after(&state, ip) {
        return rate_limited(retry_after);
    }
    if let Some(retry_after) = unlock_retry_after(&state, ip, &paste_id) {
        return rate_limited(retry_after);
    }
    let nonce = match envelope::decode_b64_exact(&body.nonce, CHALLENGE_NONCE_BYTES) {
        Some(_) => body.nonce,
        None => return invalid("Invalid challenge nonce"),
    };
    let proof = match envelope::decode_b64_exact(&body.proof, 32) {
        Some(value) => value,
        None => return invalid("Invalid unlock proof"),
    };
    if let Err(response) = verify_and_unlock(&state, &paste_id, &nonce, &proof, ip).await {
        return response;
    }
    match unlock_response(&state, &paste_id).await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!("Failed to build unlock response: {error}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error")
        }
    }
}

async fn verify_and_unlock(
    state: &Arc<AppState>,
    paste_id: &str,
    nonce: &str,
    proof: &[u8],
    ip: IpAddr,
) -> Result<(), Response> {
    match burn_if_due(state, paste_id).await {
        Ok(true) => {
            return Err(api_error(
                StatusCode::GONE,
                "SHARE_INVALID",
                "This share is no longer available",
            ));
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Database error",
            ));
        }
    }

    let row = match load_share(state, paste_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(api_error(
                StatusCode::NOT_FOUND,
                "SHARE_INVALID",
                "Share not found",
            ));
        }
        Err(error) => {
            tracing::error!("Failed to load share: {error}");
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Database error",
            ));
        }
    };
    let now = auth::now_unix();
    if !share_is_usable(&row, now) {
        if let Err(error) = retire_share(state, &row, now).await {
            tracing::error!("Failed to retire share: {error}");
        }
        return Err(api_error(
            StatusCode::GONE,
            "SHARE_INVALID",
            "This share is no longer available",
        ));
    }

    let nonce_hash = auth::hash_token(nonce);
    let challenge_valid: Option<i64> = match sqlx::query_scalar(
        "DELETE FROM share_challenges
         WHERE nonce_hash = ? AND share_id = ? AND expires_at > ?
         RETURNING expires_at",
    )
    .bind(nonce_hash.as_slice())
    .bind(paste_id)
    .bind(now)
    .fetch_optional(&state.db)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("Failed to consume share challenge: {error}");
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Database error",
            ));
        }
    };
    if challenge_valid.is_none() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PROOF",
            "Challenge is missing or expired",
        ));
    }

    if !verify_proof(&row.share_auth_key, nonce, paste_id, proof) {
        record_unlock_attempt(state, ip, paste_id);
        record_share_ip_attempt(state, ip);
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_PROOF",
            "Invalid share proof",
        ));
    }
    clear_unlock_failures(state, ip, paste_id);

    Ok(())
}

async fn unlock_response(
    state: &Arc<AppState>,
    paste_id: &str,
) -> Result<Response, sqlx::Error> {
    let share = load_share(state, paste_id).await?;
    let Some(share) = share else {
        return Ok(api_error(
            StatusCode::NOT_FOUND,
            "SHARE_INVALID",
            "Share not found",
        ));
    };
    let now = auth::now_unix();
    if !share_is_usable(&share, now) {
        if let Err(error) = retire_share(state, &share, now).await {
            tracing::error!("Failed to retire share: {error}");
        }
        return Ok(api_error(
            StatusCode::GONE,
            "SHARE_INVALID",
            "This share is no longer available",
        ));
    }
    if share.burn_mode.as_deref() == Some("time") && share.burn_at.is_some_and(|at| at <= now) {
        let _ = delete_paste(state, paste_id).await;
        return Ok(api_error(
            StatusCode::GONE,
            "SHARE_INVALID",
            "This share is no longer available",
        ));
    }

    // Deliberately do not return the paste ciphertext or wrapped paste key here.
    // `/view` is the counted step; returning them at unlock would let a guest
    // bypass maxUnlocks and the unlock-count burn by never calling `/view`.
    let files: Vec<FileMetaDto> = sqlx::query_as(
        "SELECT id, enc_meta, size, created_at FROM files
         WHERE paste_id = ? ORDER BY created_at ASC, id ASC",
    )
    .bind(paste_id)
    .fetch_all(&state.db)
    .await?;

    let token = random_token(SHARE_TOKEN_BYTES);
    let token_hash = auth::hash_token(&token);
    let expires_at = now + SHARE_TOKEN_TTL_SECONDS;
    sqlx::query(
        "INSERT INTO share_tokens (token_hash, share_id, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(token_hash.as_slice())
    .bind(paste_id)
    .bind(expires_at)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        no_store_headers(),
        Json(json!({
            "shareToken": token,
            "shareTokenExpiresAt": expires_at,
            "unlocksUsed": share.unlocks_used,
            "maxUnlocks": share.max_unlocks,
            "files": files,
        })),
    )
        .into_response())
}

#[derive(FromRow)]
struct ViewTokenRow {
    paste_id: String,
    token_expires_at: i64,
    share_expires_at: Option<i64>,
    revoked_at: Option<i64>,
    unlocks_used: i64,
    max_unlocks: Option<i64>,
    burn_mode: Option<String>,
    burn_at: Option<i64>,
}

enum ViewOutcome {
    Invalid,
    Gone {
        disk_names: Vec<String>,
    },
    Counted {
        unlocks_used: i64,
        payload: GuestPayload,
    },
    BurnedPaste {
        unlocks_used: i64,
        payload: GuestPayload,
        disk_names: Vec<String>,
    },
    RevokedShare {
        unlocks_used: i64,
        payload: GuestPayload,
    },
}

async fn delete_paste_in_tx(
    connection: &mut sqlx::SqliteConnection,
    paste_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let disk_names: Vec<String> =
        sqlx::query_scalar("SELECT disk_name FROM files WHERE paste_id = ?")
            .bind(paste_id)
            .fetch_all(&mut *connection)
            .await?;
    sqlx::query("DELETE FROM pastes WHERE id = ?")
        .bind(paste_id)
        .execute(&mut *connection)
        .await?;
    Ok(disk_names)
}

async fn delete_share_in_tx(
    connection: &mut sqlx::SqliteConnection,
    paste_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM shares WHERE paste_id = ?")
        .bind(paste_id)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn view_transaction(
    connection: &mut sqlx::Transaction<'_, Sqlite>,
    token_hash: &[u8],
    paste_id: &str,
    now: i64,
) -> Result<ViewOutcome, sqlx::Error> {
    let row = sqlx::query_as::<_, ViewTokenRow>(
        "SELECT t.share_id AS paste_id, t.expires_at AS token_expires_at,
                s.expires_at AS share_expires_at, s.revoked_at, s.unlocks_used,
                s.max_unlocks, p.burn_mode, p.burn_at
         FROM share_tokens t
         JOIN shares s ON s.paste_id = t.share_id
         JOIN pastes p ON p.id = s.paste_id
         WHERE t.token_hash = ? AND t.share_id = ?",
    )
    .bind(token_hash)
    .bind(paste_id)
    .fetch_optional(&mut **connection)
    .await?;

    let Some(row) = row else {
        return Ok(ViewOutcome::Invalid);
    };
    if row.token_expires_at <= now {
        sqlx::query("DELETE FROM share_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&mut **connection)
            .await?;
        return Ok(ViewOutcome::Invalid);
    }
    if row.burn_mode.as_deref() == Some("time") && row.burn_at.is_some_and(|at| at <= now) {
        let disk_names = delete_paste_in_tx(&mut **connection, &row.paste_id).await?;
        return Ok(ViewOutcome::Gone { disk_names });
    }
    if row.revoked_at.is_some()
        || row
            .share_expires_at
            .is_some_and(|expires_at| expires_at <= now)
    {
        delete_share_in_tx(&mut **connection, &row.paste_id).await?;
        return Ok(ViewOutcome::Gone { disk_names: vec![] });
    }
    if row.max_unlocks.is_some_and(|max| row.unlocks_used >= max) {
        if row.burn_mode.as_deref() == Some("unlock_count") {
            let disk_names = delete_paste_in_tx(&mut **connection, &row.paste_id).await?;
            return Ok(ViewOutcome::Gone { disk_names });
        }
        delete_share_in_tx(&mut **connection, &row.paste_id).await?;
        return Ok(ViewOutcome::Gone { disk_names: vec![] });
    }

    let payload = match load_guest_payload(&mut **connection, &row.paste_id).await? {
        Some(payload) => payload,
        None => return Ok(ViewOutcome::Gone { disk_names: vec![] }),
    };

    sqlx::query("DELETE FROM share_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .execute(&mut **connection)
        .await?;
    let unlocks_used: i64 = sqlx::query_scalar(
        "UPDATE shares SET unlocks_used = unlocks_used + 1
         WHERE paste_id = ? RETURNING unlocks_used",
    )
    .bind(&row.paste_id)
    .fetch_one(&mut **connection)
    .await?;

    let limit_reached = row.max_unlocks.is_some_and(|max| unlocks_used >= max);
    if limit_reached {
        if row.burn_mode.as_deref() == Some("unlock_count") {
            let disk_names = delete_paste_in_tx(&mut **connection, &row.paste_id).await?;
            return Ok(ViewOutcome::BurnedPaste {
                unlocks_used,
                payload,
                disk_names,
            });
        }
        delete_share_in_tx(&mut **connection, &row.paste_id).await?;
        return Ok(ViewOutcome::RevokedShare {
            unlocks_used,
            payload,
        });
    }

    Ok(ViewOutcome::Counted {
        unlocks_used,
        payload,
    })
}

/// POST /api/shares/:id/view
pub async fn handle_view(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(paste_id): Path<String>,
    Json(body): Json<ViewBody>,
) -> Response {
    if !auth::check_fetch_site(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "Cross-site share request rejected",
        );
    }
    if !is_paste_id(&paste_id) {
        return invalid("Invalid paste ID");
    }
    if envelope::decode_b64_exact(&body.share_token, SHARE_TOKEN_BYTES).is_none() {
        return api_error(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid share token");
    }
    match burn_if_due(&state, &paste_id).await {
        Ok(true) => {
            return api_error(StatusCode::GONE, "SHARE_INVALID", "This share is no longer available");
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let mut transaction = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!("Failed to begin view transaction: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    let token_hash = auth::hash_token(&body.share_token);
    let outcome = match view_transaction(
        &mut transaction,
        token_hash.as_slice(),
        &paste_id,
        auth::now_unix(),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = transaction.rollback().await;
            tracing::error!("Failed to record share view: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    if let Err(error) = transaction.commit().await {
        tracing::error!("Failed to commit share view: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }

    match outcome {
        ViewOutcome::Invalid => api_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_TOKEN",
            "Share token is no longer valid",
        ),
        ViewOutcome::Gone { disk_names } => {
            remove_uploads(&state, disk_names).await;
            api_error(
                StatusCode::GONE,
                "SHARE_INVALID",
                "This share is no longer available",
            )
        }
        ViewOutcome::Counted {
            unlocks_used,
            payload,
        } => view_success(unlocks_used, false, payload),
        ViewOutcome::RevokedShare {
            unlocks_used,
            payload,
        } => {
            let _ = state.ws_sender.send(
                json!({ "type": "share_revoked", "pasteId": paste_id }).to_string(),
            );
            view_success(unlocks_used, true, payload)
        }
        ViewOutcome::BurnedPaste {
            unlocks_used,
            payload,
            disk_names,
        } => {
            remove_uploads(&state, disk_names).await;
            let _ = state.ws_sender.send(
                json!({ "type": "paste_burned", "pasteId": paste_id }).to_string(),
            );
            view_success(unlocks_used, true, payload)
        }
    }
}

async fn remove_uploads(state: &AppState, disk_names: Vec<String>) {
    for disk_name in disk_names {
        let path = std::path::Path::new(&state.uploads_dir).join(disk_name);
        if let Err(error) = tokio::fs::remove_file(&path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Failed to delete upload {}: {error}", path.display());
            }
        }
    }
}

fn view_success(unlocks_used: i64, burned: bool, payload: GuestPayload) -> Response {
    let GuestPayload {
        paste,
        share,
        files,
    } = payload;
    (
        no_store_headers(),
        Json(json!({
            "success": true,
            "unlocksUsed": unlocks_used,
            "burned": burned,
            "paste": paste,
            "share": share,
            "files": files,
        })),
    )
        .into_response()
}

/// Validate a share token for a file download. Does not consume the token.
pub async fn token_allows_paste(
    state: &AppState,
    token: &str,
    paste_id: &str,
) -> Result<bool, sqlx::Error> {
    if envelope::decode_b64_exact(token, SHARE_TOKEN_BYTES).is_none() {
        return Ok(false);
    }
    let token_hash = auth::hash_token(token);
    let now = auth::now_unix();
    let row: Option<(Option<i64>, Option<i64>, Option<i64>, i64, i64)> = sqlx::query_as(
        "SELECT s.expires_at, s.revoked_at, s.max_unlocks, s.unlocks_used, t.expires_at
         FROM share_tokens t
         JOIN shares s ON s.paste_id = t.share_id
         WHERE t.token_hash = ? AND s.paste_id = ?",
    )
    .bind(token_hash.as_slice())
    .bind(paste_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((share_expires_at, revoked_at, max_unlocks, unlocks_used, token_expires_at)) = row
    else {
        return Ok(false);
    };
    Ok(token_expires_at > now
        && share_expires_at.is_none_or(|expires_at| expires_at > now)
        && revoked_at.is_none()
        && max_unlocks.is_none_or(|max| unlocks_used < max))
}

/// Delete expired share tokens, challenges, and shares.
pub async fn cleanup_share_state(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let now = auth::now_unix();
    sqlx::query("DELETE FROM share_tokens WHERE expires_at <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM share_challenges WHERE expires_at <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        crate::db::init_schema(&pool, false).await.unwrap();
        pool
    }

    async fn insert_burnable_paste(pool: &SqlitePool, paste_id: &str, max_unlocks: i64) {
        sqlx::query(
            "INSERT INTO pastes
                (id, key_salt, title_ct, content_ct, language_ct, pinned,
                 burn_mode, burn_after, burn_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, NULL, 0, 'unlock_count', ?, NULL, 0, 0)",
        )
        .bind(paste_id)
        .bind(vec![0u8; 16])
        .bind(vec![0u8; 28])
        .bind(vec![0u8; 28])
        .bind(max_unlocks)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO shares
                (paste_id, share_salt, share_auth_key, wrapped_paste_key,
                 expires_at, revoked_at, unlocks_used, max_unlocks, created_at)
             VALUES (?, ?, ?, ?, NULL, NULL, 0, ?, 0)",
        )
        .bind(paste_id)
        .bind(vec![1u8; 16])
        .bind(vec![2u8; 32])
        .bind(vec![3u8; 60])
        .bind(max_unlocks)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO share_tokens (token_hash, share_id, expires_at, created_at)
             VALUES (?, ?, 100, 0)",
        )
        .bind(vec![4u8; 32])
        .bind(paste_id)
        .execute(pool)
        .await
        .unwrap();
    }

    #[test]
    fn proof_matches_hmac_contract() {
        let key = [7u8; 32];
        let nonce = "nonce-value";
        let paste_id = "paste-value";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(format!("{nonce}|{paste_id}").as_bytes());
        let proof = mac.finalize().into_bytes();
        assert!(verify_proof(&key, nonce, paste_id, &proof));
        assert!(!verify_proof(&key, nonce, "other", &proof));
    }

    #[tokio::test]
    async fn view_burns_paste_at_unlock_limit() {
        let pool = test_pool().await;
        insert_burnable_paste(&pool, "paste", 1).await;

        let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let outcome = view_transaction(&mut transaction, &[4u8; 32], "paste", 50)
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        assert!(matches!(
            outcome,
            ViewOutcome::BurnedPaste {
                unlocks_used: 1,
                ..
            }
        ));
        let pastes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pastes")
            .fetch_one(&pool)
            .await
            .unwrap();
        let shares: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shares")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(pastes, 0);
        assert_eq!(shares, 0);
    }

    #[tokio::test]
    async fn view_counts_below_limit_without_burning() {
        let pool = test_pool().await;
        insert_burnable_paste(&pool, "paste", 2).await;

        let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let outcome = view_transaction(&mut transaction, &[4u8; 32], "paste", 50)
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        assert!(matches!(outcome, ViewOutcome::Counted { unlocks_used: 1, .. }));
        let remaining: i64 = sqlx::query_scalar("SELECT unlocks_used FROM shares WHERE paste_id = ?")
            .bind("paste")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn share_use_checks_expiry_and_limits() {
        let row = ShareRow {
            paste_id: "p".into(),
            share_salt: vec![],
            share_auth_key: vec![],
            expires_at: Some(200),
            revoked_at: None,
            unlocks_used: 1,
            max_unlocks: Some(2),
            created_at: 1,
            burn_mode: None,
            burn_at: None,
        };
        assert!(share_is_usable(&row, 100));
        assert!(!share_is_usable(&row, 200));
        let mut limited = row.clone();
        limited.unlocks_used = 2;
        assert!(!share_is_usable(&limited, 100));
    }

    async fn limiter_state() -> AppState {
        let pool = test_pool().await;
        AppState::new(
            pool,
            String::new(),
            String::new(),
            0,
            0,
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn unlock_limiter_locks_exponentially_and_caps_at_15_minutes() {
        let state = limiter_state().await;
        let ip: IpAddr = "203.0.113.4".parse().unwrap();

        // Four recorded failures stay under the limit; the fifth uses it up.
        for _ in 0..MAX_UNLOCK_ATTEMPTS - 1 {
            record_unlock_attempt(&state, ip, "paste");
        }
        assert!(unlock_retry_after(&state, ip, "paste").is_none());
        record_unlock_attempt(&state, ip, "paste");

        // The next check trips the base one-minute lockout.
        assert_eq!(unlock_retry_after(&state, ip, "paste"), Some(60));

        // Each blocked attempt doubles the remaining lockout…
        assert_eq!(unlock_retry_after(&state, ip, "paste"), Some(120));
        assert_eq!(unlock_retry_after(&state, ip, "paste"), Some(240));
        assert_eq!(unlock_retry_after(&state, ip, "paste"), Some(480));
        // …capped at 15 minutes.
        assert_eq!(unlock_retry_after(&state, ip, "paste"), Some(900));
        assert_eq!(unlock_retry_after(&state, ip, "paste"), Some(900));

        // Success clears the bucket entirely.
        clear_unlock_failures(&state, ip, "paste");
        assert!(unlock_retry_after(&state, ip, "paste").is_none());
    }

    #[tokio::test]
    async fn unlock_limiter_entries_are_isolated_per_paste() {
        let state = limiter_state().await;
        let ip: IpAddr = "203.0.113.4".parse().unwrap();

        for _ in 0..MAX_UNLOCK_ATTEMPTS {
            record_unlock_attempt(&state, ip, "paste-a");
        }
        assert_eq!(unlock_retry_after(&state, ip, "paste-a"), Some(60));
        // A different paste for the same IP is unaffected.
        assert!(unlock_retry_after(&state, ip, "paste-b").is_none());
    }

    #[tokio::test]
    async fn share_ip_limiter_caps_one_ip_across_many_pastes() {
        let state = limiter_state().await;
        let ip: IpAddr = "203.0.113.4".parse().unwrap();

        // Rotate paste IDs so every per-paste bucket stays fresh; only the
        // aggregate per-IP counter (plan §7.4 secondary control) can trip.
        for index in 0..MAX_SHARE_IP_ATTEMPTS {
            record_unlock_attempt(&state, ip, &format!("paste-{index}"));
            record_share_ip_attempt(&state, ip);
            assert!(
                unlock_retry_after(&state, ip, &format!("paste-{index}")).is_none(),
                "per-paste bucket must stay fresh while rotating paste IDs"
            );
        }

        // The next attempt from this IP — even against a brand-new paste —
        // is blocked by the aggregate cap.
        assert!(share_ip_retry_after(&state, ip).is_some());
        assert!(unlock_retry_after(&state, ip, "paste-fresh").is_none());
    }
}
