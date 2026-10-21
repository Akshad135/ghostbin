use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use super::file;
use crate::auth;
use crate::expiry::{
    BurnAction, compute_burn_at, parse_burn_action, pending_delete_at,
};
use crate::slugs::generate_slug;
use crate::state::AppState;

#[derive(Debug, Serialize, FromRow, Clone)]
pub struct Paste {
    pub id: i64,
    pub slug: String,
    pub title: String,
    pub content: String,
    pub language: String,
    pub pinned: i32,
    pub burn_trigger: Option<String>,
    pub burn_action: String,
    pub burn_at: Option<String>,
    pub burn_after_unlocks: Option<i64>,
    pub burn_unlocks_used: i64,
    pub burn_pending_delete_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub encrypted_paste_key: Option<String>,
    pub share_wrapped_paste_key: Option<String>,
    pub share_auth_salt: Option<String>,
    pub share_auth_verifier: Option<String>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct PasteListItem {
    pub id: i64,
    pub slug: String,
    pub title: String,
    pub content: String,
    pub language: String,
    pub pinned: i32,
    pub burn_trigger: Option<String>,
    pub burn_action: String,
    pub burn_at: Option<String>,
    pub burn_after_unlocks: Option<i64>,
    pub burn_unlocks_used: i64,
    pub burn_pending_delete_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub encrypted_paste_key: Option<String>,
    pub share_wrapped_paste_key: Option<String>,
    pub file_count: i64,
}

#[derive(Deserialize)]
pub struct ListQuery {
    page: Option<u32>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
pub struct CreatePasteBody {
    title: Option<String>,
    content: String,
    language: Option<String>,
    pinned: Option<i32>,
    file_slugs: Option<Vec<String>>,
    encrypted_paste_key: Option<String>,
    burn_trigger: Option<String>,
    burn_action: Option<String>,
    burn_after_value: Option<i64>,
    burn_after_unit: Option<String>,
    burn_after_unlocks: Option<i64>,
}

#[derive(Deserialize)]
pub struct UpdatePasteBody {
    title: Option<String>,
    content: Option<String>,
    language: Option<String>,
    pinned: Option<i32>,
    new_file_slugs: Option<Vec<String>>,
    removed_file_slugs: Option<Vec<String>>,
    encrypted_paste_key: Option<String>,
    share_wrapped_paste_key: Option<String>,
    revoke_share: Option<bool>,
    share_auth_salt: Option<String>,
    share_auth_verifier: Option<String>,
    /// Absent keeps the current rule, null clears it, string replaces it.
    burn_trigger: Option<Option<String>>,
    burn_action: Option<String>,
    burn_after_value: Option<i64>,
    burn_after_unit: Option<String>,
    burn_after_unlocks: Option<i64>,
}

#[derive(Deserialize)]
pub struct UnlockBody {
    auth_secret: String,
}

struct BurnFields {
    trigger: Option<String>,
    action: String,
    burn_at: Option<String>,
    after_unlocks: Option<i64>,
}

enum TimeBurnResult {
    None,
    Revoked,
    Deleted,
}

fn json_error(status: StatusCode, msg: &str) -> impl IntoResponse {
    (status, Json(serde_json::json!({ "error": msg })))
}

/// Returns the standard "paste is visible" WHERE clause.
/// `prefix` is prepended to every column name — use `"p."` when the
/// pastes table is aliased in a JOIN, or `""` for simple queries.
fn visible_paste_clause_for(prefix: &str) -> String {
    format!(
        "{prefix}burn_pending_delete_at IS NULL \
         AND NOT ({prefix}burn_trigger = 'time' \
                  AND {prefix}burn_action = 'delete' \
                  AND {prefix}burn_at IS NOT NULL \
                  AND {prefix}burn_at <= datetime('now'))"
    )
}

fn visible_paste_clause() -> String {
    visible_paste_clause_for("")
}

fn default_action_for_trigger(
    trigger: &str,
    provided: Option<&str>,
) -> Result<BurnAction, &'static str> {
    match provided {
        Some(action) => parse_burn_action(Some(action)),
        None if trigger == "unlock_count" => Ok(BurnAction::RevokeShare),
        None => Ok(BurnAction::Delete),
    }
}

fn build_burn_fields(
    trigger: Option<&str>,
    action: Option<&str>,
    value: Option<i64>,
    unit: Option<&str>,
    after_unlocks: Option<i64>,
) -> Result<BurnFields, &'static str> {
    let Some(trigger) = trigger else {
        return Ok(BurnFields {
            trigger: None,
            action: "delete".to_string(),
            burn_at: None,
            after_unlocks: None,
        });
    };

    let action = default_action_for_trigger(trigger, action)?;

    match trigger {
        "time" => {
            let burn_at = compute_burn_at(value, unit)?.ok_or("Burn time is required")?;
            Ok(BurnFields {
                trigger: Some("time".to_string()),
                action: action.as_str().to_string(),
                burn_at: Some(burn_at),
                after_unlocks: None,
            })
        }
        "unlock_count" => {
            let after_unlocks = after_unlocks.ok_or("Burn unlock count is required")?;
            if after_unlocks <= 0 {
                return Err("Burn unlock count must be positive");
            }
            if after_unlocks > 100_000 {
                return Err("Unlock count cannot exceed 100,000");
            }
            Ok(BurnFields {
                trigger: Some("unlock_count".to_string()),
                action: action.as_str().to_string(),
                burn_at: None,
                after_unlocks: Some(after_unlocks),
            })
        }
        _ => Err("Invalid burn trigger"),
    }
}

pub async fn delete_paste_unchecked(state: &AppState, slug: &str) -> Result<(), sqlx::Error> {
    file::delete_files_for_paste(&state.db, &state.uploads_dir, slug).await;
    sqlx::query("DELETE FROM pastes WHERE slug = ?")
        .bind(slug)
        .execute(&state.db)
        .await?;
    let msg = serde_json::json!({ "type": "paste_deleted", "slug": slug });
    let _ = state.ws_sender.send(msg.to_string());
    Ok(())
}

async fn enforce_time_burn(state: &AppState, slug: &str) -> TimeBurnResult {
    let due: Option<(String,)> = sqlx::query_as(
        "SELECT burn_action FROM pastes
         WHERE slug = ? AND burn_trigger = 'time' AND burn_at IS NOT NULL AND burn_at <= datetime('now')",
    )
    .bind(slug)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let Some((action,)) = due else {
        return TimeBurnResult::None;
    };

    if action == "delete" {
        match delete_paste_unchecked(state, slug).await {
            Ok(_) => TimeBurnResult::Deleted,
            Err(e) => {
                tracing::error!("Failed to delete time-burned paste {slug}: {e}");
                TimeBurnResult::Deleted
            }
        }
    } else {
        if let Err(e) = sqlx::query(
            "UPDATE pastes SET
                share_wrapped_paste_key = NULL,
                share_auth_salt = NULL,
                share_auth_verifier = NULL,
                burn_trigger = NULL,
                burn_action = 'delete',
                burn_at = NULL,
                burn_after_unlocks = NULL,
                burn_unlocks_used = 0,
                burn_pending_delete_at = NULL,
                updated_at = datetime('now')
             WHERE slug = ?",
        )
        .bind(slug)
        .execute(&state.db)
        .await
        {
            tracing::error!("Failed to revoke time-burned paste {slug}: {e}");
        }
        let msg = serde_json::json!({ "type": "paste_updated", "slug": slug });
        let _ = state.ws_sender.send(msg.to_string());
        TimeBurnResult::Revoked
    }
}

async fn load_active_paste(state: &AppState, slug: &str) -> Option<Paste> {
    let clause = visible_paste_clause();
    let query = format!("SELECT * FROM pastes WHERE slug = ? AND {clause}");
    sqlx::query_as(&query)
        .bind(slug)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None)
}

pub async fn handle_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ListQuery>,
) -> impl IntoResponse {
    if !auth::is_authenticated(&state.db, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).min(50);
    let offset = (page - 1) * limit;
    let filter = visible_paste_clause_for("p.");

    // Single query with LEFT JOIN replaces the previous N+1 per-paste COUNT loop.
    let query = format!(
        "SELECT p.id, p.slug, p.title, p.content, p.language, p.pinned,
            p.burn_trigger, p.burn_action, p.burn_at, p.burn_after_unlocks, p.burn_unlocks_used, p.burn_pending_delete_at,
            p.created_at, p.updated_at, p.encrypted_paste_key, p.share_wrapped_paste_key,
            COUNT(f.id) AS file_count
         FROM pastes p
         LEFT JOIN files f ON f.paste_slug = p.slug
         WHERE {filter}
         GROUP BY p.id
         ORDER BY p.pinned DESC, p.created_at DESC
         LIMIT ? OFFSET ?"
    );

    let pastes: Vec<PasteListItem> = match sqlx::query_as(&query)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Failed to list pastes: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load pastes")
                .into_response();
        }
    };

    let paste_json_list: Vec<serde_json::Value> = pastes
        .iter()
        .map(|p| serde_json::to_value(p).unwrap())
        .collect();

    let count_clause = visible_paste_clause();
    let count_query = format!("SELECT COUNT(*) as total FROM pastes WHERE {count_clause}");
    let total: i64 = sqlx::query_scalar(&count_query)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    Json(serde_json::json!({
        "pastes": paste_json_list,
        "total": total,
        "page": page,
        "limit": limit,
        "hasMore": (offset + limit) < total as u32,
    }))
    .into_response()
}

pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreatePasteBody>,
) -> impl IntoResponse {
    if !auth::is_authenticated(&state.db, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if body.content.len() > state.max_text_size {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "Text content too large. Maximum is {} KB. For larger content, attach it as a file.",
                state.max_text_size / 1_024
            ),
        )
        .into_response();
    }

    let has_files = body
        .file_slugs
        .as_ref()
        .map(|f| !f.is_empty())
        .unwrap_or(false);
    if body.content.trim().is_empty() && !has_files {
        return json_error(StatusCode::BAD_REQUEST, "Content or files are required")
            .into_response();
    }

    let burn = match build_burn_fields(
        body.burn_trigger.as_deref(),
        body.burn_action.as_deref(),
        body.burn_after_value,
        body.burn_after_unit.as_deref(),
        body.burn_after_unlocks,
    ) {
        Ok(burn) => burn,
        Err(msg) => return json_error(StatusCode::BAD_REQUEST, msg).into_response(),
    };

    let mut slug = generate_slug();
    for _ in 0..5 {
        let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM pastes WHERE slug = ?")
            .bind(&slug)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);
        if exists.is_none() {
            break;
        }
        slug = generate_slug();
    }

    let title = body.title.unwrap_or_default();
    let language = body.language.unwrap_or_else(|| "plaintext".to_string());
    let pinned = if body.pinned.unwrap_or(0) != 0 { 1 } else { 0 };

    let result = sqlx::query(
        "INSERT INTO pastes (
            slug, title, content, language, pinned,
            burn_trigger, burn_action, burn_at, burn_after_unlocks, burn_unlocks_used, burn_pending_delete_at,
            encrypted_paste_key
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)",
    )
    .bind(&slug)
    .bind(&title)
    .bind(&body.content)
    .bind(&language)
    .bind(pinned)
    .bind(&burn.trigger)
    .bind(&burn.action)
    .bind(&burn.burn_at)
    .bind(burn.after_unlocks)
    .bind(&body.encrypted_paste_key)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            if let Some(ref file_slugs) = body.file_slugs {
                if !file_slugs.is_empty() {
                    if let Err(e) = file::link_files_to_paste(&state.db, &slug, file_slugs).await {
                        tracing::warn!("Failed to link some files to paste {slug}: {e}");
                    }
                }
            }

            let msg = serde_json::json!({ "type": "paste_created", "slug": slug });
            let _ = state.ws_sender.send(msg.to_string());
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "slug": slug, "success": true })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create paste: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create paste").into_response()
        }
    }
}

pub async fn handle_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    match enforce_time_burn(&state, &slug).await {
        TimeBurnResult::Deleted => {
            return json_error(StatusCode::GONE, "This paste has burned").into_response();
        }
        TimeBurnResult::Revoked | TimeBurnResult::None => {}
    }

    let Some(paste) = load_active_paste(&state, &slug).await else {
        return json_error(StatusCode::NOT_FOUND, "Paste not found").into_response();
    };

    let authenticated = auth::is_authenticated(&state.db, &headers).await;

    if !authenticated {
        if paste.share_wrapped_paste_key.is_none() {
            return json_error(StatusCode::NOT_FOUND, "Paste not found").into_response();
        }

        let files = file::get_files_for_paste(&state.db, &slug).await;
        let mut paste_json = serde_json::to_value(&paste).unwrap();
        if let Some(obj) = paste_json.as_object_mut() {
            obj.insert(
                "share_wrapped_paste_key".to_string(),
                serde_json::Value::Null,
            );
            obj.insert("share_auth_salt".to_string(), serde_json::Value::Null);
            obj.insert("share_auth_verifier".to_string(), serde_json::Value::Null);
        }
        return Json(serde_json::json!({
            "paste": paste_json,
            "files": files,
            "is_shared": true,
        }))
        .into_response();
    }

    let files = file::get_files_for_paste(&state.db, &slug).await;

    Json(serde_json::json!({
        "paste": paste,
        "files": files,
    }))
    .into_response()
}

pub async fn handle_unlock(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<UnlockBody>,
) -> impl IntoResponse {
    const MAX_ATTEMPTS: u32 = 10;
    const WINDOW: Duration = Duration::from_secs(3600);
    const PBKDF2_ITERS: u32 = 200_000;

    let ip = addr.ip();

    {
        let mut attempts = state.unlock_attempts.lock().unwrap();
        let key = (ip, slug.clone());
        let now = Instant::now();

        let entry = attempts
            .entry(key)
            .or_insert_with(|| crate::state::LoginAttempts {
                count: 0,
                window_start: now,
            });

        if now.duration_since(entry.window_start) >= WINDOW {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= MAX_ATTEMPTS {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many unlock attempts. Please wait before trying again.",
            )
            .into_response();
        }
        // Do NOT increment here — only failed auth attempts count toward the limit.
    }

    match enforce_time_burn(&state, &slug).await {
        TimeBurnResult::Deleted => {
            return json_error(StatusCode::GONE, "This paste has burned").into_response();
        }
        TimeBurnResult::Revoked | TimeBurnResult::None => {}
    }

    let Some(paste) = load_active_paste(&state, &slug).await else {
        return json_error(StatusCode::NOT_FOUND, "Paste not found").into_response();
    };

    let (Some(share_wrapped_paste_key), Some(share_auth_salt), Some(share_auth_verifier)) = (
        paste.share_wrapped_paste_key.clone(),
        paste.share_auth_salt.clone(),
        paste.share_auth_verifier.clone(),
    ) else {
        return json_error(StatusCode::NOT_FOUND, "Paste not found").into_response();
    };

    let salt_bytes = match hex::decode(&share_auth_salt) {
        Ok(b) => b,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Invalid share state")
                .into_response();
        }
    };

    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        body.auth_secret.as_bytes(),
        &salt_bytes,
        PBKDF2_ITERS,
        &mut derived,
    );
    let computed_verifier = hex::encode(derived);

    if computed_verifier != share_auth_verifier {
        // Increment the per-(IP, slug) failure counter only on a wrong access code.
        // Successful unlocks never consume rate-limit quota.
        {
            let mut attempts = state.unlock_attempts.lock().unwrap();
            let now = Instant::now();
            let entry = attempts
                .entry((ip, slug.clone()))
                .or_insert_with(|| crate::state::LoginAttempts { count: 0, window_start: now });
            if now.duration_since(entry.window_start) >= WINDOW {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
        }
        return json_error(StatusCode::UNAUTHORIZED, "Incorrect access code").into_response();
    }

    // Atomically increment the unlock counter and read back the new value in a
    // single SQL statement. This prevents a TOCTOU race where two concurrent
    // unlock requests both read the same stale count, causing the burn limit to
    // be bypassed. The UPDATE is the authoritative source of truth.
    let mut updated_unlocks_used = paste.burn_unlocks_used;
    let mut threshold_reached = false;
    if paste.burn_trigger.as_deref() == Some("unlock_count") {
        let row: Option<(i64,)> = sqlx::query_as(
            "UPDATE pastes
             SET burn_unlocks_used = burn_unlocks_used + 1,
                 updated_at = datetime('now')
             WHERE slug = ? AND burn_pending_delete_at IS NULL
             RETURNING burn_unlocks_used",
        )
        .bind(&slug)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

        if let Some((new_count,)) = row {
            updated_unlocks_used = new_count;
            if let Some(limit) = paste.burn_after_unlocks {
                threshold_reached = updated_unlocks_used >= limit;
            }
        } else {
            // Paste was deleted between our earlier load and this update
            // (e.g. concurrent burn). Treat as not found.
            tracing::warn!("Paste {slug} disappeared during unlock count increment");
            return json_error(StatusCode::GONE, "This paste has burned").into_response();
        }
    }

    let files = file::get_files_for_paste(&state.db, &slug).await;
    let mut paste_json = serde_json::to_value(&paste).unwrap();
    if let Some(obj) = paste_json.as_object_mut() {
        obj.insert("share_auth_salt".to_string(), serde_json::Value::Null);
        obj.insert("share_auth_verifier".to_string(), serde_json::Value::Null);
        obj.insert(
            "share_wrapped_paste_key".to_string(),
            serde_json::Value::Null,
        );
        obj.insert(
            "burn_unlocks_used".to_string(),
            serde_json::json!(updated_unlocks_used),
        );
    }

    if threshold_reached {
        if paste.burn_action == "revoke_share" {
            if let Err(e) = sqlx::query(
                "UPDATE pastes SET
                    share_wrapped_paste_key = NULL,
                    share_auth_salt = NULL,
                    share_auth_verifier = NULL,
                    burn_trigger = NULL,
                    burn_action = 'delete',
                    burn_at = NULL,
                    burn_after_unlocks = NULL,
                    burn_unlocks_used = 0,
                    burn_pending_delete_at = NULL,
                    updated_at = datetime('now')
                 WHERE slug = ?",
            )
            .bind(&slug)
            .execute(&state.db)
            .await
            {
                tracing::error!("Failed to revoke unlock-burned paste {slug}: {e}");
            }
            let msg = serde_json::json!({ "type": "paste_updated", "slug": slug });
            let _ = state.ws_sender.send(msg.to_string());
        } else {
            let total_bytes: u64 = files.iter().map(|f| f.file_size as u64).sum();
            let pending_at = pending_delete_at(total_bytes);
            if let Some(obj) = paste_json.as_object_mut() {
                obj.insert(
                    "burn_pending_delete_at".to_string(),
                    serde_json::json!(pending_at),
                );
            }
            if let Err(e) = sqlx::query(
                "UPDATE pastes SET
                    share_wrapped_paste_key = NULL,
                    share_auth_salt = NULL,
                    share_auth_verifier = NULL,
                    burn_trigger = NULL,
                    burn_action = 'delete',
                    burn_at = NULL,
                    burn_after_unlocks = NULL,
                    burn_unlocks_used = 0,
                    burn_pending_delete_at = ?,
                    updated_at = datetime('now')
                 WHERE slug = ?",
            )
            .bind(&pending_at)
            .bind(&slug)
            .execute(&state.db)
            .await
            {
                tracing::error!("Failed to mark unlock-burned paste {slug} for deletion: {e}");
            }
            let msg = serde_json::json!({ "type": "paste_deleted", "slug": slug });
            let _ = state.ws_sender.send(msg.to_string());
        }
    }

    Json(serde_json::json!({
        "share_wrapped_paste_key": share_wrapped_paste_key,
        "paste": paste_json,
        "files": files,
    }))
    .into_response()
}

pub async fn handle_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(body): Json<UpdatePasteBody>,
) -> impl IntoResponse {
    if !auth::is_authenticated(&state.db, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let exists: Option<(i64, Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT id, burn_trigger, burn_after_unlocks FROM pastes WHERE slug = ? AND burn_pending_delete_at IS NULL")
            .bind(&slug)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

    if exists.is_none() {
        return json_error(StatusCode::NOT_FOUND, "Paste not found").into_response();
    }

    enum BindValue {
        String(String),
        Int(i64),
    }
    let mut updates: Vec<String> = Vec::new();
    let mut binds: Vec<BindValue> = Vec::new();

    if let Some(ref title) = body.title {
        updates.push("title = ?".to_string());
        binds.push(BindValue::String(title.clone()));
    }
    if let Some(ref content) = body.content {
        if content.len() > state.max_text_size {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!(
                    "Text content too large. Maximum is {} KB. For larger content, attach it as a file.",
                    state.max_text_size / 1_024
                ),
            )
            .into_response();
        }
        updates.push("content = ?".to_string());
        binds.push(BindValue::String(content.clone()));
    }
    if let Some(ref language) = body.language {
        updates.push("language = ?".to_string());
        binds.push(BindValue::String(language.clone()));
    }
    if let Some(true) = body.revoke_share {
        updates.push("share_wrapped_paste_key = NULL".to_string());
        updates.push("share_auth_salt = NULL".to_string());
        updates.push("share_auth_verifier = NULL".to_string());
    } else if let Some(ref share_wrapped) = body.share_wrapped_paste_key {
        updates.push("share_wrapped_paste_key = ?".to_string());
        binds.push(BindValue::String(share_wrapped.clone()));
        if let Some(ref salt) = body.share_auth_salt {
            updates.push("share_auth_salt = ?".to_string());
            binds.push(BindValue::String(salt.clone()));
        }
        if let Some(ref verifier) = body.share_auth_verifier {
            updates.push("share_auth_verifier = ?".to_string());
            binds.push(BindValue::String(verifier.clone()));
        }
    }
    if let Some(pinned) = body.pinned {
        updates.push("pinned = ?".to_string());
        binds.push(BindValue::Int(if pinned != 0 { 1 } else { 0 }));
    }
    if let Some(ref encrypted_paste_key) = body.encrypted_paste_key {
        updates.push("encrypted_paste_key = ?".to_string());
        binds.push(BindValue::String(encrypted_paste_key.clone()));
    }
    if let Some(trigger) = body.burn_trigger.as_ref() {
        if let Some(trigger) = trigger.as_deref() {
            let burn = match build_burn_fields(
                Some(trigger),
                body.burn_action.as_deref(),
                body.burn_after_value,
                body.burn_after_unit.as_deref(),
                body.burn_after_unlocks,
            ) {
                Ok(burn) => burn,
                Err(msg) => return json_error(StatusCode::BAD_REQUEST, msg).into_response(),
            };
            updates.push("burn_trigger = ?".to_string());
            binds.push(BindValue::String(burn.trigger.unwrap()));
            updates.push("burn_action = ?".to_string());
            binds.push(BindValue::String(burn.action));
            match burn.burn_at {
                Some(ts) => {
                    updates.push("burn_at = ?".to_string());
                    binds.push(BindValue::String(ts));
                }
                None => updates.push("burn_at = NULL".to_string()),
            }
            match burn.after_unlocks {
                Some(count) => {
                    updates.push("burn_after_unlocks = ?".to_string());
                    binds.push(BindValue::Int(count));
                }
                None => updates.push("burn_after_unlocks = NULL".to_string()),
            }

            let burn_changed = match exists {
                Some((_, ref old_trigger, old_unlocks)) => {
                    old_trigger.as_deref() != Some(trigger) || old_unlocks != burn.after_unlocks
                },
                None => true,
            };
            if burn_changed {
                updates.push("burn_unlocks_used = 0".to_string());
                updates.push("burn_pending_delete_at = NULL".to_string());
            }
        } else {
            updates.push("burn_trigger = NULL".to_string());
            updates.push("burn_action = 'delete'".to_string());
            updates.push("burn_at = NULL".to_string());
            updates.push("burn_after_unlocks = NULL".to_string());
            updates.push("burn_unlocks_used = 0".to_string());
            updates.push("burn_pending_delete_at = NULL".to_string());
        }
    }

    if updates.is_empty() && body.new_file_slugs.is_none() && body.removed_file_slugs.is_none() {
        return json_error(StatusCode::BAD_REQUEST, "No fields to update").into_response();
    }

    if !updates.is_empty() {
        updates.push("updated_at = datetime('now')".to_string());
        let set_clause = updates.join(", ");
        let sql = format!("UPDATE pastes SET {set_clause} WHERE slug = ?");
        let mut query = sqlx::query(&sql);
        for bind in binds {
            query = match bind {
                BindValue::String(s) => query.bind(s),
                BindValue::Int(i) => query.bind(i),
            };
        }
        query = query.bind(&slug);

        if let Err(e) = query.execute(&state.db).await {
            tracing::error!("Failed to update paste: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update paste")
                .into_response();
        }
    }

    if let Some(removed) = &body.removed_file_slugs {
        for file_slug in removed {
            let owned: Option<(i64,)> =
                sqlx::query_as("SELECT id FROM files WHERE slug = ? AND paste_slug = ?")
                    .bind(file_slug)
                    .bind(&slug)
                    .fetch_optional(&state.db)
                    .await
                    .unwrap_or(None);

            if owned.is_none() {
                continue;
            }

            let file_path = std::path::Path::new(&state.uploads_dir).join(file_slug);
            if file_path.exists() {
                let _ = tokio::fs::remove_file(&file_path).await;
            }
            let _ = sqlx::query("DELETE FROM files WHERE slug = ? AND paste_slug = ?")
                .bind(file_slug)
                .bind(&slug)
                .execute(&state.db)
                .await;
        }
    }

    if let Some(ref new_slugs) = body.new_file_slugs {
        if !new_slugs.is_empty() {
            if let Err(e) = file::link_files_to_paste(&state.db, &slug, new_slugs).await {
                tracing::warn!("Failed to link some files to paste {slug}: {e}");
            }
        }
    }

    let msg = serde_json::json!({ "type": "paste_updated", "slug": slug });
    let _ = state.ws_sender.send(msg.to_string());
    Json(serde_json::json!({ "success": true })).into_response()
}

pub async fn handle_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    if !auth::is_authenticated(&state.db, &headers).await {
        return json_error(StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM pastes WHERE slug = ?")
        .bind(&slug)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    if exists.is_none() {
        return json_error(StatusCode::NOT_FOUND, "Paste not found").into_response();
    }

    match delete_paste_unchecked(&state, &slug).await {
        Ok(_) => Json(serde_json::json!({ "success": true })).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete paste: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete paste").into_response()
        }
    }
}
