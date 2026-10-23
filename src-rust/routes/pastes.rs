use std::path::Path as FsPath;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;

use super::files::FileMetaDto;
use super::util::{api_error, is_paste_id, is_unique_violation, no_store_headers, require_csrf, require_owner};
use crate::auth;
use crate::envelope;
use crate::state::AppState;

const MAX_TITLE_PLAINTEXT: usize = 16 * 1024;
const MAX_LANGUAGE_PLAINTEXT: usize = 4 * 1024;
const MAX_BURN_SECONDS: i64 = 30 * 24 * 60 * 60;
const MAX_BURN_UNLOCKS: i64 = 1_000_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePasteBody {
    id: String,
    key_salt: String,
    title_ct: String,
    content_ct: String,
    language_ct: Option<String>,
    pinned: Option<bool>,
    burn_mode: Option<String>,
    burn_after: Option<i64>,
    burn_after_seconds: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePasteBody {
    title_ct: Option<String>,
    content_ct: Option<String>,
    language_ct: Option<String>,
    pinned: Option<bool>,
    burn_mode: Option<String>,
    burn_after: Option<i64>,
    burn_after_seconds: Option<i64>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    page: Option<u32>,
    limit: Option<u32>,
}

#[derive(FromRow)]
struct PasteRow {
    id: String,
    key_salt: Vec<u8>,
    title_ct: Vec<u8>,
    content_ct: Vec<u8>,
    language_ct: Option<Vec<u8>>,
    pinned: i64,
    burn_mode: Option<String>,
    burn_after: Option<i64>,
    burn_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
    file_count: i64,
}

#[derive(FromRow)]
struct PasteListRow {
    id: String,
    key_salt: Vec<u8>,
    title_ct: Vec<u8>,
    language_ct: Option<Vec<u8>>,
    pinned: i64,
    burn_mode: Option<String>,
    burn_after: Option<i64>,
    burn_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
    file_count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasteSummary {
    pub id: String,
    pub key_salt: String,
    pub title_ct: String,
    pub language_ct: Option<String>,
    pub pinned: bool,
    pub burn_mode: Option<String>,
    pub burn_after: Option<i64>,
    pub burn_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub file_count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasteDetail {
    #[serde(flatten)]
    pub summary: PasteSummary,
    pub content_ct: String,
    pub files: Vec<FileMetaDto>,
}

impl PasteRow {
    fn summary(&self) -> PasteSummary {
        PasteSummary {
            id: self.id.clone(),
            key_salt: envelope::encode_b64(&self.key_salt),
            title_ct: envelope::encode_envelope(&self.title_ct),
            language_ct: self.language_ct.as_deref().map(envelope::encode_envelope),
            pinned: self.pinned != 0,
            burn_mode: self.burn_mode.clone(),
            burn_after: self.burn_after,
            burn_at: self.burn_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            file_count: self.file_count,
        }
    }
}

impl PasteListRow {
    fn summary(&self) -> PasteSummary {
        PasteSummary {
            id: self.id.clone(),
            key_salt: envelope::encode_b64(&self.key_salt),
            title_ct: envelope::encode_envelope(&self.title_ct),
            language_ct: self.language_ct.as_deref().map(envelope::encode_envelope),
            pinned: self.pinned != 0,
            burn_mode: self.burn_mode.clone(),
            burn_after: self.burn_after,
            burn_at: self.burn_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            file_count: self.file_count,
        }
    }
}

struct ValidatedPaste {
    id: String,
    key_salt: Vec<u8>,
    title_ct: Vec<u8>,
    content_ct: Vec<u8>,
    language_ct: Option<Vec<u8>>,
    pinned: bool,
    burn_mode: Option<String>,
    burn_after: Option<i64>,
    burn_at: Option<i64>,
}

fn invalid(message: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "INVALID_REQUEST", message)
}

fn validate_envelope(
    value: &str,
    max_plaintext_len: usize,
    field: &'static str,
) -> Result<Vec<u8>, Response> {
    envelope::decode_envelope(value, max_plaintext_len)
        .ok_or_else(|| invalid(&format!("Invalid {field} ciphertext")))
}

fn validate_language(value: Option<&str>) -> Result<Option<Vec<u8>>, Response> {
    match value {
        None | Some("") => Ok(None),
        Some(value) => validate_envelope(value, MAX_LANGUAGE_PLAINTEXT, "language").map(Some),
    }
}

fn compute_burn(
    mode: Option<&str>,
    burn_after: Option<i64>,
    burn_after_seconds: Option<i64>,
    now: i64,
) -> Result<(Option<String>, Option<i64>, Option<i64>), Response> {
    match mode {
        None | Some("none") => {
            if burn_after.is_some() || burn_after_seconds.is_some() {
                return Err(invalid("Burn fields require a burn mode"));
            }
            Ok((None, None, None))
        }
        Some("time") => {
            if burn_after.is_some() {
                return Err(invalid("Time burn must not include burnAfter"));
            }
            let seconds = burn_after_seconds.ok_or_else(|| invalid("Missing burnAfterSeconds"))?;
            if !(60..=MAX_BURN_SECONDS).contains(&seconds) {
                return Err(invalid("Burn time must be between 1 minute and 30 days"));
            }
            Ok((Some("time".to_string()), None, Some(now + seconds)))
        }
        Some("unlock_count") => {
            if burn_after_seconds.is_some() {
                return Err(invalid("Unlock burn must not include burnAfterSeconds"));
            }
            let count = burn_after.ok_or_else(|| invalid("Missing burnAfter"))?;
            if !(1..=MAX_BURN_UNLOCKS).contains(&count) {
                return Err(invalid("burnAfter is out of range"));
            }
            Ok((Some("unlock_count".to_string()), Some(count), None))
        }
        Some(_) => Err(invalid("Invalid burn mode")),
    }
}

fn validate_create(body: CreatePasteBody, state: &AppState) -> Result<ValidatedPaste, Response> {
    if !is_paste_id(&body.id) {
        return Err(invalid("Invalid paste ID"));
    }
    let key_salt = envelope::decode_b64_exact(&body.key_salt, 16)
        .ok_or_else(|| invalid("Invalid key salt"))?;
    let title_ct = validate_envelope(&body.title_ct, MAX_TITLE_PLAINTEXT, "title")?;
    let content_ct = validate_envelope(
        &body.content_ct,
        state.max_text_size.saturating_mul(2),
        "content",
    )?;
    let language_ct = validate_language(body.language_ct.as_deref())?;
    let (burn_mode, burn_after, burn_at) = compute_burn(
        body.burn_mode.as_deref(),
        body.burn_after,
        body.burn_after_seconds,
        auth::now_unix(),
    )?;

    Ok(ValidatedPaste {
        id: body.id,
        key_salt,
        title_ct,
        content_ct,
        language_ct,
        pinned: body.pinned.unwrap_or(false),
        burn_mode,
        burn_after,
        burn_at,
    })
}

async fn fetch_paste(
    state: &AppState,
    paste_id: &str,
) -> Result<Option<PasteRow>, sqlx::Error> {
    sqlx::query_as::<_, PasteRow>(
        "SELECT id, key_salt, title_ct, content_ct, language_ct, pinned, burn_mode,
                burn_after, burn_at, created_at, updated_at,
                (SELECT COUNT(*) FROM files f WHERE f.paste_id = p.id) AS file_count
         FROM pastes p WHERE id = ?",
    )
    .bind(paste_id)
    .fetch_optional(&state.db)
    .await
}

/// Delete a paste, its share and files, and the on-disk file bodies.
pub async fn delete_paste(state: &Arc<AppState>, paste_id: &str) -> Result<bool, sqlx::Error> {
    // Collect file names and delete the row in one write transaction: a
    // file upload committing between two loose statements would cascade-
    // delete its files row after the names were read, leaving the
    // encrypted body stranded on disk past the burn.
    let mut transaction = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let disk_names: Vec<String> =
        sqlx::query_scalar("SELECT disk_name FROM files WHERE paste_id = ?")
            .bind(paste_id)
            .fetch_all(&mut *transaction)
            .await?;

    let deleted = sqlx::query("DELETE FROM pastes WHERE id = ?")
        .bind(paste_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
        > 0;
    transaction.commit().await?;

    if !deleted {
        return Ok(false);
    }

    for disk_name in disk_names {
        let path = FsPath::new(&state.uploads_dir).join(disk_name);
        if let Err(error) = tokio::fs::remove_file(&path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Failed to delete upload {}: {error}", path.display());
            }
        }
    }

    let _ = state
        .ws_sender
        .send(json!({ "type": "paste_deleted", "pasteId": paste_id }).to_string());
    Ok(true)
}

/// Delete a paste if its time burn has expired. Returns true when deleted.
pub async fn burn_if_due(state: &Arc<AppState>, paste_id: &str) -> Result<bool, sqlx::Error> {
    let due: Option<i64> = sqlx::query_scalar(
        "SELECT burn_at FROM pastes
         WHERE id = ? AND burn_mode = 'time' AND burn_at IS NOT NULL AND burn_at <= ?",
    )
    .bind(paste_id)
    .bind(auth::now_unix())
    .fetch_optional(&state.db)
    .await?;

    if due.is_none() {
        return Ok(false);
    }
    delete_paste(state, paste_id).await
}

/// Periodic sweep for time-burned pastes.
pub async fn burn_due_pastes(state: &Arc<AppState>) -> Result<usize, sqlx::Error> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM pastes
         WHERE burn_mode = 'time' AND burn_at IS NOT NULL AND burn_at <= ?",
    )
    .bind(auth::now_unix())
    .fetch_all(&state.db)
    .await?;

    let mut deleted = 0;
    for id in ids {
        if delete_paste(state, &id).await? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// GET /api/pastes
pub async fn handle_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if let Err(response) = require_owner(&state, &headers).await {
        return response;
    }

    let page = query.page.unwrap_or(1).max(1) as i64;
    let limit = query.limit.unwrap_or(20).clamp(1, 100) as i64;
    let offset = (page - 1) * limit;
    let now = auth::now_unix();

    let total: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM pastes
         WHERE NOT (burn_mode = 'time' AND burn_at IS NOT NULL AND burn_at <= ?)",
    )
    .bind(now)
    .fetch_one(&state.db)
    .await
    {
        Ok(total) => total,
        Err(error) => {
            tracing::error!("Failed to count pastes: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    let rows: Vec<PasteListRow> = match sqlx::query_as(
        "SELECT id, key_salt, title_ct, language_ct, pinned, burn_mode,
                burn_after, burn_at, created_at, updated_at,
                (SELECT COUNT(*) FROM files f WHERE f.paste_id = p.id) AS file_count
         FROM pastes p
         WHERE NOT (burn_mode = 'time' AND burn_at IS NOT NULL AND burn_at <= ?)
         ORDER BY pinned DESC, updated_at DESC, id ASC
         LIMIT ? OFFSET ?",
    )
    .bind(now)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Failed to list pastes: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    let pastes = rows.iter().map(PasteListRow::summary).collect::<Vec<_>>();
    let has_more = offset + (rows.len() as i64) < total;

    (
        no_store_headers(),
        Json(json!({
            "pastes": pastes,
            "total": total,
            "page": page,
            "limit": limit,
            "hasMore": has_more,
        })),
    )
        .into_response()
}

/// POST /api/pastes
pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreatePasteBody>,
) -> Response {
    if let Err(response) = require_csrf(&headers) {
        return response;
    }
    if let Err(response) = require_owner(&state, &headers).await {
        return response;
    }

    let paste = match validate_create(body, &state) {
        Ok(paste) => paste,
        Err(response) => return response,
    };
    let now = auth::now_unix();

    let result = sqlx::query(
        "INSERT INTO pastes
            (id, key_salt, title_ct, content_ct, language_ct, pinned,
             burn_mode, burn_after, burn_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&paste.id)
    .bind(&paste.key_salt)
    .bind(&paste.title_ct)
    .bind(&paste.content_ct)
    .bind(paste.language_ct.as_deref())
    .bind(i64::from(paste.pinned))
    .bind(&paste.burn_mode)
    .bind(paste.burn_after)
    .bind(paste.burn_at)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await;

    if let Err(error) = result {
        if is_unique_violation(&error) {
            return api_error(StatusCode::CONFLICT, "PASTE_EXISTS", "Paste ID already exists");
        }
        tracing::error!("Failed to create paste: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }

    let summary = PasteSummary {
        id: paste.id.clone(),
        key_salt: envelope::encode_b64(&paste.key_salt),
        title_ct: envelope::encode_envelope(&paste.title_ct),
        language_ct: paste.language_ct.as_deref().map(envelope::encode_envelope),
        pinned: paste.pinned,
        burn_mode: paste.burn_mode,
        burn_after: paste.burn_after,
        burn_at: paste.burn_at,
        created_at: now,
        updated_at: now,
        file_count: 0,
    };

    let _ = state.ws_sender.send(
        json!({ "type": "paste_created", "pasteId": paste.id }).to_string(),
    );

    (
        StatusCode::CREATED,
        no_store_headers(),
        Json(json!({ "paste": summary })),
    )
        .into_response()
}

/// GET /api/pastes/:id
pub async fn handle_get(
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

    let row = match fetch_paste(&state, &paste_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return api_error(StatusCode::NOT_FOUND, "PASTE_NOT_FOUND", "Paste not found");
        }
        Err(error) => {
            tracing::error!("Failed to load paste: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    let files: Vec<FileMetaDto> = match sqlx::query_as(
        "SELECT id, enc_meta, size, created_at FROM files
         WHERE paste_id = ? ORDER BY created_at ASC, id ASC",
    )
    .bind(&paste_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(files) => files,
        Err(error) => {
            tracing::error!("Failed to load paste files: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    let detail = PasteDetail {
        summary: row.summary(),
        content_ct: envelope::encode_envelope(&row.content_ct),
        files,
    };

    (
        no_store_headers(),
        Json(json!({ "paste": detail })),
    )
        .into_response()
}

/// PUT /api/pastes/:id
pub async fn handle_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(paste_id): Path<String>,
    Json(body): Json<UpdatePasteBody>,
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

    let row = match fetch_paste(&state, &paste_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return api_error(StatusCode::NOT_FOUND, "PASTE_NOT_FOUND", "Paste not found");
        }
        Err(error) => {
            tracing::error!("Failed to load paste: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    // Burn changes must not leave an existing share with stale maxUnlocks.
    // Require the owner to revoke/replace the share first.
    let burn_change = body.burn_mode.is_some()
        || body.burn_after.is_some()
        || body.burn_after_seconds.is_some();
    if burn_change {
        let share_exists: Option<String> =
            match sqlx::query_scalar("SELECT paste_id FROM shares WHERE paste_id = ?")
                .bind(&paste_id)
                .fetch_optional(&state.db)
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!("Failed to check existing share: {error}");
                    return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
                }
            };
        if share_exists.is_some() {
            return api_error(
                StatusCode::CONFLICT,
                "SHARE_EXISTS",
                "Revoke the share before changing burn settings",
            );
        }
    }

    let mut title_ct = row.title_ct;
    let mut content_ct = row.content_ct;
    let mut language_ct = row.language_ct;
    let mut pinned = row.pinned != 0;
    let mut burn_mode = row.burn_mode;
    let mut burn_after = row.burn_after;
    let mut burn_at = row.burn_at;
    let mut changed = false;

    if let Some(value) = body.title_ct {
        title_ct = match validate_envelope(&value, MAX_TITLE_PLAINTEXT, "title") {
            Ok(value) => value,
            Err(response) => return response,
        };
        changed = true;
    }
    if let Some(value) = body.content_ct {
        content_ct = match validate_envelope(
            &value,
            state.max_text_size.saturating_mul(2),
            "content",
        ) {
            Ok(value) => value,
            Err(response) => return response,
        };
        changed = true;
    }
    if let Some(value) = body.language_ct {
        language_ct = match validate_language(Some(&value)) {
            Ok(value) => value,
            Err(response) => return response,
        };
        changed = true;
    }
    if let Some(value) = body.pinned {
        pinned = value;
        changed = true;
    }
    if let Some(mode) = body.burn_mode {
        let (new_mode, new_after, new_at) =
            match compute_burn(Some(&mode), body.burn_after, body.burn_after_seconds, auth::now_unix()) {
                Ok(value) => value,
                Err(response) => return response,
            };
        burn_mode = new_mode;
        burn_after = new_after;
        burn_at = new_at;
        changed = true;
    } else if body.burn_after.is_some() || body.burn_after_seconds.is_some() {
        return invalid("Burn fields require a burn mode");
    }

    if !changed {
        return invalid("No changes supplied");
    }

    let now = auth::now_unix();
    let result = sqlx::query(
        "UPDATE pastes
         SET title_ct = ?, content_ct = ?, language_ct = ?, pinned = ?,
             burn_mode = ?, burn_after = ?, burn_at = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(&title_ct)
    .bind(&content_ct)
    .bind(language_ct.as_deref())
    .bind(i64::from(pinned))
    .bind(&burn_mode)
    .bind(burn_after)
    .bind(burn_at)
    .bind(now)
    .bind(&paste_id)
    .execute(&state.db)
    .await;

    match result {
        Ok(result) if result.rows_affected() == 1 => {}
        // Zero rows: the paste vanished between the fetch above and this
        // UPDATE (concurrent delete or burn sweep). Report the miss
        // instead of acknowledging a save that never landed.
        Ok(_) => {
            return api_error(StatusCode::NOT_FOUND, "PASTE_NOT_FOUND", "Paste not found");
        }
        Err(error) => {
            tracing::error!("Failed to update paste: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let summary = PasteSummary {
        id: paste_id.clone(),
        key_salt: envelope::encode_b64(&row.key_salt),
        title_ct: envelope::encode_envelope(&title_ct),
        language_ct: language_ct.as_deref().map(envelope::encode_envelope),
        pinned,
        burn_mode,
        burn_after,
        burn_at,
        created_at: row.created_at,
        updated_at: now,
        file_count: row.file_count,
    };

    let _ = state.ws_sender.send(
        json!({ "type": "paste_updated", "pasteId": paste_id }).to_string(),
    );

    (
        no_store_headers(),
        Json(json!({ "paste": summary })),
    )
        .into_response()
}

/// DELETE /api/pastes/:id
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

    match delete_paste(&state, &paste_id).await {
        Ok(true) => (no_store_headers(), Json(json!({ "success": true }))).into_response(),
        Ok(false) => api_error(StatusCode::NOT_FOUND, "PASTE_NOT_FOUND", "Paste not found"),
        Err(error) => {
            tracing::error!("Failed to delete paste: {error}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burn_modes_are_validated() {
        assert!(compute_burn(None, None, None, 100).is_ok());
        assert!(compute_burn(Some("time"), None, Some(60), 100).is_ok());
        assert_eq!(
            compute_burn(Some("time"), None, Some(60), 100).unwrap(),
            (Some("time".to_string()), None, Some(160))
        );
        assert!(compute_burn(Some("time"), None, Some(59), 100).is_err());
        assert!(compute_burn(Some("time"), Some(2), Some(60), 100).is_err());
        assert!(compute_burn(Some("unlock_count"), Some(2), None, 100).is_ok());
        assert!(compute_burn(Some("unlock_count"), Some(0), None, 100).is_err());
        assert!(compute_burn(Some("unlock_count"), None, None, 100).is_err());
        assert!(compute_burn(Some("none"), Some(2), None, 100).is_err());
    }
}
