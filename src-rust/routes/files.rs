use std::collections::HashSet;
use std::path::Path as FsPath;
use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use sqlx::FromRow;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use super::pastes::burn_if_due;
use super::shares::token_allows_paste;
use super::util::{api_error, is_file_id, is_unique_violation, no_store_headers, require_csrf, require_owner};
use crate::auth;
use crate::envelope;
use crate::state::AppState;

const MAX_ENC_META_PLAINTEXT: usize = 4096;
const SHARE_TOKEN_HEADER: &str = "x-share-token";

#[derive(FromRow)]
pub struct FileMetaDto {
    pub id: String,
    pub enc_meta: Vec<u8>,
    pub size: i64,
    pub created_at: i64,
}

impl Serialize for FileMetaDto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Helper<'a> {
            id: &'a str,
            enc_meta: String,
            size: i64,
            created_at: i64,
        }

        Helper {
            id: &self.id,
            enc_meta: envelope::encode_envelope(&self.enc_meta),
            size: self.size,
            created_at: self.created_at,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadQuery {
    paste_id: String,
    file_id: String,
    size: i64,
}

#[derive(FromRow)]
struct DownloadRow {
    disk_name: String,
    size: i64,
    paste_id: String,
}

fn random_disk_name() -> String {
    let mut bytes = [0u8; 24];
    rand::Rng::fill(&mut rand::rng(), &mut bytes[..]);
    envelope::encode_b64(&bytes)
}

async fn remove_quiet(path: &FsPath) {
    if let Err(error) = tokio::fs::remove_file(path).await {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("Failed to remove {}: {error}", path.display());
        }
    }
}

/// POST /api/files?pasteId=...&fileId=...&size=...
/// Body: raw encrypted file container. `X-File-Meta` carries the encrypted metadata.
pub async fn handle_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<UploadQuery>,
    request: Request,
) -> Response {
    if let Err(response) = require_csrf(&headers) {
        return response;
    }
    if let Err(response) = require_owner(&state, &headers).await {
        return response;
    }
    if !super::util::is_paste_id(&query.paste_id) {
        return api_error(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid paste ID");
    }
    if !is_file_id(&query.file_id) {
        return api_error(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid file ID");
    }
    // Encrypted attachments are never empty (envelope + GCM overhead), so a
    // zero-size body is always invalid.
    if query.size <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "File must not be empty",
        );
    }
    if query.size as usize > state.max_file_size {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "FILE_TOO_LARGE",
            "File exceeds the size limit",
        );
    }

    let enc_meta = match headers
        .get("x-file-meta")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| envelope::decode_envelope(value, MAX_ENC_META_PLAINTEXT))
    {
        Some(value) => value,
        None => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Missing or invalid file metadata",
            );
        }
    };

    match burn_if_due(&state, &query.paste_id).await {
        Ok(true) => {
            return api_error(StatusCode::GONE, "PASTE_BURNED", "This paste has burned");
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let paste_exists: Option<String> = match sqlx::query_scalar("SELECT id FROM pastes WHERE id = ?")
        .bind(&query.paste_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("Failed to check paste: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    if paste_exists.is_none() {
        return api_error(StatusCode::NOT_FOUND, "PASTE_NOT_FOUND", "Paste not found");
    }

    // Fast-fail quota check before streaming the body; the authoritative
    // check runs inside the insert transaction below so concurrent uploads
    // cannot both pass it and overshoot the quota.
    let used: i64 = match sqlx::query_scalar(
        "SELECT COALESCE(SUM(size), 0) FROM files WHERE paste_id = ?",
    )
    .bind(&query.paste_id)
    .fetch_one(&state.db)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("Failed to sum paste files: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    if used.saturating_add(query.size) > state.max_file_size as i64 {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PASTE_TOO_LARGE",
            "Paste attachment quota exceeded",
        );
    }

    let disk_name = random_disk_name();
    let final_path = FsPath::new(&state.uploads_dir).join(&disk_name);
    let temp_path = FsPath::new(&state.uploads_dir).join(format!(".tmp-{disk_name}"));
    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
    {
        Ok(file) => file,
        Err(error) => {
            tracing::error!("Failed to create upload temp file: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Storage error");
        }
    };

    let mut stream = request.into_body().into_data_stream();
    let mut written: i64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                tracing::warn!("Upload stream failed: {error}");
                drop(file);
                remove_quiet(&temp_path).await;
                return api_error(StatusCode::BAD_REQUEST, "UPLOAD_FAILED", "Upload failed");
            }
        };
        written = written.saturating_add(chunk.len() as i64);
        if written > query.size {
            drop(file);
            remove_quiet(&temp_path).await;
            return api_error(
                StatusCode::BAD_REQUEST,
                "SIZE_MISMATCH",
                "Uploaded body is larger than declared size",
            );
        }
        if let Err(error) = file.write_all(&chunk).await {
            tracing::error!("Failed to write upload: {error}");
            drop(file);
            remove_quiet(&temp_path).await;
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Storage error");
        }
    }

    if written != query.size {
        drop(file);
        remove_quiet(&temp_path).await;
        return api_error(
            StatusCode::BAD_REQUEST,
            "SIZE_MISMATCH",
            "Uploaded body is smaller than declared size",
        );
    }

    if let Err(error) = file.sync_all().await {
        tracing::error!("Failed to sync upload: {error}");
        drop(file);
        remove_quiet(&temp_path).await;
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Storage error");
    }
    drop(file);

    if let Err(error) = tokio::fs::rename(&temp_path, &final_path).await {
        tracing::error!("Failed to finalize upload: {error}");
        remove_quiet(&temp_path).await;
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Storage error");
    }

    let now = auth::now_unix();
    let mut transaction = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!("Failed to begin file insert: {error}");
            remove_quiet(&final_path).await;
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    let used: i64 = match sqlx::query_scalar(
        "SELECT COALESCE(SUM(size), 0) FROM files WHERE paste_id = ?",
    )
    .bind(&query.paste_id)
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            let _ = transaction.rollback().await;
            tracing::error!("Failed to sum paste files: {error}");
            remove_quiet(&final_path).await;
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    if used.saturating_add(query.size) > state.max_file_size as i64 {
        let _ = transaction.rollback().await;
        remove_quiet(&final_path).await;
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PASTE_TOO_LARGE",
            "Paste attachment quota exceeded",
        );
    }

    let result = sqlx::query(
        "INSERT INTO files (id, paste_id, enc_meta, size, disk_name, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&query.file_id)
    .bind(&query.paste_id)
    .bind(&enc_meta)
    .bind(query.size)
    .bind(&disk_name)
    .bind(now)
    .execute(&mut *transaction)
    .await;

    if let Err(error) = result {
        let _ = transaction.rollback().await;
        remove_quiet(&final_path).await;
        if is_unique_violation(&error) {
            return api_error(StatusCode::CONFLICT, "FILE_EXISTS", "File ID already exists");
        }
        tracing::error!("Failed to insert file: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }

    if let Err(error) = transaction.commit().await {
        // Leave the uploaded file in place: if the commit actually landed
        // the row needs it, and if not, startup reconciliation cleans the
        // orphaned disk file.
        tracing::error!("Failed to commit file insert: {error}");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
    }

    let _ = state.ws_sender.send(
        json!({ "type": "paste_updated", "pasteId": query.paste_id }).to_string(),
    );

    (
        StatusCode::CREATED,
        no_store_headers(),
        Json(json!({ "success": true, "fileId": query.file_id })),
    )
        .into_response()
}

/// GET /api/files/:id
/// Owner session or an unlocked share token (`X-Share-Token`) is required.
pub async fn handle_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Response {
    if !is_file_id(&file_id) {
        return api_error(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid file ID");
    }

    let row: Option<DownloadRow> = match sqlx::query_as(
        "SELECT disk_name, size, paste_id FROM files WHERE id = ?",
    )
    .bind(&file_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("Failed to load file: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };
    let Some(row) = row else {
        return api_error(StatusCode::NOT_FOUND, "FILE_NOT_FOUND", "File not found");
    };

    let owner = match auth::current_session(&state.db, &headers).await {
        Ok(session) => session.is_some(),
        Err(error) => {
            tracing::error!("Session lookup failed: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    };

    if !owner {
        let token = headers
            .get(SHARE_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let allowed = match token_allows_paste(&state, token, &row.paste_id).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!("Share token check failed: {error}");
                return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
            }
        };
        if !allowed {
            return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Access denied");
        }
    }

    match burn_if_due(&state, &row.paste_id).await {
        Ok(true) => {
            return api_error(StatusCode::GONE, "PASTE_BURNED", "This paste has burned");
        }
        Ok(false) => {}
        Err(error) => {
            tracing::error!("Failed to enforce paste burn: {error}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "Database error");
        }
    }

    let path = FsPath::new(&state.uploads_dir).join(&row.disk_name);
    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(error) => {
            tracing::error!("Failed to open upload {}: {error}", path.display());
            return api_error(StatusCode::NOT_FOUND, "FILE_NOT_FOUND", "File not found");
        }
    };

    let body = Body::from_stream(ReaderStream::new(file));
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&row.size.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{file_id}.bin\""))
            .unwrap_or(HeaderValue::from_static("attachment")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Remove stale temp files and files whose DB row disappeared.
pub async fn reconcile_uploads(state: &Arc<AppState>) -> Result<(), String> {
    let known: HashSet<String> = sqlx::query_scalar::<_, String>("SELECT disk_name FROM files")
        .fetch_all(&state.db)
        .await
        .map_err(|error| format!("Failed to load upload names: {error}"))?
        .into_iter()
        .collect();

    let mut entries = tokio::fs::read_dir(&state.uploads_dir)
        .await
        .map_err(|error| format!("Failed to read uploads directory: {error}"))?;

    let mut removed = 0usize;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| format!("Failed to read uploads directory entry: {error}"))?
    {
        let file_type = entry
            .file_type()
            .await
            .map_err(|error| format!("Failed to inspect upload: {error}"))?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(".tmp-") || !known.contains(&name) {
            if let Err(error) = tokio::fs::remove_file(entry.path()).await {
                tracing::warn!("Failed to remove orphan upload {name}: {error}");
            } else {
                removed += 1;
            }
        }
    }

    if removed > 0 {
        tracing::info!("Removed {removed} orphan upload file(s)");
    }
    Ok(())
}
