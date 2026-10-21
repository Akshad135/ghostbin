use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;

pub const SESSION_COOKIE_NAME: &str = "__Host-gb_session";
pub const CSRF_COOKIE_NAME: &str = "__Host-gb_csrf";
pub const SESSION_TTL_SECONDS: i64 = 60 * 60 * 24 * 30;
pub const AUTH_KEY_BYTES: usize = 32;
pub const KDF_SALT_BYTES: usize = 16;
pub const WRAPPED_VAULT_KEY_BYTES: usize = 12 + 32 + 16; // IV + 32-byte vault key + tag

const SESSION_ID_BYTES: usize = 16;
const SESSION_TOKEN_BYTES: usize = 32;
const CSRF_TOKEN_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub session: Session,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub memory_size: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub hash_length: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_size: 32 * 1024,
            iterations: 3,
            parallelism: 1,
            hash_length: 32,
        }
    }
}

impl KdfParams {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.memory_size < 8 || self.memory_size > 1_048_576 {
            return Err("memorySize must be between 8 and 1048576 KiB");
        }
        if self.iterations < 1 || self.iterations > 10 {
            return Err("iterations must be between 1 and 10");
        }
        if self.parallelism < 1 || self.parallelism > 8 {
            return Err("parallelism must be between 1 and 8");
        }
        if self.memory_size < 8 * self.parallelism {
            return Err("memorySize must be at least 8 * parallelism");
        }
        if self.hash_length != 32 {
            return Err("hashLength must be 32");
        }
        Ok(())
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_token(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn hash_token(token: &str) -> [u8; 32] {
    sha256(token.as_bytes())
}

pub fn hash_auth_key(auth_key: &[u8]) -> [u8; 32] {
    sha256(auth_key)
}

pub fn auth_key_matches(stored_hash: &[u8], presented_auth_key: &[u8]) -> bool {
    let presented_hash = hash_auth_key(presented_auth_key);
    stored_hash.ct_eq(presented_hash.as_slice()).into()
}

pub fn decode_base64url(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    if bytes.len() == expected_len {
        Some(bytes)
    } else {
        None
    }
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_vault_envelope(value: &str) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix("v1:")?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if bytes.len() == WRAPPED_VAULT_KEY_BYTES {
        Some(bytes)
    } else {
        None
    }
}

pub fn encode_vault_envelope(bytes: &[u8]) -> Option<String> {
    if bytes.len() != WRAPPED_VAULT_KEY_BYTES {
        return None;
    }
    Some(format!("v1:{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn session_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"
    ))
    .expect("session cookie is valid")
}

fn csrf_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{CSRF_COOKIE_NAME}={token}; Path=/; Secure; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"
    ))
    .expect("CSRF cookie is valid")
}

fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-gb_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
    )
}

fn clear_csrf_cookie() -> HeaderValue {
    HeaderValue::from_static("__Host-gb_csrf=; Path=/; Secure; SameSite=Lax; Max-Age=0")
}

pub fn append_auth_cookies(headers: &mut HeaderMap, session_token: &str, csrf_token: &str) {
    headers.append(header::SET_COOKIE, session_cookie(session_token));
    headers.append(header::SET_COOKIE, csrf_cookie(csrf_token));
}

pub fn append_clear_cookies(headers: &mut HeaderMap) {
    headers.append(header::SET_COOKIE, clear_session_cookie());
    headers.append(header::SET_COOKIE, clear_csrf_cookie());
}

pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=')
            && key.trim() == name
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

pub fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    get_cookie(headers, SESSION_COOKIE_NAME)
}

pub fn check_fetch_site(headers: &HeaderMap) -> bool {
    match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        Some(site) => {
            let site = site.to_ascii_lowercase();
            site == "same-origin" || site == "none"
        }
        None => true,
    }
}

pub fn check_csrf(headers: &HeaderMap) -> bool {
    if !check_fetch_site(headers) {
        return false;
    }

    let Some(cookie) = get_cookie(headers, CSRF_COOKIE_NAME) else {
        return false;
    };
    let Some(header_value) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
        return false;
    };

    !cookie.is_empty() && cookie.as_bytes().ct_eq(header_value.as_bytes()).into()
}

pub async fn create_session(pool: &SqlitePool) -> Result<NewSession, sqlx::Error> {
    let now = now_unix();
    let session = Session {
        id: random_token(SESSION_ID_BYTES),
        token: random_token(SESSION_TOKEN_BYTES),
    };
    let token_hash = hash_token(&session.token);
    let csrf_token = random_token(CSRF_TOKEN_BYTES);

    sqlx::query(
        "INSERT INTO sessions (id, token_hash, created_at, expires_at, last_seen)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&session.id)
    .bind(token_hash.as_slice())
    .bind(now)
    .bind(now + SESSION_TTL_SECONDS)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(NewSession {
        session,
        csrf_token,
    })
}

pub async fn current_session(
    pool: &SqlitePool,
    headers: &HeaderMap,
) -> Result<Option<Session>, sqlx::Error> {
    let Some(token) = session_token_from_headers(headers) else {
        return Ok(None);
    };
    let token_hash = hash_token(&token);

    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT id, expires_at FROM sessions WHERE token_hash = ?")
            .bind(token_hash.as_slice())
            .fetch_optional(pool)
            .await?;

    let Some((id, expires_at)) = row else {
        return Ok(None);
    };

    let now = now_unix();
    if expires_at <= now {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&id)
            .execute(pool)
            .await?;
        return Ok(None);
    }

    sqlx::query("UPDATE sessions SET last_seen = ? WHERE id = ?")
        .bind(now)
        .bind(&id)
        .execute(pool)
        .await?;

    Ok(Some(Session { id, token }))
}

pub async fn is_authenticated(pool: &SqlitePool, headers: &HeaderMap) -> bool {
    match current_session(pool, headers).await {
        Ok(session) => session.is_some(),
        Err(error) => {
            tracing::error!("Session lookup failed: {error}");
            false
        }
    }
}

pub async fn revoke_session(pool: &SqlitePool, token: &str) -> Result<(), sqlx::Error> {
    let token_hash = hash_token(token);
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(token_hash.as_slice())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_expired_sessions(pool: &SqlitePool, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
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
            .expect("in-memory SQLite");
        crate::db::init_schema(&pool, false)
            .await
            .expect("schema init");
        pool
    }

    fn cookie_headers(session_token: Option<&str>, csrf: Option<(&str, &str)>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let mut cookie = String::new();
        if let Some(token) = session_token {
            cookie.push_str(&format!("{SESSION_COOKIE_NAME}={token}"));
        }
        if let Some((cookie_token, _)) = csrf {
            if !cookie.is_empty() {
                cookie.push_str("; ");
            }
            cookie.push_str(&format!("{CSRF_COOKIE_NAME}={cookie_token}"));
        }
        if !cookie.is_empty() {
            headers.insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        }
        if let Some((_, header_token)) = csrf {
            headers.insert("x-csrf-token", HeaderValue::from_str(header_token).unwrap());
        }
        headers
    }

    #[test]
    fn tokens_are_url_safe_and_unique() {
        let a = random_token(SESSION_TOKEN_BYTES);
        let b = random_token(SESSION_TOKEN_BYTES);
        assert_eq!(a.len(), 43);
        assert_eq!(b.len(), 43);
        assert_ne!(a, b);
        assert!(!a.contains('='));
        assert!(!a.contains('+'));
        assert!(!a.contains('/'));
    }

    #[test]
    fn auth_key_hash_and_comparison() {
        let key = [7u8; AUTH_KEY_BYTES];
        let hash = hash_auth_key(&key);
        assert_eq!(hash.len(), 32);
        assert!(auth_key_matches(&hash, &key));
        let other = [8u8; AUTH_KEY_BYTES];
        assert!(!auth_key_matches(&hash, &other));
    }

    #[test]
    fn cookies_have_the_required_flags() {
        let session = session_cookie("session-token")
            .to_str()
            .unwrap()
            .to_string();
        assert!(session.contains("__Host-gb_session=session-token"));
        assert!(session.contains("HttpOnly"));
        assert!(session.contains("Secure"));
        assert!(session.contains("SameSite=Lax"));
        assert!(session.contains("Path=/"));
        assert!(session.contains("Max-Age=2592000"));

        let csrf = csrf_cookie("csrf-token").to_str().unwrap().to_string();
        assert!(csrf.contains("__Host-gb_csrf=csrf-token"));
        assert!(!csrf.contains("HttpOnly"));
        assert!(csrf.contains("Secure"));
    }

    #[test]
    fn csrf_requires_matching_cookie_and_header() {
        let good = cookie_headers(None, Some(("csrf-token", "csrf-token")));
        assert!(check_csrf(&good));

        let bad = cookie_headers(None, Some(("csrf-token", "other-token")));
        assert!(!check_csrf(&bad));

        let mut cross_site = cookie_headers(None, Some(("csrf-token", "csrf-token")));
        cross_site.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!check_csrf(&cross_site));
    }

    #[test]
    fn vault_envelope_requires_prefix_and_exact_length() {
        let bytes = vec![1u8; WRAPPED_VAULT_KEY_BYTES];
        let encoded = encode_vault_envelope(&bytes).unwrap();
        assert!(encoded.starts_with("v1:"));
        assert_eq!(decode_vault_envelope(&encoded).unwrap(), bytes);
        assert!(decode_vault_envelope("v2:AAAA").is_none());
        assert!(decode_vault_envelope("v1:AAAA").is_none());
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let pool = test_pool().await;
        let created = create_session(&pool).await.unwrap();
        let token = created.session.token.clone();
        let id = created.session.id.clone();

        let headers = cookie_headers(Some(&token), None);
        let current = current_session(&pool, &headers).await.unwrap().unwrap();
        assert_eq!(current.id, id);

        revoke_session(&pool, &token).await.unwrap();
        assert!(current_session(&pool, &headers).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_session_is_deleted() {
        let pool = test_pool().await;
        let created = create_session(&pool).await.unwrap();
        let token = created.session.token.clone();
        let headers = cookie_headers(Some(&token), None);

        sqlx::query("UPDATE sessions SET expires_at = ? WHERE id = ?")
            .bind(now_unix() - 1)
            .bind(&created.session.id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(current_session(&pool, &headers).await.unwrap().is_none());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
