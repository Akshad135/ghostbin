use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::HeaderMap;
use sqlx::SqlitePool;
use tokio::sync::broadcast;

use crate::proxy::Cidr;

/// One rate-limit bucket: attempts in the current window, plus an optional
/// lockout used by the exponential share-unlock limiter.
pub struct LoginAttempts {
    pub count: u32,
    pub window_start: Instant,
    pub locked_until: Option<Instant>,
}

/// Shared application state passed to all route handlers.
pub struct AppState {
    pub db: SqlitePool,
    pub dist_dir: String,
    pub uploads_dir: String,
    /// Maximum byte size of a single file attachment.
    pub max_file_size: usize,
    /// Maximum byte size of a text paste's `content` field.
    pub max_text_size: usize,
    pub ws_sender: broadcast::Sender<String>,
    pub login_attempts: Mutex<HashMap<IpAddr, LoginAttempts>>,
    /// Rate-limit counters for share-code unlock attempts.
    /// Key: (client IP, paste ID). Value: attempt count + window start.
    pub unlock_attempts: Mutex<HashMap<(IpAddr, String), LoginAttempts>>,
    /// Secondary per-IP control across all share endpoints (plan §7.4):
    /// caps one IP guessing at many different shares, each of which gets
    /// its own `unlock_attempts` bucket.
    pub share_ip_attempts: Mutex<HashMap<IpAddr, LoginAttempts>>,
    /// Account-wide login failure counter — the "per account" limit from
    /// plan §7.3, throttling distributed guessing across many IPs.
    pub account_login_failures: Mutex<LoginAttempts>,
    /// Trusted proxy CIDRs from `TRUSTED_PROXIES`; empty means the socket
    /// peer address is always used as the client IP.
    pub trusted_proxies: Vec<Cidr>,
}

impl AppState {
    pub fn new(
        db: SqlitePool,
        dist_dir: String,
        uploads_dir: String,
        max_file_size: usize,
        max_text_size: usize,
        trusted_proxies: Vec<Cidr>,
    ) -> Self {
        // Create a broadcast channel with a capacity of 100 messages
        let (ws_sender, _) = broadcast::channel(100);
        Self {
            db,
            dist_dir,
            uploads_dir,
            max_file_size,
            max_text_size,
            ws_sender,
            login_attempts: Mutex::new(HashMap::new()),
            unlock_attempts: Mutex::new(HashMap::new()),
            share_ip_attempts: Mutex::new(HashMap::new()),
            account_login_failures: Mutex::new(LoginAttempts {
                count: 0,
                window_start: Instant::now(),
                locked_until: None,
            }),
            trusted_proxies,
        }
    }

    /// Resolve the client IP for rate limiting, honoring `X-Forwarded-For`
    /// only when the request arrived through a trusted proxy (plan §9).
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        crate::proxy::client_ip(peer, headers, &self.trusted_proxies)
    }
}

/// Type alias used throughout route handlers.
pub type SharedState = Arc<AppState>;
