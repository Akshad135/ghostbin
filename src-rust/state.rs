use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sqlx::SqlitePool;
use tokio::sync::broadcast;

/// Tracks recent failed login attempts from a single IP, for simple
/// fixed-window rate limiting.
pub struct LoginAttempts {
    pub count: u32,
    pub window_start: Instant,
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
}

impl AppState {
    pub fn new(
        db: SqlitePool,
        dist_dir: String,
        uploads_dir: String,
        max_file_size: usize,
        max_text_size: usize,
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
        }
    }
}

/// Type alias used throughout route handlers.
pub type SharedState = Arc<AppState>;
