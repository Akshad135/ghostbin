-- GhostBin E2EE schema, version 3.
-- The server never stores plaintext paste content, passphrases, or raw auth keys.

CREATE TABLE settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    kdf_salt BLOB NOT NULL,
    kdf_params TEXT NOT NULL,
    auth_hash BLOB NOT NULL,
    wrapped_vault_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

CREATE TABLE pastes (
    id TEXT PRIMARY KEY,
    key_salt BLOB NOT NULL,
    title_ct BLOB NOT NULL,
    content_ct BLOB NOT NULL,
    language_ct BLOB,
    pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    burn_mode TEXT CHECK (burn_mode IN ('time', 'unlock_count') OR burn_mode IS NULL),
    burn_after INTEGER CHECK (burn_after IS NULL OR burn_after > 0),
    burn_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE shares (
    paste_id TEXT PRIMARY KEY REFERENCES pastes(id) ON DELETE CASCADE,
    share_salt BLOB NOT NULL,
    share_auth_key BLOB NOT NULL,
    -- KDF params the share was created with; guests derive keys with these,
    -- so they are pinned per share instead of following the server default.
    kdf_params TEXT NOT NULL,
    wrapped_paste_key BLOB NOT NULL,
    expires_at INTEGER,
    unlocks_used INTEGER NOT NULL DEFAULT 0 CHECK (unlocks_used >= 0),
    max_unlocks INTEGER CHECK (max_unlocks IS NULL OR max_unlocks > 0),
    created_at INTEGER NOT NULL
);

CREATE TABLE share_tokens (
    token_hash BLOB PRIMARY KEY,
    share_id TEXT NOT NULL REFERENCES shares(paste_id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE share_challenges (
    nonce_hash BLOB PRIMARY KEY,
    share_id TEXT NOT NULL REFERENCES shares(paste_id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE files (
    id TEXT PRIMARY KEY,
    paste_id TEXT NOT NULL REFERENCES pastes(id) ON DELETE CASCADE,
    enc_meta BLOB NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    disk_name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_pastes_updated_at ON pastes(updated_at);
CREATE INDEX idx_pastes_burn_at ON pastes(burn_at) WHERE burn_at IS NOT NULL;
CREATE INDEX idx_shares_expires_at ON shares(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_share_tokens_expires_at ON share_tokens(expires_at);
CREATE INDEX idx_share_tokens_share_id ON share_tokens(share_id);
CREATE INDEX idx_share_challenges_expires_at ON share_challenges(expires_at);
CREATE INDEX idx_share_challenges_share_id ON share_challenges(share_id);
CREATE INDEX idx_files_paste_id ON files(paste_id);
