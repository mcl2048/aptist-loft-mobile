CREATE TABLE hub_login (
    id TEXT PRIMARY KEY,
    state_hash TEXT NOT NULL UNIQUE,
    proof_hash TEXT NOT NULL,
    auth_box TEXT,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'claimed', 'ready', 'issued', 'denied', 'failed')),
    expires_at INTEGER NOT NULL,
    session_hash TEXT UNIQUE,
    session_box TEXT,
    session_expires_at INTEGER
) STRICT;

CREATE INDEX hub_login_expiry ON hub_login(expires_at);
CREATE INDEX hub_login_session_expiry ON hub_login(session_expires_at);

CREATE TABLE hub_rate (
    bucket INTEGER PRIMARY KEY,
    window INTEGER NOT NULL,
    used INTEGER NOT NULL
) STRICT;
