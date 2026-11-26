CREATE TABLE hub_device_session (
    session_hash TEXT PRIMARY KEY,
    owner_hash TEXT NOT NULL,
    identity_box TEXT NOT NULL,
    enrolled_by TEXT UNIQUE,
    renewed_by TEXT,
    mail_box TEXT,
    mail_expires_at INTEGER,
    mail_revision INTEGER NOT NULL DEFAULT 0,
    CHECK ((mail_box IS NULL) = (mail_expires_at IS NULL))
) STRICT;

CREATE INDEX hub_device_session_owner ON hub_device_session(owner_hash);
CREATE INDEX hub_device_session_mail_expiry ON hub_device_session(mail_expires_at)
WHERE mail_expires_at IS NOT NULL;

CREATE TABLE hub_vault (
    owner_hash TEXT NOT NULL,
    vault_id TEXT NOT NULL CHECK (length(vault_id) = 43),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4294967295),
    ciphertext TEXT NOT NULL CHECK (length(ciphertext) BETWEEN 22 AND 349526),
    PRIMARY KEY (owner_hash, vault_id)
) STRICT, WITHOUT ROWID;

ALTER TABLE hub_login ADD COLUMN renewal_hash TEXT;
CREATE INDEX hub_login_renewal ON hub_login(renewal_hash)
WHERE renewal_hash IS NOT NULL;
