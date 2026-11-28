CREATE TABLE hub_notes (
    owner_hash TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4294967295),
    ciphertext TEXT NOT NULL CHECK (length(ciphertext) BETWEEN 22 AND 349526)
) STRICT, WITHOUT ROWID;
