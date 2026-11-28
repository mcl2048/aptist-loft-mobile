SELECT notes.reset_revision
FROM hub_device_session AS session
JOIN hub_notes AS notes ON notes.owner_hash = session.owner_hash
WHERE session.session_hash = ?1 AND notes.key_epoch = ?2
    AND notes.reset_revision = ?3 + 1 AND notes.reset_fingerprint = ?4
