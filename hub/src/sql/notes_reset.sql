INSERT INTO hub_notes (owner_hash, revision, ciphertext, key_epoch, reset_revision, reset_fingerprint)
SELECT session.owner_hash, ?2 + 1, ?3, ?4, ?2 + 1, ?5
FROM hub_device_session AS session
WHERE session.session_hash = ?1
AND (?2 = 0 OR EXISTS (
    SELECT 1 FROM hub_notes
    WHERE owner_hash = session.owner_hash AND revision = ?2
))
ON CONFLICT (owner_hash) DO UPDATE SET
    revision = excluded.revision,
    ciphertext = excluded.ciphertext,
    key_epoch = excluded.key_epoch,
    reset_revision = excluded.reset_revision,
    reset_fingerprint = excluded.reset_fingerprint
WHERE hub_notes.revision = ?2 AND hub_notes.key_epoch IS NOT excluded.key_epoch
RETURNING revision
