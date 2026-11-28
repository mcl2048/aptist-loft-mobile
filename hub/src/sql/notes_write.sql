INSERT INTO hub_notes (owner_hash, revision, ciphertext)
SELECT session.owner_hash, ?2 + 1, ?3
FROM hub_device_session AS session
WHERE session.session_hash = ?1
AND (?2 = 0 OR EXISTS (
    SELECT 1 FROM hub_notes
    WHERE owner_hash = session.owner_hash AND revision = ?2
))
ON CONFLICT (owner_hash) DO UPDATE SET
    revision = excluded.revision,
    ciphertext = excluded.ciphertext
WHERE hub_notes.revision = ?2
RETURNING revision
