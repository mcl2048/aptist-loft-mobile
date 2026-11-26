INSERT INTO hub_vault (owner_hash, vault_id, revision, ciphertext)
SELECT session.owner_hash, ?2, ?3 + 1, ?4
FROM hub_device_session AS session
WHERE session.session_hash = ?1
AND (
    (?3 = 0 AND (SELECT COUNT(*) FROM hub_vault WHERE owner_hash = session.owner_hash) < ?5)
    OR EXISTS (
        SELECT 1 FROM hub_vault
        WHERE owner_hash = session.owner_hash AND vault_id = ?2 AND revision = ?3
    )
)
ON CONFLICT (owner_hash, vault_id) DO UPDATE SET
    revision = excluded.revision, ciphertext = excluded.ciphertext
WHERE hub_vault.revision = ?3
RETURNING revision
