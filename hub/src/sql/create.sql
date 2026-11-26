INSERT INTO hub_login (id, state_hash, proof_hash, auth_box, phase, expires_at, renewal_hash)
SELECT ?1, ?2, ?3, ?4, 'pending', ?5, ?8
WHERE (SELECT COUNT(*) FROM hub_login
       WHERE expires_at > ?6 AND phase IN ('pending','claimed','ready')) < ?7
AND (?8 IS NULL OR EXISTS (SELECT 1 FROM hub_device_session WHERE session_hash = ?8))
RETURNING id
