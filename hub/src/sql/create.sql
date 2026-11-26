INSERT INTO hub_login (id, state_hash, proof_hash, auth_box, phase, expires_at)
SELECT ?1, ?2, ?3, ?4, 'pending', ?5
WHERE (SELECT COUNT(*) FROM hub_login
       WHERE expires_at > ?6 AND phase IN ('pending','claimed','ready')) < ?7
RETURNING id
