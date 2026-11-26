UPDATE hub_login SET phase = 'issued'
WHERE id = ?1 AND proof_hash = ?2 AND expires_at > ?3
AND phase IN ('ready','issued') AND session_expires_at > ?3
RETURNING id, session_hash, session_box, session_expires_at
