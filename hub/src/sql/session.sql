SELECT id, session_hash, session_box, session_expires_at
FROM hub_login
WHERE session_hash = ?1 AND session_expires_at > ?2 AND phase = 'issued'
