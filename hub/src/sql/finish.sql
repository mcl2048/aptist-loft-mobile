UPDATE hub_login
SET phase = 'ready', auth_box = NULL, session_hash = ?2, session_box = ?3, session_expires_at = ?4
WHERE id = ?1 AND phase = 'claimed' AND expires_at > ?5 AND ?4 > ?5
RETURNING id
