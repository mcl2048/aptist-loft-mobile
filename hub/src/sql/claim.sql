UPDATE hub_login SET phase = 'claimed'
WHERE state_hash = ?1 AND expires_at > ?2 AND phase = 'pending'
RETURNING id, auth_box
