DELETE FROM hub_device_session
WHERE enrolled_by = ?1 AND EXISTS (
    SELECT 1 FROM hub_login AS tx
    WHERE tx.id = ?1 AND tx.proof_hash = ?2 AND tx.phase = 'issued'
    AND tx.expires_at > ?3 AND tx.session_hash = hub_device_session.session_hash
)
