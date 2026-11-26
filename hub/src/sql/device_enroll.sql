INSERT INTO hub_device_session (session_hash, owner_hash, identity_box, enrolled_by, mail_box, mail_expires_at)
SELECT tx.session_hash, ?2, ?3, tx.id, ?4, ?5
FROM hub_login AS tx
WHERE tx.id = ?1 AND tx.proof_hash = ?6 AND tx.phase = 'ready'
AND tx.expires_at > ?7 AND tx.session_expires_at > ?7
AND tx.renewal_hash IS NULL
AND (SELECT COUNT(*) FROM hub_device_session WHERE owner_hash = ?2) < ?8
ON CONFLICT(session_hash) DO NOTHING
