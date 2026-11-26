SELECT device.session_hash
FROM hub_login AS tx
INNER JOIN hub_device_session AS device ON device.session_hash = ?4
WHERE tx.id = ?1 AND tx.proof_hash = ?2 AND tx.expires_at > ?3
AND tx.phase = 'issued' AND tx.session_expires_at > ?3
AND (device.enrolled_by = tx.id OR device.renewed_by = tx.id)
