UPDATE hub_device_session
SET mail_box = ?4, mail_expires_at = ?5, renewed_by = ?1, mail_revision = mail_revision + 1
WHERE session_hash = ?2 AND owner_hash = ?3 AND mail_revision = ?6
AND EXISTS (
    SELECT 1 FROM hub_login AS tx
    WHERE tx.id = ?1 AND tx.proof_hash = ?7 AND tx.phase = 'ready'
    AND tx.expires_at > ?8 AND tx.session_expires_at > ?8
    AND tx.renewal_hash = ?2
)
