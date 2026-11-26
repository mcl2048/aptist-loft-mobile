UPDATE hub_login SET phase = 'issued'
WHERE id = ?1 AND proof_hash = ?2 AND expires_at > ?3
AND phase = 'ready' AND session_expires_at > ?3
AND EXISTS (
    SELECT 1 FROM hub_device_session AS device
    WHERE device.session_hash = ?4 AND (device.enrolled_by = ?1 OR device.renewed_by = ?1)
)
