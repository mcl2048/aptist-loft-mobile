SELECT notes.revision,
       CASE WHEN notes.revision != ?2 THEN notes.ciphertext END AS ciphertext
FROM hub_device_session AS session
LEFT JOIN hub_notes AS notes ON notes.owner_hash = session.owner_hash
WHERE session.session_hash = ?1
