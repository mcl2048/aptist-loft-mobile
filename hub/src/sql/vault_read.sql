SELECT vault.revision, vault.ciphertext
FROM hub_device_session AS session
INNER JOIN hub_vault AS vault ON vault.owner_hash = session.owner_hash
WHERE session.session_hash = ?1 AND vault.vault_id = ?2
