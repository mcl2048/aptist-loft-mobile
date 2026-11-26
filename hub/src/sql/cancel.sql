DELETE FROM hub_login WHERE id = ?1 AND proof_hash = ?2 RETURNING id
