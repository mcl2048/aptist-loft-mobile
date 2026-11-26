DELETE FROM hub_login WHERE renewal_hash = ?1
OR session_hash = ?1 AND phase = 'issued'
