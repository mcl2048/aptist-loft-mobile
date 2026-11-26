INSERT INTO hub_rate (bucket, window, used) VALUES (?1, ?2, 1)
ON CONFLICT(bucket) DO UPDATE SET
    used = CASE WHEN hub_rate.window < excluded.window THEN 1 ELSE hub_rate.used + 1 END,
    window = excluded.window
WHERE hub_rate.window < excluded.window OR (hub_rate.window = excluded.window AND hub_rate.used < ?3)
RETURNING used
