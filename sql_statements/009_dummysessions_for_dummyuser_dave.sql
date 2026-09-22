CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO sessions (session_id, user_id, expires_at)
SELECT
    encode(gen_random_bytes(32), 'hex'),
    id,
    NOW() + INTERVAL '72 hour'
FROM users
WHERE email = 'dave@example.com';
