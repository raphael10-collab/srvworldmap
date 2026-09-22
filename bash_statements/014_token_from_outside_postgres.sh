TOKEN=$(openssl rand -hex 32)

PGPASSWORD='StrongestPwd' psql \
  -h 127.0.0.1 \
  -U securetiles_user \
  -d securetiles \
  -v token="$TOKEN" <<'SQL'
INSERT INTO sessions (
    session_id_hash,
    user_id,
    expires_at
)
SELECT
    digest(:'token', 'sha256'),
    id,
    CURRENT_TIMESTAMP + INTERVAL '72 hours'
FROM users
WHERE email = 'dave@example.com'
RETURNING
    user_id,
    encode(session_id_hash, 'hex') AS session_hash,
    expires_at;
SQL

echo "Raw session token:"
echo "$TOKEN"
