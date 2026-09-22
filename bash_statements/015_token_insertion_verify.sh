psql -h 127.0.0.1 -U securetiles_user -d securetiles -W -c \
"SELECT
    s.user_id,
    u.email,
    encode(s.session_id_hash, 'hex') AS session_hash,
    s.expires_at,
    s.revoked_at
 FROM sessions s
 JOIN users u ON u.id = s.user_id
 WHERE u.email = 'dave@example.com'
 ORDER BY s.expires_at DESC;"
