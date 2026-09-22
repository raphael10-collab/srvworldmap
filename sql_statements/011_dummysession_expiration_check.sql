SELECT
    session_id,
    user_id,
    expires_at,
    revoked_at,
    NOW() AS database_time,
    expires_at > NOW() AS not_expired,
    revoked_at IS NULL AS not_revoked
FROM public.sessions
WHERE session_id =
'27f4fdee1b07606cc252e4223dead7de4bee2ee67d64e36580899f03f844e8b5';
