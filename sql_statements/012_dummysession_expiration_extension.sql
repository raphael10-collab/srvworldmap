UPDATE public.sessions
SET expires_at = NOW() + INTERVAL '365 days',
    revoked_at = NULL
WHERE session_id_hash =
'\xe9443dfb9145053879c5a457ee7f714293823bacc32d4b9ba115b6bce9d77c84';
