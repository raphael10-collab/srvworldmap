SELECT
    pid,
    usename,
    client_addr,
    client_port,
    datname,
    state,
    wait_event_type,
    wait_event,
    query_start,
    now() - query_start AS duration,
    query
FROM pg_stat_activity
WHERE datname = 'securetiles'
ORDER BY query_start;
