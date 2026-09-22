psql -h 127.0.0.1 -U securetiles_user -d securetiles -W <<'SQL'
SELECT has_table_privilege(current_user, 'public.sessions', 'SELECT,INSERT,UPDATE,DELETE');
SELECT has_table_privilege(current_user, 'public.users', 'SELECT');
SQL
