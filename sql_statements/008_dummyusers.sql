INSERT INTO public.users (
    id,
    can_view_restricted_map,
    email,
    password_hash
)
VALUES
    (1, false, 'alice@example.com',
     '$2b$12$LQv3c1yqBWmVj7dQ2xQ0eOe5pZ3n8n0fYjK8x7w6v5u4t3s2r1q0O'),
    (2, true, 'bob@example.com',
     '$2b$12$LQv3c1yqBWmVj7dQ2xQ0eOe5pZ3n8n0fYjK8x7w6v5u4t3s2r1q0O'),
    (3, false, 'carol@example.com',
     '$2b$12$LQv3c1yqBWmVj7dQ2xQ0eOe5pZ3n8n0fYjK8x7w6v5u4t3s2r1q0O'),
    (4, true, 'dave@example.com',
     '$2b$12$LQv3c1yqBWmVj7dQ2xQ0eOe5pZ3n8n0fYjK8x7w6v5u4t3s2r1q0O')
ON CONFLICT (id) DO NOTHING;
