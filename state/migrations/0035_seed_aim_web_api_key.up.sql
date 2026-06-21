-- Default dev key used by the mirrored AIM Web client (k=ao1yOLlHVHhsa3o6).
INSERT OR IGNORE INTO web_api_keys (
    dev_id,
    dev_key,
    app_name,
    created_at,
    is_active,
    rate_limit,
    allowed_origins,
    capabilities
) VALUES (
    'aim_web',
    'ao1yOLlHVHhsa3o6',
    'AIM Web Client',
    strftime('%s', 'now'),
    1,
    600,
    '["http://localhost","https://localhost","http://localhost:8000","https://localhost:8000","http://127.0.0.1:8000","https://127.0.0.1:8000"]',
    '[]'
);
