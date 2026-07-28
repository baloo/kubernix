CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    derivation_path TEXT NOT NULL,
    system TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    outputs TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cache_objects (
    key TEXT PRIMARY KEY,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
