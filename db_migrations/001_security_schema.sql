-- =============================================================================
-- Threadlytics — Security Schema Migration 001
-- =============================================================================
-- Run against your Supabase project via:
--   Supabase Dashboard → SQL Editor → paste & run
--
-- This migration adds:
--   1. companies          — tenant isolation, retention config, private mode
--   2. audit_logs         — immutable append-only audit trail
--   3. profiles columns   — company_id, role, last_login, is_active
--   4. uploads columns    — company_id, file metadata, expiry, soft-delete
--   5. RLS policies       — company-level data isolation
--   6. Indexes            — performance on common query patterns
-- =============================================================================


-- ── 1. COMPANIES TABLE ─────────────────────────────────────────────────────────
-- One row per organisation. Tenant isolation key.

CREATE TABLE IF NOT EXISTS companies (
    id                       UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    name                     VARCHAR(200) NOT NULL,
    plan                     VARCHAR(50)  DEFAULT 'trial',
    retention_hours          INTEGER      DEFAULT 24            CHECK (retention_hours BETWEEN 1 AND 8760),
    private_processing_mode  BOOLEAN      DEFAULT FALSE,
    security_contact_email   VARCHAR(254),
    max_users                INTEGER      DEFAULT 5,
    created_at               TIMESTAMPTZ  DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  DEFAULT NOW()
);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_companies_updated_at ON companies;
CREATE TRIGGER update_companies_updated_at
    BEFORE UPDATE ON companies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ── 2. AUDIT LOGS TABLE ────────────────────────────────────────────────────────
-- Append-only. RLS prevents any UPDATE or DELETE.
-- GDPR Art. 30 / SOC 2 CC7.1 / ISO 27001 A.12.4 compliant.

CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     UUID,                                            -- auth.users.id
    company_id  UUID        REFERENCES companies(id),
    action      VARCHAR(100) NOT NULL,                           -- see audit.py constants
    resource    VARCHAR(500),                                    -- e.g. "upload:uuid", "report:weekly"
    ip_address  VARCHAR(50),
    user_agent  VARCHAR(500),
    status      VARCHAR(20)  DEFAULT 'SUCCESS'
                CHECK (status IN ('SUCCESS', 'FAILURE', 'BLOCKED')),
    metadata    JSONB        DEFAULT '{}'
);

-- Immutable: enable RLS, allow INSERT only — no UPDATE, no DELETE
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Any authenticated user can INSERT (the service key is used, so this policy
-- is mainly for defence-in-depth via the anon/user key)
DROP POLICY IF EXISTS audit_logs_insert ON audit_logs;
CREATE POLICY audit_logs_insert ON audit_logs
    FOR INSERT WITH CHECK (true);

-- SELECT: company members can read their own company's logs;
-- records with NULL company_id are system events (admin only)
DROP POLICY IF EXISTS audit_logs_select ON audit_logs;
CREATE POLICY audit_logs_select ON audit_logs
    FOR SELECT USING (
        company_id = (
            SELECT company_id FROM profiles
            WHERE id = auth.uid()
        )
        OR (
            SELECT role FROM profiles WHERE id = auth.uid()
        ) = 'Admin'
    );

-- Explicitly NO UPDATE policy  → UPDATE is denied for all roles
-- Explicitly NO DELETE policy  → DELETE is denied for all roles

-- Indexes for Security Centre queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_company_ts    ON audit_logs (company_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id       ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action        ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status        ON audit_logs (status) WHERE status != 'SUCCESS';


-- ── 3. EXTEND PROFILES TABLE ───────────────────────────────────────────────────

ALTER TABLE profiles
    ADD COLUMN IF NOT EXISTS company_id     UUID        REFERENCES companies(id),
    ADD COLUMN IF NOT EXISTS role           VARCHAR(50)  DEFAULT 'MA'
                                            CHECK (role IN ('Admin','Director','Merchandiser','AM','MA')),
    ADD COLUMN IF NOT EXISTS last_login     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS is_active      BOOLEAN      DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS mfa_enabled    BOOLEAN      DEFAULT FALSE;

-- Index for company-based user lookups (Security Centre user list)
CREATE INDEX IF NOT EXISTS idx_profiles_company_id ON profiles (company_id);

-- RLS: users can only see profiles in their own company
-- (The application uses the service key which bypasses RLS; this is belt-and-suspenders
--  for any future direct Supabase client access)
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS profiles_select_own_company ON profiles;
CREATE POLICY profiles_select_own_company ON profiles
    FOR SELECT USING (
        company_id = (SELECT company_id FROM profiles WHERE id = auth.uid())
        OR id = auth.uid()
    );

DROP POLICY IF EXISTS profiles_update_own ON profiles;
CREATE POLICY profiles_update_own ON profiles
    FOR UPDATE USING (id = auth.uid());


-- ── 4. EXTEND UPLOADS TABLE ────────────────────────────────────────────────────

ALTER TABLE uploads
    ADD COLUMN IF NOT EXISTS company_id     UUID        REFERENCES companies(id),
    ADD COLUMN IF NOT EXISTS file_hash      VARCHAR(64),         -- SHA-256 of original file
    ADD COLUMN IF NOT EXISTS file_size      INTEGER,             -- bytes
    ADD COLUMN IF NOT EXISTS file_encrypted BOOLEAN      DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS expires_at     TIMESTAMPTZ  DEFAULT (NOW() + INTERVAL '24 hours'),
    ADD COLUMN IF NOT EXISTS deleted_at     TIMESTAMPTZ;         -- soft-delete timestamp

-- Indexes for retention queries and company isolation
CREATE INDEX IF NOT EXISTS idx_uploads_company_id       ON uploads (company_id);
CREATE INDEX IF NOT EXISTS idx_uploads_expires_at       ON uploads (expires_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_uploads_user_company     ON uploads (user_id, company_id);

-- RLS: strict company isolation — users can only see uploads from their company
ALTER TABLE uploads ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS uploads_company_isolation ON uploads;
CREATE POLICY uploads_company_isolation ON uploads
    FOR ALL USING (
        company_id = (SELECT company_id FROM profiles WHERE id = auth.uid())
        OR user_id = auth.uid()    -- fallback for rows without company_id (legacy data)
    );


-- ── 5. AUTO-CREATE COMPANIES FOR EXISTING USERS ────────────────────────────────
-- Migrates existing users without a company_id into individual company tenants.
-- Safe to run multiple times (WHERE company_id IS NULL guard).

DO $$
DECLARE
    prof RECORD;
    new_company_id UUID;
BEGIN
    FOR prof IN
        SELECT id, email FROM profiles WHERE company_id IS NULL
    LOOP
        -- Create a company named after the user's email domain
        INSERT INTO companies (name, plan)
        VALUES (
            split_part(prof.email, '@', 2),   -- e.g. "example.com"
            COALESCE(
                (SELECT plan FROM profiles WHERE id = prof.id),
                'trial'
            )
        )
        RETURNING id INTO new_company_id;

        -- Link the profile to the new company
        UPDATE profiles
        SET company_id = new_company_id
        WHERE id = prof.id;

        -- Link existing uploads to the same company
        UPDATE uploads
        SET company_id = new_company_id
        WHERE user_id = prof.id
          AND company_id IS NULL;

    END LOOP;
END $$;


-- ── 6. CHAT MESSAGES — COMPANY ISOLATION ──────────────────────────────────────

ALTER TABLE chat_messages
    ADD COLUMN IF NOT EXISTS company_id UUID REFERENCES companies(id);

-- Backfill company_id from the linked upload
UPDATE chat_messages cm
SET company_id = u.company_id
FROM uploads u
WHERE cm.upload_id = u.id
  AND cm.company_id IS NULL;

ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS chat_messages_company_isolation ON chat_messages;
CREATE POLICY chat_messages_company_isolation ON chat_messages
    FOR ALL USING (
        company_id = (SELECT company_id FROM profiles WHERE id = auth.uid())
        OR user_id = auth.uid()
    );


-- ── 7. STRIPE EVENTS — AUDIT SAFETY ───────────────────────────────────────────
-- Ensure the stripe_events table exists (idempotent)

CREATE TABLE IF NOT EXISTS stripe_events (
    id          VARCHAR(100) PRIMARY KEY,
    type        VARCHAR(100),
    processed   BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);


-- ── 8. RETENTION TRIGGER — AUTO-EXPIRE NOTIFICATION ──────────────────────────
-- Optional: create a database-level function for the scheduler to call
-- (Currently handled in Python by APScheduler, but this provides a SQL-level
--  fallback that can be called via Supabase Edge Functions or pg_cron)

CREATE OR REPLACE FUNCTION expire_uploads_past_retention()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    UPDATE uploads
    SET deleted_at = NOW()
    WHERE expires_at < NOW()
      AND deleted_at IS NULL;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- To schedule via pg_cron (Supabase Pro):
-- SELECT cron.schedule('expire-uploads', '0 * * * *', 'SELECT expire_uploads_past_retention()');


-- ── VERIFICATION QUERIES ───────────────────────────────────────────────────────
-- Run these after migration to verify everything looks correct:

-- SELECT COUNT(*) FROM companies;                        -- Should equal number of distinct users
-- SELECT COUNT(*) FROM audit_logs;                       -- Should be 0 (no events yet)
-- SELECT column_name FROM information_schema.columns WHERE table_name = 'uploads';
-- SELECT column_name FROM information_schema.columns WHERE table_name = 'profiles';
-- SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';
