-- ============================================================
-- Site Guardian API — Supabase Schema
-- Run this in: Supabase Dashboard > SQL Editor
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- TABLE 1: users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- TABLE 2: domains
-- ============================================================
CREATE TABLE IF NOT EXISTS domains (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain              TEXT NOT NULL,
  is_verified         BOOLEAN DEFAULT false,
  verification_token  TEXT,
  verification_method TEXT,
  created_at          TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- TABLE 3: scans
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  findings    JSONB,
  risk_score  TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- TABLE 4: notifications
-- ============================================================
CREATE TABLE IF NOT EXISTS notifications (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message    TEXT NOT NULL,
  is_read    BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================

-- Enable RLS on all tables
ALTER TABLE users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE domains       ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans         ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- ── users ────────────────────────────────────────────────────
-- Users can only read and update their own row
CREATE POLICY "users: select own"
  ON users FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "users: update own"
  ON users FOR UPDATE
  USING (auth.uid() = id);

-- ── domains ──────────────────────────────────────────────────
CREATE POLICY "domains: select own"
  ON domains FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "domains: insert own"
  ON domains FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "domains: update own"
  ON domains FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "domains: delete own"
  ON domains FOR DELETE
  USING (auth.uid() = user_id);

-- ── scans ─────────────────────────────────────────────────────
CREATE POLICY "scans: select own"
  ON scans FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "scans: insert own"
  ON scans FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "scans: delete own"
  ON scans FOR DELETE
  USING (auth.uid() = user_id);

-- ── notifications ─────────────────────────────────────────────
CREATE POLICY "notifications: select own"
  ON notifications FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "notifications: update own"
  ON notifications FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "notifications: delete own"
  ON notifications FOR DELETE
  USING (auth.uid() = user_id);
