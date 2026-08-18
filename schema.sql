-- VirtualPrime database schema
-- Mirrors the former localStorage keys:
--   ve_users -> users, ve_partners -> partners, ve_pushed -> pushed_picks,
--   ve_purchases -> purchases, ve_results -> results, ve_credits -> credits,
--   ve_payment_config -> payment_config

CREATE TABLE IF NOT EXISTS users (
  email          TEXT PRIMARY KEY,
  name           TEXT NOT NULL DEFAULT '',
  pw_hash        TEXT NOT NULL,
  plan           TEXT,
  plan_end       BIGINT,                       -- epoch ms, matches old planEnd
  ref            TEXT,                          -- referral code captured at signup
  partner        TEXT,                          -- partner code this member is attributed to
  sporty_account TEXT,                          -- linked SportyBet account number
  unlimited_until BIGINT,                        -- epoch ms; unlimited predictions while now < this
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- add the columns on existing databases too (idempotent)
ALTER TABLE users ADD COLUMN IF NOT EXISTS sporty_account TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS unlimited_until BIGINT;
-- one-time GHS 50 registration fee (added 2026-08-11); accounts created
-- before then are grandfathered in as paid
ALTER TABLE users ADD COLUMN IF NOT EXISTS reg_fee_paid BOOLEAN NOT NULL DEFAULT false;
UPDATE users SET reg_fee_paid = true WHERE reg_fee_paid = false AND created_at < TIMESTAMPTZ '2026-08-11 00:00:00+00';


CREATE TABLE IF NOT EXISTS partners (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL DEFAULT '',
  email       TEXT UNIQUE NOT NULL,
  pw_hash     TEXT NOT NULL,
  code        TEXT UNIQUE NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
  locked      BOOLEAN NOT NULL DEFAULT false,
  commission  NUMERIC NOT NULL DEFAULT 10,       -- % of referred revenue the partner earns
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at TIMESTAMPTZ,
  locked_at   TIMESTAMPTZ
);
ALTER TABLE partners ADD COLUMN IF NOT EXISTS commission NUMERIC NOT NULL DEFAULT 10;
-- partner's own revenue counter reset point (display only; purchases stay stored)
ALTER TABLE partners ADD COLUMN IF NOT EXISTS revenue_cleared_at TIMESTAMPTZ;
-- add foreign key constraint and index for partner relationship (after partners table exists)
CREATE INDEX IF NOT EXISTS idx_users_partner ON users(partner);
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'fk_users_partner') THEN
    ALTER TABLE users ADD CONSTRAINT fk_users_partner FOREIGN KEY (partner) REFERENCES partners(code) ON DELETE SET NULL;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS pushed_picks (
  id            SERIAL PRIMARY KEY,
  member_email  TEXT NOT NULL,
  home          TEXT NOT NULL,
  away          TEXT NOT NULL,
  outcome       TEXT NOT NULL,               -- 'home' | 'draw' | 'away'
  label         TEXT NOT NULL,
  odds          NUMERIC,
  from_code     TEXT,                         -- partner code or 'ADMIN'
  from_name     TEXT,
  used          BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pushed_member ON pushed_picks(member_email);
CREATE INDEX IF NOT EXISTS idx_pushed_from   ON pushed_picks(from_code);

CREATE TABLE IF NOT EXISTS purchases (
  id           SERIAL PRIMARY KEY,
  email        TEXT NOT NULL,
  pkg          TEXT,                          -- package label e.g. "GHS 500"
  reference    TEXT,                          -- payment reference
  predictions  INTEGER NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_purchases_email ON purchases(email);

CREATE TABLE IF NOT EXISTS results (
  id           SERIAL PRIMARY KEY,
  email        TEXT,
  data         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credits (
  email     TEXT PRIMARY KEY,
  amount    INTEGER NOT NULL DEFAULT 0,   -- Instant Football credits
  rb_amount INTEGER NOT NULL DEFAULT 0    -- Red & Black credits (separate pool)
);
ALTER TABLE credits ADD COLUMN IF NOT EXISTS rb_amount INTEGER NOT NULL DEFAULT 0;

-- Tracks screenshot-scan usage so the admin knows when to top up API credits.
CREATE TABLE IF NOT EXISTS scan_meter (
  id        INTEGER PRIMARY KEY DEFAULT 1,
  used      BIGINT NOT NULL DEFAULT 0,   -- total scans performed (info)
  remaining BIGINT NOT NULL DEFAULT 0,   -- scans left; admin tops this up
  CONSTRAINT scan_singleton CHECK (id = 1)
);
INSERT INTO scan_meter (id, used, remaining) VALUES (1, 8, 953) ON CONFLICT (id) DO UPDATE SET used=8, remaining=953;

-- Security alerts surfaced in the admin panel (e.g. unverified purchase attempts).
CREATE TABLE IF NOT EXISTS security_alerts (
  id         SERIAL PRIMARY KEY,
  email      TEXT,
  kind       TEXT,
  detail     TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts(created_at DESC);

-- Editable GHS → local exchange rates (display-only on the packages page).
CREATE TABLE IF NOT EXISTS fx_rates (
  code TEXT PRIMARY KEY,
  rate NUMERIC NOT NULL
);
INSERT INTO fx_rates (code, rate) VALUES
  ('NGN', 140), ('KES', 12.5), ('TZS', 240), ('ZMW', 2.5), ('ZAR', 1.8)
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS payment_config (
  id          INTEGER PRIMARY KEY DEFAULT 1,
  provider    TEXT DEFAULT 'paystack',
  currency    TEXT DEFAULT 'GHS',
  public_key  TEXT DEFAULT '',
  secret_key  TEXT DEFAULT '',
  business    TEXT DEFAULT 'VirtualPrime',
  momo_number  TEXT DEFAULT '',
  momo_name    TEXT DEFAULT '',
  momo_network TEXT DEFAULT '',
  momo_accounts JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{network,number,name}, …]
  CONSTRAINT singleton CHECK (id = 1)
);
INSERT INTO payment_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
-- rebrand: migrate the stored display name (idempotent)
UPDATE payment_config SET business = 'VirtualPrime' WHERE business = 'Virtual Oracle';
-- direct-MoMo fields on existing databases too (idempotent)
ALTER TABLE payment_config ADD COLUMN IF NOT EXISTS momo_number  TEXT DEFAULT '';
ALTER TABLE payment_config ADD COLUMN IF NOT EXISTS momo_name    TEXT DEFAULT '';
ALTER TABLE payment_config ADD COLUMN IF NOT EXISTS momo_network TEXT DEFAULT '';
ALTER TABLE payment_config ADD COLUMN IF NOT EXISTS momo_accounts JSONB NOT NULL DEFAULT '[]'::jsonb;
-- Per-method config: {paystack:{enabled,key,secret}, flutterwave:{...}, cowrie:{...}, manual:{enabled}, bank:{enabled}}
-- Empty object = not migrated yet; server derives it from the legacy single-provider columns.
ALTER TABLE payment_config ADD COLUMN IF NOT EXISTS providers JSONB NOT NULL DEFAULT '{}'::jsonb;
-- Direct bank-transfer receiving accounts: [{bank,number,name}, …]
ALTER TABLE payment_config ADD COLUMN IF NOT EXISTS bank_accounts JSONB NOT NULL DEFAULT '[]'::jsonb;
-- admin revenue counter reset point (display only; purchases stay stored)
ALTER TABLE payment_config ADD COLUMN IF NOT EXISTS revenue_cleared_at TIMESTAMPTZ;

-- Direct mobile-money payments (provider = 'manual'): the buyer sends money
-- straight to the admin's MoMo number, then submits the transaction ID here.
-- Credits are granted ONLY when the admin approves the claim.
CREATE TABLE IF NOT EXISTS manual_claims (
  id         SERIAL PRIMARY KEY,
  email      TEXT NOT NULL,
  pkg        TEXT,                              -- package label e.g. "GHS 385"
  credits    INTEGER NOT NULL DEFAULT 0,        -- 9999 = 24h unlimited
  amount     TEXT,                              -- what the buyer was told to send
  txid       TEXT NOT NULL,                     -- MoMo transaction ID / bank transfer reference
  proof      TEXT,                              -- receipt screenshot (data:image URL; required for bank)
  status     TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_claims_status ON manual_claims(status);
ALTER TABLE manual_claims ADD COLUMN IF NOT EXISTS proof TEXT;
