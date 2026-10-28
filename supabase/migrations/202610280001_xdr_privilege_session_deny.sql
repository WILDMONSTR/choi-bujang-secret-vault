-- Apply to the same Supabase project as SUPABASE_URL.
CREATE TABLE IF NOT EXISTS public.xdr_privilege_session_rules (
  subject_id text PRIMARY KEY CHECK (subject_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  rule_id text NOT NULL CHECK (rule_id LIKE 'xdr-privilege-%'),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  evidence_alert_ids text[] NOT NULL CHECK (cardinality(evidence_alert_ids) > 0),
  evidence_pattern text NOT NULL,
  confidence numeric(4,3) NOT NULL CHECK (confidence >= 0.85 AND confidence <= 1),
  CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS xdr_privilege_session_rules_expiry_idx
  ON public.xdr_privilege_session_rules (expires_at);
ALTER TABLE public.xdr_privilege_session_rules ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.xdr_privilege_session_rules FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.xdr_privilege_session_rules TO service_role;
