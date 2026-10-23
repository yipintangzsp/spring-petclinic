-- Additive only: no historical visits are replayed and no business rows are rewritten.
SET lock_timeout = '3s';
SET statement_timeout = '15s';
CREATE SCHEMA IF NOT EXISTS clinic_messaging;
CREATE TABLE IF NOT EXISTS clinic_messaging.jobs (
 event_id VARCHAR(128) PRIMARY KEY,
 idempotency_key VARCHAR(128) NOT NULL UNIQUE,
 kind VARCHAR(32) NOT NULL CHECK (kind IN ('visit_followup','statistics_report','release_deployed')),
 payload TEXT NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'queued',
 delivery_version INTEGER NOT NULL DEFAULT 1,
 confirmed_version INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0,
 cycle_attempt INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 result TEXT,
 last_error VARCHAR(120),
 CHECK (length(payload) <= 4096)
);
CREATE INDEX IF NOT EXISTS messaging_dispatch_due ON clinic_messaging.jobs (next_attempt_at) WHERE confirmed_version < delivery_version;
CREATE INDEX IF NOT EXISTS messaging_status_updated ON clinic_messaging.jobs (status, updated_at);
CREATE TABLE IF NOT EXISTS clinic_messaging.followups (
 event_id VARCHAR(128) PRIMARY KEY REFERENCES clinic_messaging.jobs(event_id),
 visit_id INTEGER NOT NULL UNIQUE, pet_id INTEGER NOT NULL, owner_id INTEGER NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'todo', created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 completed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS clinic_messaging.report_results (
 event_id VARCHAR(128) PRIMARY KEY REFERENCES clinic_messaging.jobs(event_id),
 window_start DATE NOT NULL, window_end DATE NOT NULL,
 owners BIGINT NOT NULL, pets BIGINT NOT NULL, vets BIGINT NOT NULL, visits BIGINT NOT NULL,
 generated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS clinic_messaging.release_audit (
 event_id VARCHAR(128) PRIMARY KEY REFERENCES clinic_messaging.jobs(event_id),
 release VARCHAR(80) NOT NULL, build INTEGER NOT NULL, source_commit VARCHAR(64) NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE OR REPLACE FUNCTION clinic_messaging.visit_followup_outbox() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, clinic_messaging AS $$
BEGIN
 INSERT INTO clinic_messaging.jobs (event_id,idempotency_key,kind,payload)
 SELECT 'visit-'||NEW.id,'visit-'||NEW.id,'visit_followup',
 json_build_object('visit_id',NEW.id,'pet_id',NEW.pet_id,'owner_id',p.owner_id)::text
 FROM public.pets p WHERE p.id=NEW.pet_id
 ON CONFLICT (idempotency_key) DO NOTHING;
 RETURN NEW;
END;
$$;
-- Recreate only this explicitly named trigger; existing triggers are untouched.
CREATE OR REPLACE TRIGGER petclinic_visit_followup_outbox AFTER INSERT ON public.visits
FOR EACH ROW EXECUTE FUNCTION clinic_messaging.visit_followup_outbox();
