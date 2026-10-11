-- Additive schema only. Never changes or initializes public business tables.
CREATE SCHEMA IF NOT EXISTS petclinic_analytics;
CREATE TABLE IF NOT EXISTS petclinic_analytics.runs (
  run_id TEXT PRIMARY KEY,
  generated_at TIMESTAMPTZ NOT NULL,
  window_start DATE NOT NULL,
  window_end DATE NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('demo', 'business')),
  owners BIGINT NOT NULL CHECK (owners >= 0),
  pets BIGINT NOT NULL CHECK (pets >= 0),
  vets BIGINT NOT NULL CHECK (vets >= 0),
  visits BIGINT NOT NULL CHECK (visits >= 0),
  watermark BIGINT NOT NULL,
  input_rows INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('success'))
);
CREATE TABLE IF NOT EXISTS petclinic_analytics.visit_facts (
  visit_id BIGINT PRIMARY KEY,
  visit_date DATE NOT NULL,
  pet_id BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS petclinic_analytics.daily_visits (
  run_id TEXT NOT NULL REFERENCES petclinic_analytics.runs(run_id),
  stat_date DATE NOT NULL,
  visits BIGINT NOT NULL CHECK (visits >= 0),
  PRIMARY KEY (run_id, stat_date)
);
CREATE TABLE IF NOT EXISTS petclinic_analytics.pet_types (
  run_id TEXT NOT NULL REFERENCES petclinic_analytics.runs(run_id),
  type TEXT NOT NULL,
  pets BIGINT NOT NULL CHECK (pets >= 0),
  PRIMARY KEY (run_id, type)
);
CREATE INDEX IF NOT EXISTS runs_generated_at ON petclinic_analytics.runs (generated_at DESC);
