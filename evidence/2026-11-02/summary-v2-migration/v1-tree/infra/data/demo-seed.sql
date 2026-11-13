\set ON_ERROR_STOP on
-- Opt-in only: psql -v demo_enabled=on -f demo-seed.sql. Never an app bootstrap script.
\if :{?demo_enabled}
\else
  \echo 'Set demo_enabled=on explicitly to seed synthetic data.'
  \quit
\endif
\if :demo_enabled
\else
  \echo 'Demo seeding disabled.'
  \quit
\endif
BEGIN;
SELECT pg_advisory_xact_lock(20261006);
CREATE SCHEMA IF NOT EXISTS petclinic_demo;
CREATE TABLE IF NOT EXISTS petclinic_demo.seed (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM petclinic_demo.seed WHERE version='capacity-v1') THEN
  IF EXISTS(SELECT 1 FROM owners WHERE id BETWEEN 1000001 AND 1000189)
   OR EXISTS(SELECT 1 FROM pets WHERE id BETWEEN 1000001 AND 1000337)
   OR EXISTS(SELECT 1 FROM vets WHERE id BETWEEN 1000001 AND 1000014)
   OR EXISTS(SELECT 1 FROM visits WHERE id BETWEEN 1000001 AND 1001195) THEN
    RAISE EXCEPTION 'Reserved IDs occupied; abort rather than overwrite existing business data';
  END IF;
  IF (SELECT count(*) FROM types) = 0 OR (SELECT count(*) FROM specialties) = 0 THEN
    RAISE EXCEPTION 'Base types and specialties must exist';
  END IF;
  INSERT INTO owners(id,first_name,last_name,address,city,telephone)
    SELECT 1000000+n,'Demo','Owner'||lpad(n::text,3,'0'),'Demo street '||n,
      'DemoDistrict'||(n%5), '555010'||lpad(n::text,4,'0') FROM generate_series(1,189) n;
  INSERT INTO pets(id,name,birth_date,type_id,owner_id)
    SELECT 1000000+n,'DemoPet'||lpad(n::text,3,'0'),date '2020-01-01'+(n%1700),
      (SELECT id FROM types ORDER BY id OFFSET ((n-1)%(SELECT count(*) FROM types)) LIMIT 1),
      1000001+((n-1)%189) FROM generate_series(1,337) n;
  INSERT INTO vets(id,first_name,last_name)
    SELECT 1000000+n,'Demo','Vet'||lpad(n::text,2,'0') FROM generate_series(1,14) n;
  INSERT INTO vet_specialties(vet_id,specialty_id)
    SELECT 1000000+n,(SELECT id FROM specialties ORDER BY id OFFSET ((n-1)%(SELECT count(*) FROM specialties)) LIMIT 1)
      FROM generate_series(1,14) n;
  INSERT INTO visits(id,pet_id,visit_date,description)
    SELECT 1000000+n,1000001+((n-1)%337),date '2026-10-01'-(n%365),
      CASE n%4 WHEN 0 THEN 'Demo annual wellness examination' WHEN 1 THEN 'Demo vaccination follow-up'
       WHEN 2 THEN 'Demo dental examination' ELSE 'Demo nutrition consultation' END FROM generate_series(1,1195) n;
  INSERT INTO petclinic_demo.seed(version) VALUES('capacity-v1');
 END IF;
END $$;
COMMIT;
SELECT 'owners',count(*) FROM owners UNION ALL SELECT 'pets',count(*) FROM pets
 UNION ALL SELECT 'vets',count(*) FROM vets UNION ALL SELECT 'visits',count(*) FROM visits;
