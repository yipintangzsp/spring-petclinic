// Run the production delta/upsert SQL against transaction-local fixtures only.
export function reconciliationSql(source) {
 const delta=source.match(/cur\.execute\('''(SELECT v\.id,v\.visit_date,v\.pet_id,[\s\S]*?LEFT JOIN petclinic_analytics\.visit_facts[\s\S]*?)''', \(MAX_ROWS \+ 1,\)\)/)?.[1];
 const upsert=source.match(/execute_values\(cur, '''(INSERT INTO petclinic_analytics\.visit_facts[\s\S]*?)''',/)?.[1];
 if(!delta||!upsert)throw Error('Production visit reconciliation SQL was not found');
 const fixture=sql=>sql.replaceAll('public.visits','pg_temp.source_visits').replaceAll('public.pets','pg_temp.source_pets').replaceAll('petclinic_analytics.visit_facts','pg_temp.facts');
 const select=fixture(delta).replace('%s','100');
 const insert=fixture(upsert).replace('%s',"(8,DATE '2026-06-05',1),(100,DATE '2026-07-09',1)");
 return `BEGIN;
CREATE TEMP TABLE source_pets(id BIGINT PRIMARY KEY);
CREATE TEMP TABLE source_visits(id BIGINT PRIMARY KEY,visit_date DATE,pet_id BIGINT);
CREATE TEMP TABLE facts(visit_id BIGINT PRIMARY KEY,visit_date DATE NOT NULL,pet_id BIGINT NOT NULL);
INSERT INTO source_pets VALUES(1);
INSERT INTO source_visits VALUES(8,'2026-06-05',1),(100,'2026-07-09',1);
INSERT INTO facts VALUES(100,'2025-01-01',1);
CREATE TEMP TABLE delta_before AS ${select};
DO $$ BEGIN
 IF (SELECT array_agg(id ORDER BY id) FROM delta_before) IS DISTINCT FROM ARRAY[8,100]::BIGINT[] THEN
  RAISE EXCEPTION 'Late ID below watermark or corrected visit was missed'; END IF;
END $$;
${insert};
${insert};
CREATE TEMP TABLE delta_after AS ${select};
DO $$ BEGIN
 IF (SELECT count(*) FROM facts)<>2 OR (SELECT count(*) FROM facts WHERE visit_date BETWEEN '2026-01-01' AND '2026-12-31')<>2 OR EXISTS(SELECT 1 FROM delta_after) THEN
  RAISE EXCEPTION 'Reconciliation failed correction or idempotent replay'; END IF;
END $$;
ROLLBACK;
`;
}
