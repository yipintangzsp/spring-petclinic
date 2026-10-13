-- Input is an explicitly scoped replay of the existing bounded database snapshot,
-- not CDC or a second source of clinical truth. Processing-time windows describe
-- replay processing; visit_date remains the original business dimension.
SET 'execution.runtime-mode' = 'streaming';
SET 'parallelism.default' = '1';
SET 'execution.checkpointing.interval' = '5 s';
SET 'execution.checkpointing.mode' = 'EXACTLY_ONCE';
SET 'execution.checkpointing.timeout' = '60 s';
SET 'execution.checkpointing.min-pause' = '2 s';
SET 'execution.checkpointing.externalized-checkpoint-retention' = 'RETAIN_ON_CANCELLATION';
SET 'state.checkpoints.dir' = 'file:///opt/clinic-state/checkpoints';
SET 'state.savepoints.dir' = 'file:///opt/clinic-state/savepoints';
SET 'table.exec.source.idle-timeout' = '10 s';
SET 'pipeline.name' = 'Petclinic bounded snapshot window acceptance';
SET 'table.exec.uid.generation' = 'ALWAYS';
CREATE TABLE clinic_events (
 snapshot_id STRING,
 visit_id BIGINT,
 visit_date DATE,
 processing_time AS PROCTIME()
) WITH (
 'connector'='kafka',
 'topic'='petclinic-snapshot-20261011',
 'properties.bootstrap.servers'='kafka.ns-bigdata.svc.cluster.local:9092',
 'properties.group.id'='petclinic-flink-20261011',
 'scan.startup.mode'='group-offsets',
 'properties.auto.offset.reset'='latest',
 'format'='json',
 'json.fail-on-missing-field'='true',
 'json.ignore-parse-errors'='false'
);
CREATE TABLE clinic_windows (
 snapshot_id STRING,
 visit_date DATE,
 window_start TIMESTAMP(3),
 window_end TIMESTAMP(3),
 visits BIGINT,
 PRIMARY KEY (snapshot_id,visit_date) NOT ENFORCED
) WITH (
 'connector'='kafka',
 'topic'='petclinic-windows-20261011',
 'properties.bootstrap.servers'='kafka.ns-bigdata.svc.cluster.local:9092',
 'properties.transaction.timeout.ms'='60000',
 'key.format'='json',
 'key.fields'='snapshot_id;visit_date',
 'value.fields-include'='ALL',
 'value.format'='json',
 'sink.delivery-guarantee'='exactly-once',
 'sink.transactional-id-prefix'='petclinic-windows-20261011-'
);
CREATE TEMPORARY VIEW clinic_events_deduplicated AS
 SELECT snapshot_id,visit_id,visit_date,processing_time
 FROM (
  SELECT *,ROW_NUMBER() OVER (PARTITION BY snapshot_id,visit_id ORDER BY processing_time) AS row_num
  FROM clinic_events
 ) WHERE row_num=1;
INSERT INTO clinic_windows
 SELECT snapshot_id,visit_date,
  TO_TIMESTAMP(CAST(visit_date AS STRING)),
  TO_TIMESTAMP(CAST(visit_date + INTERVAL '1' DAY AS STRING)),COUNT(*)
 FROM clinic_events_deduplicated
 GROUP BY snapshot_id,visit_date;
