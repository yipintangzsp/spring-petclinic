# RabbitMQ business integration

This connects real use cases, rather than publishing artificial health events for every installed component:

|Service path|Integration|
|---|---|
|PetClinic visits / PostgreSQL|An INSERT / pet-link UPDATE trigger writes a versioned outbox record in the visit transaction; no historical visits are replayed|
|RabbitMQ|Durable direct exchanges, three work queues and one dead-letter queue in vhost petclinic; persistent messages, mandatory routing, publisher confirms and manual ACK|
|clinic-message-worker|One serial consumer creates a manual follow-up task, calculates a bounded statistics report, or records a release audit|
|PetClinic Web|`/jobs` submits reports and displays queued/running/retrying/success/failed, attempts, UTC update time, results, follow-ups and release audit|
|Jenkins / GitLab / Harbor / Argo|Existing source/quality/image checks remain; an additive migration and immutable GitOps worker promotion precede application promotion. After successful rollout a real release event must be consumed and audited|
|Kafka / Airflow / Spark / Flink / Trino / Superset|Existing streams and analysis are preserved; reports here are small bounded PostgreSQL aggregates, not a replacement for the heavy analysis DAG|
|Prometheus / Grafana|Existing RabbitMQ native scraping plus application storage-availability, job-status and pending-outbox gauges|
|Filebeat / Elasticsearch / Loki|Worker structured stdout uses service, event_id, kind, attempt and action; existing collection paths remain|

A follow-up is an internal manual checklist. No SMS, email or external notifications are sent.

## Source and runtime

`schema.sql` is additive and versioned with the worker. PostgreSQL 18 supports the explicitly named trigger; the migration runs in one transaction with lock/statement timeouts. The existing application DB role receives SELECT/INSERT/UPDATE only on the new schema, not DDL. Public business data is not rewritten. Hibernate links pet_id after INSERT; the link UPDATE creates the outbox in that same transaction, once only. The trigger executes under a fixed search_path and records only IDs, not owner names, phone numbers or descriptions.

The worker reuses the previously validated pinned ARM64 Airflow Python runtime as a generic Python process; it does not start another Airflow installation. psycopg2 is already present. The pure Python Pika wheel is fetched over HTTPS and checked against `dependencies.json`, then stored as a named immutable ConfigMap. No startup pip install or floating image tag is used. Code comes from Kustomize's hashed ConfigMap generator, causing a controlled Recreate rollout on source changes.

Requests 50m/128Mi and limits 500m/256Mi, one replica, prefetch=1 and one serial callback. No Kubernetes API token is mounted. Egress is restricted to DNS, the existing PostgreSQL namespace/port and RabbitMQ. The separate `petclinic-app` RabbitMQ user has no management tags and permissions only on `clinic.*`; its random password lives in `petclinic/rabbitmq-client`. The requested admin management login remains unchanged.

## Delivery and recovery

Every job has an immutable event_id/idempotency_key, bounded JSON payload, delivery_version, confirmed_version, attempt counts and persistent result. The broker envelope includes schema_version=1, event_id, kind, occurred_at, delivery_version and payload. Queue names are `clinic.visit_followup.v1`, `clinic.statistics_report.v1`, `clinic.release_deployed.v1` and `clinic.dead.v1`. Exchanges are `clinic.events.v1` and `clinic.dead.v1`.

The outbox dispatcher holds a short row lock, publishes with confirms and only then updates confirmed_version. A confirm/DB-commit crash can duplicate a message, so consumers lock by event_id and ACK terminal/obsolete versions without repeating business effects. Handler effects and success commit together before ACK. A connection failure after DB commit never downgrades a successful job.

Business processing failures schedule the next outbox version in the same transaction as failure status; only then ACK the original. Retries are due after 5 and 10 seconds, at most three attempts per manual retry cycle. A terminal failure creates a confirmed outbox delivery to the dead-letter exchange. This retry delay lives in PostgreSQL, not a sleeping task Pod or an unbounded requeue loop. Invalid/unrecognized messages use RabbitMQ native NACK/dead-letter routing.

A worker/broker outage leaves jobs pending durably. Reconnect uses bounded socket/SQL timeouts and a five-second delay. Readiness reflects a recent successful loop; a running Pod is not proof of message progress. A manual retry increases delivery_version and resets the per-cycle count while preserving total attempts and dead-letter evidence. Fix the cause before retrying; dead-letter messages are not silently purged. Internal acceptance fault injection is available only through worker CLI/DB-owned test jobs, never through the public report form.

## CI order and evidence

1. Existing Node/Java tests plus the owned bounded Python unit Job. Its source/log/status is archived before removing only that Job/ConfigMap.
2. Package, SonarQube, GitLab audit, dual-architecture application build and Harbor scanning.
3. Verify the already provisioned application Secret, save existing messaging schema definition, apply additive migration/grants, and pin platform-messaging to the exact checked source SHA. Wait for Synced/Healthy and worker readiness.
4. Existing application Git promotion, Argo sync, rollout and health checks.
5. Publish a stable-id release through the worker CLI, wait for actual broker consumption/database audit, and retain `messaging-release.json`. Preserve the existing Kafka release event stage.

The stages reuse Jenkins' platform-heavy Lease and never acquire a nested lock or quiet Jenkins themselves. Failed migrations roll back transactionally; failed worker deployment does not delete tables/queues or erase earlier results. Existing stages and failure evidence remain visible. Database backup, rollback and the final end-to-end acceptance evidence must be reviewed before declaring rollout complete.

The Application template requires a validated source revision and is not applied directly with its placeholder. `pipeline.mjs deploy` supplies the checked `.git-sha`; future upgrades follow the same gate. Do not point it at unvalidated main. Broker topology is declared by the authorized worker; existing topics/queues outside clinic.* are untouched.

References: https://www.rabbitmq.com/client-libraries/publisher-confirms ; https://www.rabbitmq.com/docs/consumers ; https://www.postgresql.org/docs/current/sql-createtrigger.html
