# RabbitMQ learning service

Single ARM64 RabbitMQ 4.2.9 management instance in `data-infra`, independently reconciled by Argo Application `platform-rabbitmq`. This service complements Kafka for work queues and acknowledgements. PetClinic application traffic is not redirected to this broker.

## Installation gate

Publish this source to private GitLab and pass the existing complete Jenkins pipeline before bootstrapping `infra/devops-lab/applications/platform-rabbitmq.json`. Create `rabbitmq-auth` out of band with random `username` and `password`; never commit it. Generated credentials bootstrap only an empty data directory. Later password changes must use RabbitMQ user management and update the Secret together.

The upstream multiarch index and selected ARM64 child are in `image-lock.json`. The local registry copy preserves the child digest. No new cluster operator or Erlang distribution ports are exposed. Stable DNS nodename and 2Gi local-path PVC retain state across Pod replacements. PVC retention is Retain on scale/delete; namespace/PVC deletion is destructive and requires separate authorization. Local-path's requested capacity is not a filesystem quota, so use bounded queues and monitor actual host storage.

## Access and operations

Management host: `rabbitmq.devops.local` through existing Traefik (HTTP LAN endpoint). Add `192.168.1.58 rabbitmq.devops.local` to the client's existing hosts configuration when no matching DNS record exists. AMQP is internal at `rabbitmq.data-infra.svc.cluster.local:5672`, vhost `petclinic`. For local clients use an SSH tunnel:

```sh
ssh -t -L 15672:127.0.0.1:15672 -L 5672:127.0.0.1:5672 zhang@192.168.1.58 'sudo kubectl -n data-infra port-forward svc/rabbitmq 15672:15672 5672:5672'
```

Read login credentials explicitly on the trusted terminal (do not paste them into tickets):

```sh
ssh zhang@192.168.1.58 'sudo kubectl -n data-infra get secret rabbitmq-auth -o jsonpath="{.data.username}"' | base64 -d
ssh zhang@192.168.1.58 'sudo kubectl -n data-infra get secret rabbitmq-auth -o jsonpath="{.data.password}"' | base64 -d
```

Requests 100m CPU/256Mi, limits 500m/768Mi; Erlang schedulers 2, async threads 4, absolute memory alarm 384MiB and disk alarm 1GB. Message size is bounded at 1MiB. Set the retained operator policy on vhost `petclinic` from `queue-policy.json`: at most 10000 ready messages/64MiB per classic queue, reject-publish when full. This policy bounds queue backlog rather than silently discarding messages. Applications still need publisher confirms, consumer acknowledgements, bounded retries and idempotency.

Prometheus scrapes the native plugin every 30 seconds via ServiceMonitor; alerts cover unavailable endpoint and memory/disk alarms. Inspect Argo sync, `kubectl -n data-infra describe pod rabbitmq-0`, `logs rabbitmq-0 --tail=200`, `rabbitmq-diagnostics check_running`, `check_local_alarms`, and queue ready/unacknowledged counts. Do not delete the PVC to fix an authentication or startup error.

To stop while retaining data, commit replicas=0 to this StatefulSet through private GitLab; to resume set replicas=1. Manual scale alone is reverted by Argo self-healing. Existing shared heavy-task admission counts this service's resource requests; never lower platform stop thresholds to fit another task. Single-node local storage provides no node-failure HA.

Acceptance evidence will record real AMQP confirms, ACK/NACK/dead-letter delivery, persistence through a Pod replacement, Prometheus target and resource samples. Read the dated acceptance record before claiming this service is validated.

References: https://www.rabbitmq.com/docs/4.2/prometheus ; https://www.rabbitmq.com/docs/4.2/memory ; https://www.rabbitmq.com/docs/confirms
