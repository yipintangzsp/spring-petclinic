# PetClinic HA boundary

| Level | Status | Evidence and boundary |
|---|---|---|
| 1 Pod HA | Complete | Multiple Ready Pods, probes, rolling update and graceful shutdown; PDB protects voluntary eviction only. |
| 2 Application Node HA | Complete for tested worker maintenance; capacity constrained | Actual application execution on devops/aliyun/ucloud and scoped worker eviction are verified. N-1 capacity must be recalculated after workload changes. Node maintenance is not a physical devops outage. |
| 3 Ingress HA | Partial | Traefik routes to changing application endpoints; the tested client entry is 192.168.1.58 on devops. Multiple app Pods do not provide redundant external ingress. |
| 4 Database HA | Not complete | PostgreSQL 18.4 is a single Deployment on devops. All application replicas share it. A JDBC pool is not database replication. |
| 5 Control Plane HA | Not complete | devops is the single k3s server. Workers cannot replace its API/controller/etcd responsibilities. |
| 6 Storage HA | Not complete | PostgreSQL PVC is local-path, RWO, bound by PV node affinity to devops. Data is durable across a Pod restart only if the same storage survives; it is not replicated across nodes. |

PVC/PV deletion is forbidden in drills. The PV reclaim policy is Delete, so deleting the claim risks deleting the backing data. The PostgreSQL restart persistence test is deferred in this phase: an active Trino deployment has a catalog referencing the same server (currently a nonexistent `devops` database), and a `registry` database contains a separate persistence-test table. No shared database restart has been authorized after these dependencies were found. Private pg_dump archive readability does not prove a successful restore or Pod-recreation persistence test.

MySQL and mysql-replica remain separate database operations labs and are unchanged. Do not describe this platform as Full-stack HA.
