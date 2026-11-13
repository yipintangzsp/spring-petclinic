# Opt-in synthetic capacity dataset

`demo-seed.sql` adds 189 owners, 337 pets, 14 vets and 1195 visits to the verified base dataset (11/13/6/5), producing 200/350/20/1200 rows. IDs 1000001+ and Demo-prefixed names identify synthetic records. Existing types/specialties provide valid foreign keys. An advisory lock and transactional version marker make repeated execution a no-op; occupied reserved IDs cause an abort. Identity sequences for normal CRUD remain unchanged.

Run only in an explicitly authorized demo environment after a private `pg_dump -Fc` backup and row fingerprints. The seed never runs during application startup:

```sh
kubectl exec -i -n ns-data deploy/postgresql -- \
  psql -X -v ON_ERROR_STOP=1 -v demo_enabled=on -U postgres -d petclinic < infra/data/demo-seed.sql
```

Omitting the flag or setting it to off disables the seed. Re-running does not repair or overwrite edited demo rows. Do not delete PVCs, reset the database, or restore over a live shared instance. For data rollback, first inspect demo references and arrange a reviewed, scoped transaction; the backup is not permission to overwrite later business changes. No credentials or database dumps belong in Git.

`audit-postgres.py OUTPUT.json` records topology, row fingerprints, constraints, plans and connections without printing personal records or Secret values. PostgreSQL is also referenced by Trino; restarting it requires resolving that shared dependency first.
