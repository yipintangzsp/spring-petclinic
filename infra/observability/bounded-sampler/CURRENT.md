# Current offline candidate entrypoint

Use **`sampler_mach_time.py`**, not `sampler.py`, as the reviewed executable entrypoint.

The first sealed candidate (`sampler.py` / README.md and its 43-case evidence) is
preserved byte-for-byte. Its Darwin `proc_pid_rusage` CPU conversion was incomplete
on ARM64: raw Mach absolute time was divided by 1e9 without the timebase conversion.
Worker cost measurements from wait4 were unaffected. No production capture used it.

`sampler_mach_time.py` adds a narrow Darwin backend extension that applies the
read-only `mach_timebase_info` ratio. Linux /proc parsing, pressure thresholds,
PID/output/wall/CPU/RSS limits, clocks and supervisor behavior stay frozen. This is
an offline candidate, not an installed component or production transport.

```sh
# Only within a separately authorized NON-PRODUCTION Linux execution context:
python3 -B sampler_mach_time.py --role guest --source-id linux-sandbox --pids self
# Local Darwin native self-PID validation, never a production Linux probe:
python3 -B sampler_mach_time.py --role host --source-id offline-host --pids self
```

The corrected 45-case suite is `test_current.py`, executed only in a new no-network,
write-restricted temporary copy. Results: **44 PASS / 1 SKIP**. The skip is native
Linux, which remains unverified. All earlier attempts are retained. Current
source hashes and native CPU-unit cross-check are in:

`evidence/2026-11-05/host-guest-offline-preparation-timebase/`

Its FINAL-REPORT.md and verdict.json supersede earlier completion claims for this
round. Original budget/protocol design in README.md remains applicable, except the
entrypoint and the additional CPU unit proof. Do not run the earlier tests as a
production command or treat the previous CPU output as correctly scaled.

Still NOT_TESTED: production overhead, real synchronized Host/Guest capture, native
Linux performance, actual SSH timeout/remote cleanup. Source-ID labels are not
machine attestation. Production transport remains disabled; no background service.
