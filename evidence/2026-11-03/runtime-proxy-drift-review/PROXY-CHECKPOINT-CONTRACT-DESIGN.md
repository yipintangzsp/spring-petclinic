# Proxy checkpoint contract review — DESIGN ONLY

No implementation, live proxy configuration or authoritative checkpoint is changed.
Historical drift remains UNEXPLAINED; recovery/resume remains CLOSED.

## Proven boundary

The prior checkpoint references exactly one v2rayN file:
`/Users/zhangsir/Library/Application Support/v2rayN/binConfigs/config.json`.
The other local configuration hash is UTM configuration, not a v2rayN file.
The changed file is generated runtime configuration, but carries security-relevant
listener, outbound, routing and authentication configuration. It cannot be removed
from protection merely because a GUI regenerates it.

The installed application is v2rayN 7.20.4. Its tagged source describes generation
and writing of the runtime config, followed by starting the core in binConfigs:

- [CoreConfigHandler.GenerateClientConfig](https://github.com/2dust/v2rayN/blob/7.20.4/v2rayN/ServiceLib/Handler/CoreConfigHandler.cs)
- [CoreManager.LoadCore/CoreStart](https://github.com/2dust/v2rayN/blob/7.20.4/v2rayN/ServiceLib/Manager/CoreManager.cs)
- [ConfigHandler.SaveConfig](https://github.com/2dust/v2rayN/blob/7.20.4/v2rayN/ServiceLib/Handler/ConfigHandler.cs)

This identifies a capable writer, not the historical writer or the trigger.
Main xray PID 6529 is a child of GUI PID 84672, uses config.json and has
binConfigs as cwd. Its launch second matches the changed runtime config's mtime.
The old config content was not retained; hashes, sizes and mtimes alone do not
permit a byte diff, field diff or semantic equivalence proof.

## Proposed classes

| Class | Examples | Proposed protection |
|---|---|---|
| A: approved byte-stable inputs | approved checkpoint manifest, validator/helper code, pinned application/core binaries if explicitly inventoried | Retain exact byte identity. No existing mutable user config is proven immutable. |
| B: semantic configuration, mutable | guiConfigs/guiNConfig.json; selected profile, routing and subscription records in guiConfigs/guiNDB.db; managed subscription YAML | Validate all relevant semantics and preserve provenance. Never hash mutable SQLite file bytes as a logical snapshot. Use a consistent read transaction in a separately approved implementation. |
| C: generated, security relevant | binConfigs/config.json | Retain raw audit hash AND validate full effective runtime semantics. Source and running process identity must be linked. Do not exempt this file. |
| D: volatile data | guiLogs, generated speed-test configTest*.json, GUI/statistics state/cache | Exclude from strict immutable contract only after field/file inventory establishes it cannot control active proxy semantics. This round does not introduce exclusions. |

## Minimum semantics

Listener address/port, exposure, protocol/authentication, accounts, all inbounds;
route mode and rule order; outbound target identity and credentials as protected
digests, transport/TLS/security flags, proxy chaining and selection; DNS, mux,
sniffing, relevant security toggles; selected profile and subscription source
identity; effective generated configuration and process arguments.
127.0.0.1:10812 is also currently listening. Its pre-drift baseline was not
recorded: it must not be declared unchanged or silently excluded as harmless.

## Analysis canonicalization, not a new official hash

analysis_semantics.py parses JSON, rejects duplicate keys/nonfinite numbers,
sorts object keys and preserves array order. It preserves EVERY field, including
timestamps and counters. No field-level omission is justified by current evidence.
The Python canonical representation is local analysis, not a cross-language
canonical JSON standard and not a replacement checkpoint validator.

Object ordering/whitespace equivalence is tested only for controlled fixtures.
It does not prove the historical 6648 -> 6306 byte change was such a rewrite.
Negative fixtures change listener, port, LAN, routing, server identity and
security flags. Both strict byte identity and analysis digests detect them.
The current strict contract continues rejecting formatting changes too.

## Required before implementation or reacceptance

Obtain the pre-drift bytes matching e3c322ce52c284ac77450781fce9ed71fe0711e52d62550d076059956e054452,
or a trusted pre-drift semantic snapshot sufficiently complete for comparison.
Obtain reliable evidence for the historical write/trigger. Do not restore the old
config, restart a core or normalize live files to manufacture stability.
If historical evidence is unavailable, a NEW future baseline would require explicit
authorization and must not retroactively mark this failed checkpoint VERIFIED.
Any later implementation must preserve unknown fields by default and fail closed
on malformed input, unknown schema, unexpected active listeners or identity changes.
No benign volatile field is excluded in this round. No new checkpoint is built.
