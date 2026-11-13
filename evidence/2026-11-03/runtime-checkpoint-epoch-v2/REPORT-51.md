# Runtime checkpoint 新 epoch 验收报告

Epoch: `runtime-checkpoint-v2-20261103-1e6d9706`。新 checkpoint VERIFIED；旧 checkpoint FAILED，历史连续性 NOT_PROVEN。

本轮仅创建当前状态 epoch 和验收证据。原 14 项 receipt 绑定保持不变，并非在新 epoch 中重新执行 14 项。411 项测试通过；本轮新 Policy evaluation=0，release=0，rollout=0。

1. **old checkpoint reference**

   {
     "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/checkpoint.json",
     "sha256": "17faa575a74abd28ab5eefa5d4c316c15b20bc09a61b6cfc6c12cda8f5c43fac"
   }

2. **old checkpoint status**

   FAILED; immutable historical bytes preserved

   Evidence: `old-checkpoint-integrity.json`

3. **old checkpoint failure reason**

   UNEXPLAINED_PROXY_DRIFT; original literal UNEXPLAINED_PROXY_CONFIG_DRIFT preserved

4. **new epoch ID**

   runtime-checkpoint-v2-20261103-1e6d9706

5. **new epoch creation time**

   2026-11-03T12:47:35.747390+00:00 (UTC); Shanghai 2026-11-03 20:47:35

6. **git revision**

   741ea2866ea142b24c7838e1ef25c8327c79d279; branch fix/security-manager-plugin-switches; working tree is not claimed clean

7. **current proxy config paths**

   {
     "runtime": {
       "path": "/Users/zhangsir/Library/Application Support/v2rayN/binConfigs/config.json",
       "rawSha256": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
       "bytes": 6306,
       "mtimeNs": 1793709444157866523,
       "inode": 51467903,
       "ownerUid": 501,
       "groupGid": 20,
       "modeOctal": "0o644"
     },
     "gui": {
       "path": "/Users/zhangsir/Library/Application Support/v2rayN/guiConfigs/guiNConfig.json",
       "rawSha256": "8c64731f8332b5c3e475d202f2f4a72f613cb3388e1a0c24fbc7b33afefa16d8",
       "bytes": 7943,
       "mtimeNs": 1793709444130121275,
       "inode": 68679970,
       "ownerUid": 501,
       "groupGid": 20,
       "modeOctal": "0o644"
     },
     "database": {
       "path": "/Users/zhangsir/Library/Application Support/v2rayN/guiConfigs/guiNDB.db",
       "rawSha256": "0f48ac7aaeffcfbbf9ebd453d42e0323acf087aee25ae2fba3a83d88fb6df17e",
       "bytes": 29892608,
       "mtimeNs": 1793707481667549636,
       "inode": 5182001,
       "ownerUid": 501,
       "groupGid": 20,
       "modeOctal": "0o644"
     }
   }

   Evidence: `samples/T0.json`

8. **raw proxy hashes**

   {
     "runtime": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
     "gui": "8c64731f8332b5c3e475d202f2f4a72f613cb3388e1a0c24fbc7b33afefa16d8",
     "database": "0f48ac7aaeffcfbbf9ebd453d42e0323acf087aee25ae2fba3a83d88fb6df17e"
   }

9. **semantic proxy digest**

   059b6f8d12d7faf5632c8bf41f59f9926dce048d2faff4affa27396cac27ffb7

10. **listener baseline**

   {
     "primary": [
       {
         "listen": "127.0.0.1",
         "port": 10808,
         "protocol": "mixed",
         "auth": "noauth",
         "accountsPresent": false,
         "sniffingDigest": "da1e2af9a979a9295bd9faf5ed591b27e73532d2c3c1b3f1e16a331b33b5e903"
       }
     ],
     "allXrayListeners": [
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10907"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10908"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10953"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10954"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10967"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10968"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10977"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10978"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10979"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10980"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10981"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10982"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10983"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:10984"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:11831"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:11839"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:11841"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:13433"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:13439"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:13440"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:13441"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:13442"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:13443"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:15190"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:15198"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:15199"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:20411"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:20660"
       },
       {
         "role": "auxiliary-xray",
         "endpoint": "127.0.0.1:21062"
       },
       {
         "role": "primary-xray",
         "endpoint": "127.0.0.1:10808"
       },
       {
         "role": "primary-xray",
         "endpoint": "127.0.0.1:10812"
       }
     ]
   }

11. **port baseline**

   Primary xray loopback TCP 10808 and 10812; auxiliary listeners included in T0 and protected

12. **LAN exposure baseline**

   false; all observed xray TCP listeners are loopback; does not claim an active LAN penetration test

13. **routing baseline**

   {
     "mode": "AsIs",
     "digest": "28ffc90caeb33faa284307e5ba4708e5c689983a45a9c853b23cb51a852134f0",
     "allFieldsProtected": true
   }

14. **outbound identity baseline**

   [
     {
       "tag": "proxy",
       "protocol": "vmess",
       "allFieldsDigest": "8d639e91d2941687cfe972004c719585169026c7c3c5e3ef1fb361e6956fc91e",
       "securityField": null
     },
     {
       "tag": "direct",
       "protocol": "freedom",
       "allFieldsDigest": "adc8dbf26f0745060c10bc05e274a05b844a68c982c20f9985ee4a6cbedca0c1",
       "securityField": null
     },
     {
       "tag": "block",
       "protocol": "blackhole",
       "allFieldsDigest": "f88502e8943bb1746759fb6b6b68848ef2bc81e330db7303e5dbef7716b147bf",
       "securityField": null
     }
   ]

15. **security flags baseline**

   {
     "inbounds": [
       {
         "listen": "127.0.0.1",
         "port": 10808,
         "protocol": "mixed",
         "auth": "noauth",
         "accountsPresent": false,
         "sniffingDigest": "da1e2af9a979a9295bd9faf5ed591b27e73532d2c3c1b3f1e16a331b33b5e903"
       }
     ],
     "dnsDigest": "566cf1363877fedabef3be25fb300e8ae578d0142690b6f4c7200df44a9aad71",
     "policyDigest": "f69dbf823edb3ae93096c83be3c714ae6acc3f908ef395fe9580de3d0963038b",
     "guiSelectionDigest": "46a3599e780e31fcf58e9c463469716071dd836d94e9a9c251fa7cc1c3a83355",
     "allFieldsProtected": true,
     "privateIdentityValues": "Not archived; included in complete aggregate digest"
   }

16. **file classification**

   {
     "contractVersion": "proxy-current-state-v2.1",
     "scope": "Current v2rayN GUI, all logical SQLite tables, primary config.json core, and all xray TCP listeners",
     "jsonCanonicalization": "Python JSON values; sort object keys, preserve array order and scalar types, reject duplicate keys and nonfinite numbers; no omitted fields",
     "A": {
       "strategy": "STRICT_BYTE_HASH",
       "files": [
         "/Applications/v2rayN.app/Contents/Info.plist",
         "/Applications/v2rayN.app/Contents/MacOS/v2rayN",
         "/Users/zhangsir/Library/Application Support/v2rayN/bin/xray/xray"
       ]
     },
     "B": {
       "strategy": "RAW_AUDIT_HASH_PLUS_COMPLETE_LOGICAL_DIGEST",
       "files": [
         "guiConfigs/guiNConfig.json",
         "guiConfigs/guiNDB.db"
       ],
       "protectedJsonFields": "ALL_RECURSIVE_FIELDS",
       "protectedDatabaseFields": "ALL_TABLES_ALL_COLUMNS_ALL_ROWS_PLUS_SCHEMA; transactionally consistent read-only snapshot; duplicate rows retained",
       "rawDbHashLimit": "Audit file bytes are not a substitute for the logical transaction snapshot; no DB backup/export is produced"
     },
     "C": {
       "strategy": "STRICT_BYTE_HASH_AND_ALL_FIELDS_SEMANTIC_DIGEST",
       "files": [
         "binConfigs/config.json"
       ],
       "semanticOnlyAllowed": false,
       "reason": "Generation is established, but benign byte-changing regeneration of this exact runtime config has not been proven"
     },
     "D": {
       "excludedExactPattern": "guiLogs/*.txt",
       "reason": "Diagnostic application logs, not source or effective configuration. No cache/config/state directory is broadly exempted."
     },
     "excludedJsonFields": [],
     "excludedDatabaseTables": [],
     "allowedBenignDifferences": [
       "JSON object key ordering and whitespace in class B only, with identical complete parsed values",
       "SQLite physical layout or row enumeration order with identical complete logical table contents and schema",
       "File mtime/inode replacement with identical protected content; metadata remains recorded"
     ],
     "neverExempt": [
       "listener/address/port/LAN",
       "protocol/authentication/accounts",
       "routing/rule order",
       "outbound/server/credential identity",
       "TLS/transport/security flags",
       "DNS/sniffing/mux",
       "selected GUI profile/routing/subscription source",
       "unknown fields or new SQLite tables",
       "active main process identity changes",
       "new/changed xray listening sockets"
     ],
     "observation": {
       "samples": 5,
       "intervalSeconds": 30,
       "minimumSpanSeconds": 110,
       "maximumSpanSeconds": 180,
       "maximumCaptureSeconds": 15
     },
     "historicalContinuity": "NOT_PROVEN",
     "newEpochBaseline": "CURRENT_STATE_ONLY"
   }

   Evidence: `proxy-contract.json`

17. **byte-hash contract**

   A: Info.plist + GUI binary + xray binary strict SHA256. C: generated config strict raw SHA256 AND complete semantic digest; no semantic-only relaxation. B raw hash audited.

18. **semantic-hash contract**

   B: all GUI JSON fields and every SQLite table/schema/column/typed row + hidden rowid; no table/field ignored. C all JSON fields; arrays ordered; duplicate keys/nonfinite rejected. Protect active GUI/core identities, exe hashes, config cwd/args and all xray TCP listeners.

19. **excluded volatile files**

   Only guiLogs/*.txt diagnostic logs. No excluded JSON fields, database tables, credentials, routing, selected profile or subscription metadata.

20. **exclusion rationale**

   Diagnostic log appends do not define proxy configuration. No generic cache/state exemption. B JSON whitespace/key order and DB physical representation may vary only with identical complete logical content; mtime/inode replacement allowed only with identical protected content.

21. **T0-T4 observations**

   [
     {
       "sample": "T0",
       "startedAt": "2026-11-03T12:47:35.779809+00:00",
       "status": "CAPTURED",
       "rawHashes": {
         "runtime": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
         "gui": "8c64731f8332b5c3e475d202f2f4a72f613cb3388e1a0c24fbc7b33afefa16d8",
         "database": "0f48ac7aaeffcfbbf9ebd453d42e0323acf087aee25ae2fba3a83d88fb6df17e"
       },
       "semanticDigest": "059b6f8d12d7faf5632c8bf41f59f9926dce048d2faff4affa27396cac27ffb7"
     },
     {
       "sample": "T1",
       "startedAt": "2026-11-03T12:48:05.781059+00:00",
       "status": "CAPTURED",
       "rawHashes": {
         "runtime": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
         "gui": "8c64731f8332b5c3e475d202f2f4a72f613cb3388e1a0c24fbc7b33afefa16d8",
         "database": "0f48ac7aaeffcfbbf9ebd453d42e0323acf087aee25ae2fba3a83d88fb6df17e"
       },
       "semanticDigest": "059b6f8d12d7faf5632c8bf41f59f9926dce048d2faff4affa27396cac27ffb7"
     },
     {
       "sample": "T2",
       "startedAt": "2026-11-03T12:48:35.789883+00:00",
       "status": "CAPTURED",
       "rawHashes": {
         "runtime": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
         "gui": "8c64731f8332b5c3e475d202f2f4a72f613cb3388e1a0c24fbc7b33afefa16d8",
         "database": "0f48ac7aaeffcfbbf9ebd453d42e0323acf087aee25ae2fba3a83d88fb6df17e"
       },
       "semanticDigest": "059b6f8d12d7faf5632c8bf41f59f9926dce048d2faff4affa27396cac27ffb7"
     },
     {
       "sample": "T3",
       "startedAt": "2026-11-03T12:49:05.787171+00:00",
       "status": "CAPTURED",
       "rawHashes": {
         "runtime": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
         "gui": "8c64731f8332b5c3e475d202f2f4a72f613cb3388e1a0c24fbc7b33afefa16d8",
         "database": "0f48ac7aaeffcfbbf9ebd453d42e0323acf087aee25ae2fba3a83d88fb6df17e"
       },
       "semanticDigest": "059b6f8d12d7faf5632c8bf41f59f9926dce048d2faff4affa27396cac27ffb7"
     },
     {
       "sample": "T4",
       "startedAt": "2026-11-03T12:49:35.790343+00:00",
       "status": "CAPTURED",
       "rawHashes": {
         "runtime": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
         "gui": "8c64731f8332b5c3e475d202f2f4a72f613cb3388e1a0c24fbc7b33afefa16d8",
         "database": "0f48ac7aaeffcfbbf9ebd453d42e0323acf087aee25ae2fba3a83d88fb6df17e"
       },
       "semanticDigest": "059b6f8d12d7faf5632c8bf41f59f9926dce048d2faff4affa27396cac27ffb7"
     }
   ]

   Evidence: `stability-result.json`, `acceptance-proxy-comparison.json`

22. **raw-hash stability**

   All T0–T4 protected raw hashes stable; span 120.010534 seconds. No benign differences observed. Acceptance-time immediate comparison also passed.

23. **semantic-digest stability**

   All five complete semantic digests identical; process and binary identities stable. Bounded current-state window only; no proof across all future refresh intervals.

24. **negative semantic tests**

   25/25 proxy tests, including listener address/port/LAN, routing, outbound, security and auth changes rejected; unknown field/array/db content drift rejected. All mutations isolated fixtures.

   Evidence: `proxy-tests.log`

25. **implementation hash matrix**

   {
     "existing": 77,
     "newEpochTooling": 9,
     "frozenGateReferences": 455,
     "uniqueGateFiles": 229,
     "compatibilitySamples": 2202
   }

   Evidence: `source-hash-matrix.json`

26. **14 wired source receipts**

   [
     {
       "source": "sbom",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sbom/result.json",
           "sha256": "93388266653028f02f7cb9283b865c24a31911d257e4f86c3e13f9cb14d62399"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sbom/capture.json",
           "sha256": "20a7e80eed09f079fbca76998f525d5c261ccf5f71289c48dff7fa45616d087b"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sbom/gate.json",
           "sha256": "fc894769acf88ef317be6b1207cc59caf3713e8aa25442c9c4415c6b85f3f783"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "regression",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/regression/result.json",
           "sha256": "42d35592c129aed9e868f39e19f93d5a1c89f79e721f796d4574fdded94ea8f2"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/regression/capture.json",
           "sha256": "86367188ba328d4de606c8b8a5e3b950c6bbf5da2015fb1be078665ed16f82ee"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/regression/gate.json",
           "sha256": "f4543e06430f4e6c808186b3d3e5ef84357e5af0cd317fc12452ab606bff3843"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "falco-baseline",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/falco-baseline/result.json",
           "sha256": "6ae86bd3cf14281a09e5cb99846c53666fb7ab5b856445228e7850a62c5fbb00"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/falco-baseline/capture.json",
           "sha256": "2d7b9710f4d6268d66657a2643940d366c803f9110d9f57010b2062d0d5a220a"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/falco-baseline/gate.json",
           "sha256": "a1b4643b50de6abb15648c20dbfb95fd8a4f55536ecb000d58782847459267da"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "kyverno",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/kyverno/result.json",
           "sha256": "8e289c580e3eabe78976a54c53bf3cb6124025ba3f15ee4179c5bd9d1e284544"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/kyverno/capture.json",
           "sha256": "6e4c52b7cca8f8789a222baf5b41e6709bbb05f6b7097250c8666bc1980f19da"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/kyverno/gate.json",
           "sha256": "958761cb8f439f399d231351cefef0698905f1f431abe82ab86083e094a512d5"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "kubescape",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/kubescape/result.json",
           "sha256": "13e7d24bbd14e14747cf2e380342b15ccf012fa9447751d1aedc4d34f381af57"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/kubescape/capture.json",
           "sha256": "89da3e7a6c271f255f063057a7d7f3d6e4d0e162bcefd59fbe2dc5d7fa17cc7a"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/kubescape/gate.json",
           "sha256": "8fd2189a0fb85b8674b0b460152dbd45c42a5170dbcf1dc06ca0d65427b60df7"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "gitleaks",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 14,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#14",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/gitleaks/result.json",
           "sha256": "37bd88e88a42b8801c22beab9b2704a00245800233d93ef3d351144e4343028b"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/gitleaks/capture.json",
           "sha256": "92d957389954b8dd65b3bd30c1d304f1fc28c94c470560e00159f5fbe593a31f"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/gitleaks/gate.json",
           "sha256": "132594240fe9f65f13738d21d95b424847a082650fd95322302c642e6a9b16b8"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "sops",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sops/result.json",
           "sha256": "92e80705f4b74b712f2a381c62c63cc8751809cb5d6a3ac39d1402a8b5befc95"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sops/capture.json",
           "sha256": "6c2606088533cb7ad2841ac14c2437116004ff51d8fca4ce51fbfc3d6bccb9a3"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sops/gate.json",
           "sha256": "ace0a770ceb1b5f11d76f61977fd3d5daca7b484a9788dd15725fe99ec64191c"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "cosign",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/signature-fixtures@sha256:a786348b1bfb3125c150d94d58d6edc51beb36fb832ad258e000b03fbab7d899",
         "build": 32,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#32",
         "job": "security-runtime-facts-20261102",
         "targetScope": "candidate"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/cosign/result.json",
           "sha256": "daeb8f062c340a9366dcf3b8749be2992b8f4f826f0404836d5a3bacaf141206"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/cosign/capture.json",
           "sha256": "3204303d7d1c556a29cd97d97ee2f37d6981f7e8e0aa9255b73a69049c2c4eb9"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/cosign/gate.json",
           "sha256": "d9715e7c9acff4931bf0db94347456ed4cb490d85022b569156015f6ca24aaeb"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "sonarqube",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sonarqube/result.json",
           "sha256": "4d848cbc3d66578f122a1e3168ad76201d66e1c60f72dd044b69c7f05c349787"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sonarqube/capture.json",
           "sha256": "dfbb7122e37a03012ebe4de0d1af2d488dce51e4dd6b2b4108240a838b4838cc"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/sonarqube/gate.json",
           "sha256": "522d3b5d8f6eb92e0ae2987ad26c2859c83c301e22dd059d889502f190551635"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "zap",
       "binding": {
         "candidate": "127.0.0.1:30050/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 20,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#20",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/zap/result.json",
           "sha256": "7904ed2d6f88d8e4eaeaa41f8cda7d669efeab77dbf0001143d946e1d750b4f7"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/zap/capture.json",
           "sha256": "db0f316537d06479478e78d7e3b7366a1620bd84cb7c9459f88d2bfbd12d7985"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/zap/gate.json",
           "sha256": "3a2aa50b82f2b0f728d18216574e2a29d2a6e94f67234bba007ce87424ebd6cb"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "falco-final",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/falco-final/result.json",
           "sha256": "eff3b5af50bc7c5806b37fbae4bf47627340393eb6524c4f31711df45c7b9070"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/falco-final/capture.json",
           "sha256": "59a8dc6febd740e88034cdde9ace570464eee09d836207f20171afbc69e07e4c"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/falco-final/gate.json",
           "sha256": "59b66ff0b20a3e589b91f7ade9000f3a1e7e0c5ebc0edcc5e55f82f02c66c415"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "provenance",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/provenance/result.json",
           "sha256": "628a5621a929b6c2be6529cd2c8f5a61e6ecebb421c464f89f0fe4309310d148"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/provenance/capture.json",
           "sha256": "085d08591b4564b6cde5d1ff09eb086cb9ab47c9d65ec77a9f36d8d9c07155d5"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/provenance/gate.json",
           "sha256": "a552a914a92ce72a35b876d890cfa1de8793a110157de98d7e26cf4d9acae35b"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "build-provenance",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 12,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#12",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/build-provenance/result.json",
           "sha256": "41189b1bd20304a5c75c21405acc543dd7bb8d9482db1e10cd749f1e20802864"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/build-provenance/capture.json",
           "sha256": "f8c99253bf393a2f7f65891bacb16ba5dab8b32e2411a187f988017f825b0429"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/build-provenance/gate.json",
           "sha256": "2df03ae18892ced21db6845aa45f5671f150f63c1696c2c75ae217024c562614"
         }
       },
       "acceptance": "VERIFIED"
     },
     {
       "source": "semgrep-command-audit",
       "binding": {
         "candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137",
         "build": 15,
         "project": "petclinic",
         "source": "741ea2866ea142b24c7838e1ef25c8327c79d279",
         "runId": "security-runtime-facts-20261102#15",
         "job": "security-runtime-facts-20261102",
         "targetScope": "runtime"
       },
       "receipts": {
         "result": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/semgrep-command-audit/result.json",
           "sha256": "21f0fa3bc6854d9b7cde38c9b735aaffede3e243f28ac392de52cb8dbcf2ad23"
         },
         "capture": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/semgrep-command-audit/capture.json",
           "sha256": "5fb338ea0398f21363c04a7fd9ce87e3ab51531c5a117ee3f6f1e55e852deba6"
         },
         "gate": {
           "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/receipts/semgrep-command-audit/gate.json",
           "sha256": "ae75a634b32fe02ccfdeab57c988ad878b9d4ab27419477d333729829154c22e"
         }
       },
       "acceptance": "VERIFIED"
     }
   ]

   Evidence: `checkpoint.json`, `old-checkpoint-integrity.json`

27. **Trivy blocker receipt**

   ENVIRONMENT: storage/backup capacity unavailable. Runtime absent; Policy result null; zero evaluations. Guard remains CALCULATED_FROM_FILESYSTEM_STATE / GUARD_REQUIRES_REVALIDATION / YES. No threshold changes.

   Evidence: `blocker-trivy.json`

28. **Dojo blocker receipt**

   DEPENDENCY: current Trivy-native report absent. Runtime absent; Policy result null. TRIVY_HARD_DEPENDENCY; decoupling required YES; not implemented.

   Evidence: `blocker-defectdojo.json`

29. **historical continuity declaration**

   HISTORICAL_CONTINUITY=NOT_PROVEN; NEW_EPOCH_BASELINE=CURRENT_STATE_ONLY. Current b702 hash matches an earlier post-drift observation but does not recover old e3c3 bytes or identify historical writer.

30. **historical failed-checkpoint refs**

   {
     "checkpoint": {
       "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/checkpoint.json",
       "sha256": "17faa575a74abd28ab5eefa5d4c316c15b20bc09a61b6cfc6c12cda8f5c43fac"
     },
     "oldHashes": {
       "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/local-config-before.json",
       "sha256": "51af4f5b65f64d635fd9a63173047d6143a365365d67c43946725c4d6d53abd8"
     },
     "oldDrift": {
       "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/observed-protection-drift.json",
       "sha256": "58903ab011e6ef2d98d4db9a24c087c41faeb8bc815357754e7f1adf748b2d4c"
     },
     "oldAcceptance": {
       "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/checkpoint-integrity.json",
       "sha256": "52c46e4c81f3e5c06d17e924dc8b74f34656889b99e6214f4a3ec4bb4bd2bad9"
     },
     "driftReport": {
       "path": "evidence/2026-11-03/runtime-proxy-drift-review/REPORT-43.md",
       "sha256": "8d644959593be2c80e6592cc173d92b9c7516535f4c3ab2950e28e3d27c9f72b"
     },
     "historyRecoveryReport": {
       "path": "evidence/2026-11-03/runtime-proxy-history-recovery/REPORT-43.md",
       "sha256": "46c30a7f8c38e969e48f96a31d60ee5377f4b5959b528df2c50b9b52dfafb7a7"
     },
     "archiveDeltaReport": {
       "path": "evidence/2026-11-03/runtime-proxy-history-delta/REPORT-43.md",
       "sha256": "8990daa7b510d45411b5a998dce807d7e8e7e63d241e8b7967dad23e45b6193d"
     },
     "archiveSearch": {
       "path": "evidence/2026-11-03/runtime-proxy-history-delta/large-archive-results.json",
       "sha256": "48581d1933b54eb97c38833ce4430d5a5f99656c9d756235c371fe1489c8da51"
     },
     "priorSeals": [
       {
         "path": "evidence/2026-11-03/runtime-proxy-drift-review/evidence-sha256.json",
         "sha256": "78a4201961d40f14b1a90c04716d040dbab8d75d4ec9de69de1db3c9b8b9d840"
       },
       {
         "path": "evidence/2026-11-03/runtime-14-checkpoint-guard-review/evidence-sha256.json",
         "sha256": "f08f499deb7e3dd76962e15ec4b71250e5360cb951d96d0d0ca390c6e53e8373"
       },
       {
         "path": "evidence/2026-11-03/runtime-dojo-dependency-review/evidence-sha256.json",
         "sha256": "a4dcfbdf591300c89a519865fb66aa82ab0f3d1f97497cf3fead398e86923ed4"
       },
       {
         "path": "evidence/2026-11-03/runtime-independent-boundaries/evidence-sha256.json",
         "sha256": "215931b59927926f07c1b5fe7f59e96eb50955d60c181dafdc42bc2c309c0404"
       },
       {
         "path": "evidence/2026-11-03/runtime-final-three/evidence-sha256.json",
         "sha256": "19ec65deb854c17fad43d8cfdf428299f58fc72091ca23961c1b552d5a126cc1"
       },
       {
         "path": "evidence/2026-11-03/trivy-infra-repair/evidence-sha256.json",
         "sha256": "88045a1cb868377891b2e636063d7fddce5d2b22bf8bfd429e151deea17b0597"
       },
       {
         "path": "evidence/2026-11-03/trivy-storage-expansion/evidence-sha256.json",
         "sha256": "e8061397fdce1d867c74b8332106d88bb78edb59240b21bbc5313faee113bba4"
       },
       {
         "path": "evidence/2026-11-03/trivy-pre-expansion/evidence-sha256.json",
         "sha256": "a965e6b09123a32989e7be4171c64dec921bb696db9aeacfe780fe5d2f16f773"
       },
       {
         "path": "evidence/2026-11-03/trivy-backup-capacity/evidence-sha256.json",
         "sha256": "be0d63c27611a4a22be8ed4847491c39a658b02fcdcba753a7d377db09d702e3"
       },
       {
         "path": "evidence/2026-11-03/trivy-external-storage-gate/evidence-sha256.json",
         "sha256": "d15356592d6723f41ff232061cbbe17be5bc94360ade62d99bea25e6d122b8d4"
       },
       {
         "path": "evidence/2026-11-03/runtime-boundary-followup/evidence-sha256.json",
         "sha256": "11e0f4f241fc0787387351019bf824a7074ac2ce0678aacd84d03f72ce28fe56"
       },
       {
         "path": "evidence/2026-11-03/runtime-proxy-history-recovery/evidence-sha256.json",
         "sha256": "749136355f80b2d558d35f0bb1c0b82e6d3cbaba1ea6f586d20e65eced3023a3"
       },
       {
         "path": "evidence/2026-11-03/runtime-proxy-history-delta/evidence-sha256.json",
         "sha256": "f5c5d7345d6a305f071c41f12744baccc10035eefe988c4d5962327918d9ef4e"
       }
     ]
   }

31. **checkpoint integrity manifest**

   {
     "checkpointPath": "evidence/2026-11-03/runtime-checkpoint-epoch-v2/checkpoint.json",
     "checkpointSha256": "a4c910144aee4d917345d27ad945a0b1ab2d6befc1eed3405ed7ccb4d19dabe1",
     "integrityManifestPath": "evidence/2026-11-03/runtime-checkpoint-epoch-v2/checkpoint-integrity-manifest.json",
     "integrityManifestSha256": "ab3bafa7e78136345818898a9e36e54314c06e13c36cc8b366ac1669f39fc59a"
   }

   Evidence: `checkpoint-integrity-manifest.json`, `checkpoint-verification.json`

32. **NEW_EPOCH_PROXY_BASELINE**

   VERIFIED

33. **NEW_EPOCH_SEMANTIC_CONTRACT**

   VERIFIED

34. **NEW_EPOCH_STABILITY_OBSERVATION**

   VERIFIED

35. **RUNTIME_14_OF_16_NEW_EPOCH_CHECKPOINT**

   VERIFIED

36. **runtime tests**

   143/143 PASS; completeness negative 11/11 PASS

37. **candidate tests**

   40/40 PASS; isolated disposable checkout

38. **Policy core**

   5/5 PASS; compatibility corpus remains 2202; no new runtime Policy evaluation

39. **contract checks**

   10/10 PASS

40. **Regression 147/147**

   147/147 PASS

41. **checkpoint tests**

   19/19 PASS including epoch structure, non-Policy blockers and integrity/path constraints

42. **integrity tests**

   11/11 PASS against real new artifacts using mocked read buffers; checkpoint/baseline/contract/blocker/source tamper and recomputed-digest semantic forgery rejected. 399 manifest references verified. Old verifier retains FAILED and denies old resume.

43. **source/hash preservation**

   {
     "status": "VERIFIED",
     "existingImplementationFiles": 77,
     "newFrozenEpochTooling": 9,
     "frozenGateReferences": 455,
     "uniqueFrozenGateFiles": 229,
     "historicalSealedFilesChecked": 1065,
     "compatibilitySamplesUnchanged": 2202,
     "oldCheckpointSha256": "17faa575a74abd28ab5eefa5d4c316c15b20bc09a61b6cfc6c12cda8f5c43fac"
   }

44. **production Jenkins state**

   petclinic-ci #270 SUCCESS; no trigger; active deployed manager hash unchanged (known local undeployed optional-switch difference preserved).

   Evidence: `protected-state.json`, `live-jenkins-final.json`

45. **V1 state**

   {
     "sha256": "ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8",
     "unchanged": true
   }

   Evidence: `active-v1-selection-identity.json`

46. **nodes state**

   {
     "Ready": [
       "aliyun-worker",
       "devops",
       "ucloud-worker"
     ]
   }

   Evidence: `node-lease-postflight.json`

47. **PetClinic state**

   {
     "Ready": 3,
     "readyEndpoints": 3,
     "HTTP": 200,
     "ArgoCD": "Synced/Healthy"
   }

   Evidence: `health-final.json`

48. **release count**

   0

49. **rollout count**

   0

50. **exact blocker if new epoch FAILED**

   None for NEW epoch acceptance. Overall runtime still incomplete: Trivy ENVIRONMENT_BLOCKED and Dojo BLOCKED_BY_TRIVY. No 16/16 same-run proof, COMPLETE or Summary V2 activation.

51. **exact next permitted action**

   STOP. Future separately authorized runtime continuation only from 14/16 after fresh live-state/reference validation. Trivy requires capacity/backup change or approved guard revalidation; Dojo requires current report or authorized decoupling. No automatic continuation.

## Final verdicts

```text
OLD_CHECKPOINT_STATUS=FAILED
OLD_CHECKPOINT_REASON=UNEXPLAINED_PROXY_DRIFT
HISTORICAL_CONTINUITY=NOT_PROVEN
NEW_CHECKPOINT_EPOCH=runtime-checkpoint-v2-20261103-1e6d9706
NEW_EPOCH_PROXY_BASELINE=VERIFIED
NEW_EPOCH_SEMANTIC_CONTRACT=VERIFIED
NEW_EPOCH_STABILITY_OBSERVATION=VERIFIED
RUNTIME_14_OF_16_NEW_EPOCH_CHECKPOINT=VERIFIED
TRIVY_STORAGE_ENVIRONMENT=ENVIRONMENT_BLOCKED
TRIVY_RUNTIME_FACT_CAPTURE=INCOMPLETE
DEFECTDOJO_RUNTIME_DEPENDENCY=BLOCKED_BY_TRIVY
DEFECTDOJO_RUNTIME_FACT_CAPTURE=INCOMPLETE
COSIGN_RUNTIME_FACT_CAPTURE=VERIFIED
FINAL_WIRED_CAPABILITY=14/16
REAL_RUNTIME_FACT_CAPTURE=INCOMPLETE
REAL_POLICY_OWNER=INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME=INCOMPLETE
SUMMARY_V2_MIGRATION=INCOMPLETE
```

STOP。验收只覆盖记录的当前状态和有界采样窗口。离线完整性通过不构成未来 live state 永久有效的证明。
