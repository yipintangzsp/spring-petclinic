"""Pure evidence audit, no execution hooks or provisioner."""
COLUMNS=['Production Safety','Disk','Filesystem','Storage Topology','Measurement','Network','Credentials','Isolation','Failure Safety','Repeatability']
CRITICAL=['Disk','Filesystem','Storage Topology','Isolation','Failure Safety','Repeatability']
def score(row):
 if row['productionRole']!='VALIDATION_SAFE':return 'INELIGIBLE'
 if any(row[k]=='FAIL' for k in COLUMNS):return 'INELIGIBLE'
 if all(row[k] in {'PASS','READY','NOT_REQUIRED'} for k in COLUMNS):return 'ELIGIBLE'
 if any(row[k]=='UNKNOWN' for k in CRITICAL):return 'UNKNOWN'
 if row.get('nonDestructivePreflightOnlyProven') is True:return 'CONDITIONALLY_ELIGIBLE'
 return 'UNKNOWN'
def resource_decision(rows):
 if not rows:return 'UNKNOWN'
 result=[score(r) for r in rows]
 if 'ELIGIBLE' in result:return 'AVAILABLE'
 return 'NOT_AVAILABLE' if all(s=='INELIGIBLE' for s in result) else 'UNKNOWN'
def validate_capacity(c):
 if type(c['requiredBytes']) is not int or c['requiredBytes']<=0:raise ValueError('REQUIRED_BYTES')
 a=c['availableBytes']
 if a is None:
  if c['status']!='UNKNOWN' or c['headroomBytes'] is not None:raise ValueError('UNKNOWN_CAPACITY_NOT_PASS')
  return
 if type(a) is not int or a<0:raise ValueError('AVAILABLE_BYTES')
 if c['headroomBytes']!=a-c['requiredBytes']:raise ValueError('HEADROOM')
 if c['status']!=('PASS' if a>=c['requiredBytes'] else 'FAIL'):raise ValueError('FREE_NOT_TOTAL')
def validate_inventory(rows,requirements):
 if not rows or len({r['candidateId'] for r in rows})!=len(rows):raise ValueError('CANDIDATE_ID')
 expected={r['property'] for r in requirements['filesystemEquivalence'] if r['classification']=='MUST_MATCH_PRODUCTION'}
 for r in rows:
  for k in COLUMNS:
   if r[k] not in {'PASS','FAIL','UNKNOWN','READY','NOT_READY','NOT_REQUIRED'}:raise ValueError('UNKNOWN_VERDICT')
  if {p['property'] for p in r['mustMatchFilesystem']}!=expected:raise ValueError('MUST_MATCH_COVERAGE')
  for c in r['capacityChecks']:validate_capacity(c)
  if r['Overall']!=score(r):raise ValueError('FALSE_ELIGIBILITY')
 return True
def validate_blocker(b,rows):
 if b['runtimeResult'] is not None or b['policyResult'] is not None or b['policyEvaluations']!=0:raise ValueError('BLOCKER_NOT_POLICY')
 if b['resourceAvailable']!='NOT_AVAILABLE' or resource_decision(rows)!='NOT_AVAILABLE':raise ValueError('FALSE_RESOURCE_CLOSURE')
 if {r['candidateId'] for r in b['rejectedCandidates']}!={r['candidateId'] for r in rows}:raise ValueError('MISSING_REJECTION')
 if not b['auditClosed'] or not b['noLoop'] or not b['materialChanges']:raise ValueError('MISSING_NO_LOOP')
 return True
