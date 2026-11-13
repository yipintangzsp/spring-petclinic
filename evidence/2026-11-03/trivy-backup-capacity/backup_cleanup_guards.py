"""Pure readiness checks only. No delete, copy, process control, VM or network operations."""
from pathlib import PurePosixPath

def bytes_ok(v):return type(v) is int and v>=0

def destination_ready(e):
 if not isinstance(e,dict):return False
 flags=('independent','mountVerified','stableMount','formatSupported','reliabilityVerified','availableForFullWindow','restoreReadVerified','permissionsStable','largeFileValidated')
 if not all(e.get(k) is True for k in flags):return False
 if not all(bytes_ok(e.get(k)) for k in ('freeBytes','requiredBytes','maxFileBytes','largestFileBytes')):return False
 if e['freeBytes']<e['requiredBytes'] or e['maxFileBytes']<e['largestFileBytes']:return False
 if e.get('usesSparseBudget') is True and not all(e.get(k) is True for k in ('sparsePreservationValidated','coldSourceBoundVerified','sparseRestoreVerified')):return False
 if e.get('network') is True and not all(e.get(k) is True for k in ('sustainedConnectivity','largeFileRoundtrip','timeoutBehaviorVerified')):return False
 return type(e.get('network')) is bool and type(e.get('usesSparseBudget')) is bool

def safe_candidate(e,protected):
 if not isinstance(e,dict):return False
 raw=e.get('path');p=PurePosixPath(raw) if isinstance(raw,str) else None
 if p is None or not p.is_absolute() or '..' in p.parts or str(p)=='/':return False
 for root in protected:
  root=PurePosixPath(root)
  if p==root or root in p.parents or p in root.parents:return False
 if e.get('classification') not in ('SAFE_EPHEMERAL','SAFE_REPRODUCIBLE'):return False
 if not bytes_ok(e.get('sizeBytes')):return False
 for k in ('ownerVerified','lastUseVerified','reproducible','recoveryVerified','projectDependencyChecked','currentReferenceCheckComplete'):
  if e.get(k) is not True:return False
 return e.get('neededByCurrentProject') is False and e.get('currentProcessReference') is False and e.get('symlink') is False

def cleanup_plan_ready(candidates,protected,free,target):
 if not bytes_ok(free) or not bytes_ok(target) or not isinstance(candidates,list):return {'ready':False,'safeBytes':0}
 good=[e for e in candidates if safe_candidate(e,protected)]
 # Reject nested/doubled paths to avoid counting bytes twice.
 paths=[PurePosixPath(e['path']) for e in good]
 if len(set(paths))!=len(paths) or any(a in b.parents for a in paths for b in paths if a!=b):return {'ready':False,'safeBytes':0}
 total=sum(e['sizeBytes'] for e in good)
 return {'ready':free+total>=target and len(good)>0,'safeBytes':total,'requiredReclaimBytes':max(0,target-free),'targetBytes':target}
