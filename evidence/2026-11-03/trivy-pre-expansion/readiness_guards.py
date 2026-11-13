"""Non-executing preflight checks. No subprocess, VM, filesystem or network actions."""
GIB=1024**3
GATES=('HOST_CAPACITY_READINESS','BACKUP_READINESS','BACKUP_VALIDATION','RESTORE_READINESS','VM_MAINTENANCE_READINESS','BACKING_DISK_RESIZE_READINESS','GUEST_PARTITION_GROW_READINESS','FILESYSTEM_GROW_READINESS')
def integer_bytes(x):return type(x) is int and x>=0

def host_capacity(available,backup_bytes,growth_bytes,metadata_bytes,temporary_bytes,reserve_bytes):
 values=(available,backup_bytes,growth_bytes,metadata_bytes,temporary_bytes,reserve_bytes)
 if not all(integer_bytes(x) for x in values):return {'ready':False,'reason':'INVALID_OR_MISSING_MEASUREMENT','requiredBytes':None}
 required=sum(values[1:]);return {'ready':available>=required,'requiredBytes':required,'remainingBytes':available-required}

def image_in_use_guard(e):
 if not isinstance(e,dict):return False
 return e.get('vmState')=='Stopped' and e.get('fresh') is True and type(e.get('qemuPids')) is list and not e['qemuPids'] and type(e.get('imageOpenHandles')) is list and not e['imageOpenHandles'] and e.get('allWritersChecked') is True

def backup_ready(e):
 keys=('capacityReady','targetVerified','strategySelected','sourceIdentityBound','platformHealthy','jobsIdle','gcIdle','refreshIdle','registryMaintenanceIdle','exclusiveWindowPlanned','restorePlanDefined')
 return isinstance(e,dict) and all(e.get(k) is True for k in keys)

def validate_backup(e):
 keys=('exists','sourceWasStopped','sourceImageReleased','sourceIdentityMatches','sizeMatches','hashMatches','recognizedFormat','offlineCheckPassed','notTruncated')
 return isinstance(e,dict) and all(e.get(k) is True for k in keys)

def restore_ready(e):
 return isinstance(e,dict) and e.get('backupValidated') is True and e.get('planValidated') is True and e.get('capacityReady') is True and e.get('neverOverwriteLiveVMForTest') is True and e.get('validationLevel') in ('OFFLINE_IMAGE_VALIDATED','ISOLATED_BOOT_VERIFIED')

def isolated_boot_ready(e):
 return isinstance(e,dict) and all(e.get(k) is True for k in ('backupValidated','newVmIdentity','allNetworkingDisabled','noSharedWritableProductionStorage','cpuMemoryCapacityProven'))

def resize_ready(gates,image_guard):
 if not isinstance(gates,dict) or image_guard is not True:return False
 return all(gates.get(k)==('VERIFIED' if k=='BACKUP_VALIDATION' else 'READY') for k in GATES)
