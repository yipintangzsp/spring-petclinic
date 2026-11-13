"""Login Keychain only. No command-line secrets or plaintext fallback."""
import ctypes,uuid
C=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
S=ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
P=ctypes.c_void_p
C.CFStringCreateWithCString.argtypes=[P,ctypes.c_char_p,ctypes.c_uint32];C.CFStringCreateWithCString.restype=P
C.CFDataCreate.argtypes=[P,P,ctypes.c_long];C.CFDataCreate.restype=P
C.CFDictionaryCreate.argtypes=[P,P,P,ctypes.c_long,P,P];C.CFDictionaryCreate.restype=P
C.CFRelease.argtypes=[P]
S.SecItemAdd.argtypes=[P,P];S.SecItemAdd.restype=ctypes.c_int32
S.SecItemDelete.argtypes=[P];S.SecItemDelete.restype=ctypes.c_int32
S.SecItemCopyMatching.argtypes=[P,P];S.SecItemCopyMatching.restype=ctypes.c_int32
C.CFDataGetLength.argtypes=[P];C.CFDataGetLength.restype=ctypes.c_long
C.CFDataGetBytePtr.argtypes=[P];C.CFDataGetBytePtr.restype=P
S.SecKeychainSetUserInteractionAllowed.argtypes=[ctypes.c_bool];S.SecKeychainSetUserInteractionAllowed(False)
SERVICE='petclinic-security-manager-v2-grafana'
ACCOUNT='security-manager-v2-dashboard'
def const(k):return P.in_dll(S,k).value
def dictionary(service,account,secret=None,return_data=False):
 refs=[]
 def string(s):
  p=C.CFStringCreateWithCString(None,s.encode(),0x08000100);refs.append(p);return p
 items=[(const('kSecClass'),const('kSecClassGenericPassword')),(const('kSecAttrService'),string(service)),(const('kSecAttrAccount'),string(account))]
 if secret is not None:
  b=secret.encode();buf=ctypes.create_string_buffer(b);data=C.CFDataCreate(None,buf,len(b));refs.append(data);items.append((const('kSecValueData'),data))
 if return_data:items.append((const('kSecReturnData'),P.in_dll(C,'kCFBooleanTrue').value))
 keys=(P*len(items))(*[k for k,v in items]);values=(P*len(items))(*[v for k,v in items])
 d=C.CFDictionaryCreate(None,keys,values,len(items),None,None)
 return d,refs

def operation(action,service=SERVICE,account=ACCOUNT,secret=None):
 d,refs=dictionary(service,account,secret,action=='get');result=P()
 try:
  if action=='add':code=S.SecItemAdd(d,None)
  elif action=='delete':code=S.SecItemDelete(d)
  else:code=S.SecItemCopyMatching(d,ctypes.byref(result))
  if code:raise RuntimeError('KEYCHAIN_'+action.upper()+'_OSSTATUS_'+str(code))
  if action=='get':
   try:return ctypes.string_at(C.CFDataGetBytePtr(result),C.CFDataGetLength(result)).decode()
   finally:C.CFRelease(result)
 finally:
  C.CFRelease(d)
  for p in refs:C.CFRelease(p)
def probe():
 a='storage-probe-'+str(uuid.uuid4())
 operation('add',account=a,secret='NON_SECRET_STORAGE_PROBE')
 try:assert operation('get',account=a)=='NON_SECRET_STORAGE_PROBE'
 finally:operation('delete',account=a)
