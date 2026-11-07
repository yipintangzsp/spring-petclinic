"""Input verification only; no scanner, network, credential, shell or Policy.

The caller must obtain `git_entries` from the authorized server-side Git tree of
an independently verified commit. Never accept this manifest from a CI client.
"""
import hashlib,io,pathlib,tarfile,os,shutil

def blob_oid(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def valid_path(text):
 if not isinstance(text,str)or not text or '\\'in text or '\x00'in text:raise ValueError('SOURCE_PATH_REJECTED')
 p=pathlib.PurePosixPath(text)
 if p.is_absolute()or any(x in ('','.','..','.git')for x in text.split('/')):raise ValueError('SOURCE_PATH_REJECTED')
 return p

def materialize_verified_archive(archive,git_entries,destination,limits):
 """Verify all bytes before exclusive writes; delete only this new directory on failure."""
 if len(archive)>limits['archiveBytes']:raise ValueError('SOURCE_ARCHIVE_BUDGET')
 if not git_entries or len(git_entries)>limits['files']:raise ValueError('SOURCE_FILE_BUDGET')
 for rel,e in git_entries.items():
  valid_path(rel)
  if set(e)!={'mode','oid'}or e['mode']not in ('100644','100755')or len(e['oid'])!=40 or any(c not in '0123456789abcdef'for c in e['oid']):raise ValueError('SOURCE_TREE_REJECTED')
 files={};seen=set();prefix=None;total=0;entries=0
 with tarfile.open(fileobj=io.BytesIO(archive),mode='r:*')as tar:
  for member in tar:
   entries+=1
   if entries>limits['files']*4+4:raise ValueError('SOURCE_ENTRY_BUDGET')
   name=member.name.rstrip('/')if member.isdir()else member.name
   parts=valid_path(name).parts
   if prefix is None:prefix=parts[0]
   if parts[0]!=prefix or name in seen:raise ValueError('SOURCE_ARCHIVE_LAYOUT')
   seen.add(name)
   if member.isdir():continue
   if not member.isfile()or len(parts)<2:raise ValueError('SOURCE_LINK_OR_TYPE_REJECTED')
   rel='/'.join(parts[1:]);valid_path(rel)
   if rel not in git_entries or rel in files:raise ValueError('SOURCE_TREE_MISMATCH')
   if member.size>limits['fileBytes']:raise ValueError('SOURCE_FILE_BUDGET')
   total+=member.size
   if total>limits['expandedBytes']:raise ValueError('SOURCE_EXPANDED_BUDGET')
   data=tar.extractfile(member).read(member.size+1)
   if len(data)!=member.size or blob_oid(data)!=git_entries[rel]['oid']:raise ValueError('SOURCE_BLOB_MISMATCH')
   files[rel]=data
 if set(files)!=set(git_entries):raise ValueError('SOURCE_INCOMPLETE_TREE')
 dest=pathlib.Path(destination)
 if dest.exists()or dest.is_symlink()or dest.parent.resolve()!=dest.parent:raise ValueError('SOURCE_DESTINATION_REJECTED')
 dest.mkdir(mode=0o700)
 try:
  for rel,data in files.items():
   target=dest.joinpath(*valid_path(rel).parts);target.parent.mkdir(parents=True,exist_ok=True)
   fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
   with os.fdopen(fd,'wb')as f:f.write(data)
  manifest=[{'path':p,'gitBlobOid':git_entries[p]['oid'],'gitMode':git_entries[p]['mode'],'sha256':hashlib.sha256(files[p]).hexdigest(),'bytes':len(files[p])}for p in sorted(files)]
  return {'archiveSha256':hashlib.sha256(archive).hexdigest(),'files':manifest,'fileCount':len(manifest),'expandedBytes':total,'contentBinding':'EXACT_GIT_TREE_BLOB_SET','classification':'VERIFIED_INPUT_ONLY_NOT_SCAN'}
 except BaseException:shutil.rmtree(dest);raise

def canonical_blob_archive(git_entries,batch,limits):
 """Archive exact Git blob bytes; do not apply checkout/export text attributes."""
 import gzip
 if not git_entries or len(git_entries)>limits['files']:raise ValueError('SOURCE_FILE_BUDGET')
 out=io.BytesIO();offset=0;total=0
 with tarfile.open(fileobj=out,mode='w',format=tarfile.PAX_FORMAT)as tar:
  for rel,e in sorted(git_entries.items()):
   valid_path(rel);end=batch.find(b'\n',offset)
   if end<0:raise ValueError('SOURCE_BLOB_BATCH')
   header=batch[offset:end].decode('ascii').split();offset=end+1
   if len(header)!=3 or header[:2]!=[e['oid'],'blob']or not header[2].isdigit():raise ValueError('SOURCE_BLOB_BATCH')
   size=int(header[2]);total+=size
   if size>limits['fileBytes']or total>limits['expandedBytes']:raise ValueError('SOURCE_BLOB_BUDGET')
   data=batch[offset:offset+size];offset+=size
   if len(data)!=size or batch[offset:offset+1]!=b'\n'or blob_oid(data)!=e['oid']:raise ValueError('SOURCE_BLOB_MISMATCH')
   offset+=1;info=tarfile.TarInfo('source/'+rel);info.size=size;info.mode=0o444;info.mtime=0;tar.addfile(info,io.BytesIO(data))
 if offset!=len(batch):raise ValueError('SOURCE_BLOB_BATCH_EXTRA')
 archive=gzip.compress(out.getvalue(),mtime=0)
 if len(archive)>limits['archiveBytes']:raise ValueError('SOURCE_ARCHIVE_BUDGET')
 return archive
