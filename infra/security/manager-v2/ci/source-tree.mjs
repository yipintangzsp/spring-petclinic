// Exact Git tree reconstruction from verified blob bytes. No network or scanner.
import fs from 'node:fs';import path from 'node:path';import {createHash}from'node:crypto';import {digest}from'../../summary-v2/codec.mjs';
const oid=(kind,b)=>createHash('sha1').update(kind+' '+b.length+'\0').update(b).digest('hex');
export function verifySourceTree(sourceDir,entries,expectedTree,limits,uid){
 if(!entries||Object.keys(entries).length>limits.files)throw Error('SOURCE_TREE_BUDGET');
 const root=Object.create(null);const manifest=[];let bytes=0;const seen=new Set();
 for(const [relative,e]of Object.entries(entries)){
  if(relative.split('/').some(p=>!p||['.','..','.git'].includes(p))||relative.includes('\\')||path.isAbsolute(relative)||!['100644','100755'].includes(e.mode)||!/^[a-f0-9]{40}$/.test(e.oid))throw Error('SOURCE_TREE_ENTRY');
  const f=path.join(sourceDir,relative),s=fs.lstatSync(f);if(!s.isFile()||s.isSymbolicLink()||s.uid!==uid||(s.mode&0o022)||s.size>(limits.fileOverrides?.[relative]??limits.fileBytes)||fs.realpathSync(f)!==f)throw Error('SOURCE_TREE_FILE');
  const b=fs.readFileSync(f);bytes+=b.length;if(bytes>limits.expandedBytes||oid('blob',b)!==e.oid)throw Error('SOURCE_BLOB_BINDING');
  let node=root;const parts=relative.split('/');for(const part of parts.slice(0,-1)){if(node[part]?.oid)throw Error('SOURCE_TREE_COLLISION');node=node[part]??=(Object.create(null));}const name=parts.at(-1);if(node[name])throw Error('SOURCE_TREE_COLLISION');node[name]={oid:e.oid,mode:e.mode};
  seen.add(relative);manifest.push({path:relative,sha256:createHash('sha256').update(b).digest('hex'),bytes:b.length});
 }
 function tree(n){const items=Object.entries(n).map(([name,v])=>({name,mode:v.oid?v.mode:'40000',id:v.oid??tree(v),sort:name+(v.oid?'':'/')})).sort((a,b)=>Buffer.compare(Buffer.from(a.sort),Buffer.from(b.sort)));return oid('tree',Buffer.concat(items.flatMap(e=>[Buffer.from(e.mode+' '+e.name+'\0'),Buffer.from(e.id,'hex')])));}
 if(tree(root)!==expectedTree)throw Error('SOURCE_ROOT_TREE_BINDING');
 function walk(d){for(const e of fs.readdirSync(d,{withFileTypes:true})){const f=path.join(d,e.name);if(e.isDirectory()){const s=fs.lstatSync(f);if(s.uid!==uid||(s.mode&0o022))throw Error('SOURCE_DIRECTORY_BOUNDARY');walk(f);}else if(!e.isFile()||!seen.delete(path.relative(sourceDir,f)))throw Error('SOURCE_UNEXPECTED_ENTRY');}}
 walk(sourceDir);if(seen.size)throw Error('SOURCE_MISSING_FILE');manifest.sort((a,b)=>a.path.localeCompare(b.path));return {fileManifestDigest:digest(manifest),fileCount:manifest.length,expandedBytes:bytes,budgetExceptionHits:manifest.filter(x=>x.bytes>limits.fileBytes).map(x=>({path:x.path,bytes:x.bytes,sha256:x.sha256,gitBlobOid:entries[x.path].oid,limit:limits.fileOverrides?.[x.path]??limits.fileBytes}))};
}
