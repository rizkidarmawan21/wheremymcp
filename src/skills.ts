import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, realpath, readFile, mkdir, open, rename, rm } from 'node:fs/promises';
import { resolve, join, dirname, isAbsolute } from 'node:path';
import type { Hub } from './core.js';

export type FileMap = Record<string,string>;
type SkillRow = {id:string;name:string;source:string;digest:string;content:string;approved:number;created_at:number};
export type SyncPlan = {skill_id:string;digest:string;target:string;backup_dir:string;changes:{path:string;before:string|null;after:string}[]};
const hash = (s:string|Buffer) => createHash('sha256').update(s).digest('hex');
function filesDigest(files:FileMap) { return hash(JSON.stringify(Object.entries(files).sort(([a],[b])=>a<b?-1:a>b?1:0))); }
function validateFiles(input:unknown): FileMap {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('files must be a file map');
  const files=input as FileMap; const entries=Object.entries(files);
  if (!Object.hasOwn(files,'SKILL.md') || entries.length>256) throw new Error('SKILL.md required; maximum 256 files');
  let bytes=0;
  for (const [path,content] of entries) {
    if (!path || path.length>240 || isAbsolute(path) || path.includes('\\') || path.includes(':') || path.includes('\0') || path.split('/').some(p=>!p||p==='.'||p==='..'||p==='.unifymcp-backups')) throw new Error('Unsafe skill path');
    if(typeof content!=='string') throw new Error('Skill content must be text'); bytes+=Buffer.byteLength(content);
  }
  if(bytes>1024*1024) throw new Error('Skill exceeds 1 MiB'); return files;
}
export function importSkill(hub:Hub,input:{name:string;source:string;files:FileMap}) {
  if(typeof input.name!=='string'||!input.name.trim()||input.name.length>100||typeof input.source!=='string'||!input.source.trim()||input.source.length>500) throw new Error('name and pinned source metadata required');
  const files=validateFiles(input.files); const row={id:randomUUID(),name:input.name,source:input.source,digest:filesDigest(files),approved:0,created_at:Date.now()};
  hub.db.prepare('INSERT INTO skill(id,name,source,digest,content,approved,created_at) VALUES (@id,@name,@source,@digest,@content,@approved,@created_at)').run({...row,content:JSON.stringify(files)});
  hub.audit({action:'skill.import',resource:row.id}); return {...row,files,hashes:Object.fromEntries(Object.entries(files).map(([path,text])=>[path,hash(text)]))};
}
export function listSkills(hub:Hub) { return (hub.db.prepare('SELECT * FROM skill ORDER BY created_at DESC').all() as SkillRow[]).map(({content,...row})=>({...row,files:JSON.parse(content),hashes:Object.fromEntries(Object.entries(JSON.parse(content) as FileMap).map(([path,text])=>[path,hash(text)]))})); }
export function approveSkill(hub:Hub,id:string) { const result=hub.db.prepare('UPDATE skill SET approved=1 WHERE id=?').run(id); if(!result.changes) throw new Error('Skill not found'); hub.audit({action:'skill.approve',resource:id}); }
async function checkPath(root:string,relative:string) {
  const parts=relative.split('/'); let cursor=root;
  for (let i=0;i<parts.length;i++) { cursor=join(cursor,parts[i]!); try { const stat=await lstat(cursor); if(stat.isSymbolicLink()||(!stat.isDirectory()&&i<parts.length-1)||(!stat.isFile()&&i===parts.length-1)) throw new Error('Unsafe sync target'); } catch(e) { if((e as NodeJS.ErrnoException).code!=='ENOENT') throw e; } }
}
async function canonicalRoot(target:string) {
  if(!isAbsolute(target)) throw new Error('Explicit absolute target root required');
  const path=resolve(target); if((await lstat(path)).isSymbolicLink()) throw new Error('Symlink target root rejected');
  if(!(await lstat(path)).isDirectory()) throw new Error('Target must be a directory'); return realpath(path);
}
export async function planSkillSync(hub:Hub,id:string,target:string):Promise<SyncPlan> {
  const row=hub.db.prepare('SELECT * FROM skill WHERE id=?').get(id) as SkillRow|undefined;
  if(!row?.approved) throw new Error('Reviewed approval required');
  const files=validateFiles(JSON.parse(row.content)); if(filesDigest(files)!==row.digest) throw new Error('Skill digest mismatch');
  const root=await canonicalRoot(target); const changes:SyncPlan['changes']=[];
  for(const [path,after] of Object.entries(files)) { await checkPath(root,path); let before:string|null=null; try { before=await readFile(join(root,path),'utf8'); } catch(e) { if((e as NodeJS.ErrnoException).code!=='ENOENT') throw e; } if(before!==after) changes.push({path,before,after}); }
  return {skill_id:id,digest:row.digest,target:root,backup_dir:`.unifymcp-backups/${Date.now()}-${randomUUID()}`,changes};
}
export async function applySkillSync(hub:Hub,preview:SyncPlan) {
  const fresh=await planSkillSync(hub,preview.skill_id,preview.target);
  if(fresh.digest!==preview.digest||JSON.stringify(fresh.changes)!==JSON.stringify(preview.changes)) throw new Error('Sync preview is stale; review a new plan');
  // Recompute backup paths rather than trusting a saved plan supplied by the caller.
  const backupDir=fresh.backup_dir; preview.backup_dir=backupDir;
  for(const change of fresh.changes) {
    await checkPath(fresh.target,change.path);
    if(change.before!==null) { const backup=join(fresh.target,backupDir,change.path); await checkPath(fresh.target,`${backupDir}/${change.path}`); await mkdir(dirname(backup),{recursive:true,mode:0o700}); const handle=await open(backup,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600); try {await handle.writeFile(change.before);}finally{await handle.close();} }
    const path=join(fresh.target,change.path); await mkdir(dirname(path),{recursive:true,mode:0o700}); await checkPath(fresh.target,change.path);
    const temp=join(dirname(path),`.unifymcp-sync-${randomUUID()}`);
    try {const handle=await open(temp,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);try{await handle.writeFile(change.after);await handle.sync();}finally{await handle.close();}await checkPath(fresh.target,change.path);await rename(temp,path);}finally{await rm(temp,{force:true});}
  }
  hub.audit({action:'skill.sync',resource:preview.skill_id}); return {written:fresh.changes.length,backup_dir:backupDir};
}
