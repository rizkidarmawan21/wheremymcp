import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile, rename, rm, readdir, stat, lstat, copyFile, open } from 'node:fs/promises';
import { join, dirname, resolve, sep } from 'node:path';
import { mkdirSync, chmodSync, constants } from 'node:fs';
import { isIP } from 'node:net';
import { z } from 'zod';
import { isAllowedAddress } from './gateway/network.js';
import Database from 'better-sqlite3';
import type { FastifyInstance, preHandlerHookHandler } from 'fastify';
import { SCHEMA_VERSION, type Hub } from './core.js';
import { importSkill, listSkills, approveSkill } from './skills.js';

const BACKUP_FORMAT=1;
const digest=(bytes:Buffer)=>createHash('sha256').update(bytes).digest('hex');
function backupKey(key:Buffer,salt:Buffer) { if(key.length!==32) throw new Error('Master key must contain 32 raw bytes'); return Buffer.from(hkdfSync('sha256',key,salt,'unifymcp-backup-v1',32)); }
function acquireSQLiteLease(dataDir:string,name:string):()=>void {
  mkdirSync(dataDir,{recursive:true,mode:0o700});const file=join(dataDir,name);
  const lease=new Database(file,{timeout:0});
  try {
    chmodSync(file,0o600);lease.pragma('journal_mode=DELETE');lease.exec('CREATE TABLE IF NOT EXISTS lease(id INTEGER PRIMARY KEY)');lease.exec('BEGIN EXCLUSIVE');
  }catch(error){lease.close();throw new Error(`Instance or maintenance lease is busy: ${name}`,{cause:error});}
  let released=false;return ()=>{if(released)return;released=true;try{lease.exec('ROLLBACK');}finally{lease.close();}};
}
export function acquireRuntimeLease(dataDir:string):()=>void {return acquireSQLiteLease(dataDir,'runtime-lease.sqlite');}
export async function withOperationLock<T>(dataDir:string,offline:boolean,fn:()=>Promise<T>):Promise<T> {
  const releaseOperation=acquireSQLiteLease(dataDir,'operations-lease.sqlite');let releaseRuntime:(()=>void)|undefined;
  try {if(offline)releaseRuntime=acquireRuntimeLease(dataDir);return await fn();}
  finally{releaseRuntime?.();releaseOperation();}
}
export async function createEncryptedBackup(hub:Hub) {
  return withOperationLock(hub.config.dataDir,false,async()=>{
    const dir=join(hub.config.dataDir,'backups'); await mkdir(dir,{recursive:true,mode:0o700});
    const scratch=join(dir,`.snapshot-${randomUUID()}`); const name=`backup-${Date.now()}-${randomUUID()}.umcp`;
    try {
      await hub.db.backup(scratch); const bytes=await readFile(scratch); const manifest={format:BACKUP_FORMAT,created_at:Date.now(),schema_version:(hub.db.prepare('SELECT max(version) AS version FROM schema_migration').get() as {version:number}).version,sha256:digest(bytes)};
      const salt=randomBytes(32),iv=randomBytes(12); const key=await readFile(hub.config.masterKeyFile); if(!hub.key.equals(key))throw new Error('Master key changed; reopen the database before backing up'); const cipher=createCipheriv('aes-256-gcm',backupKey(key,salt),iv); cipher.setAAD(Buffer.from(JSON.stringify(manifest)));
      const ciphertext=Buffer.concat([cipher.update(bytes),cipher.final()]); const payload=JSON.stringify({manifest,salt:salt.toString('base64'),iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')});
      await writeFile(join(dir,`${name}.tmp`),payload,{flag:'wx',mode:0o600}); await rename(join(dir,`${name}.tmp`),join(dir,name)); hub.audit({action:'backup.create',resource:name});
      return {name,created_at:manifest.created_at,size:Buffer.byteLength(payload)};
    }finally{await rm(scratch,{force:true});}
  });
}
function validateDatabase(path:string) {
  const db=new Database(path); try {
    if(db.pragma('integrity_check',{simple:true})!=='ok') throw new Error('SQLite integrity check failed');
    const version=db.prepare('SELECT max(version) FROM schema_migration').pluck().get(); if(typeof version!=='number'||version<1||version>SCHEMA_VERSION) throw new Error('Unsupported backup schema version');
    const required:Record<string,string>={
      owner:'id,password_hash,totp_secret,mfa_enabled,last_totp_step,created_at',session:'id,token_hash,csrf_hash,csrf_token,created_at,last_used,expires_at',
      recovery_code:'hash',profile:'id,name,slug,is_default,created_at',client:'id,name,kind,profile_id,token_hash,status,expires_at,created_at,last_used',
      connection:'id,provider,alias,status,identity,scopes,credential,config,expires_at,created_at',oauth_state:'id,connection_id,verifier,session_id,expires_at',
      upstream:'id,name,url,connection_id,status,allowed_private_ips,timeout_ms,created_at',tool:'id,upstream_id,name,gateway_name,description,input_schema,annotations,fingerprint,approved_fingerprint,risk,enabled',
      profile_grant:'profile_id,tool_id,connection_id,action_class',approval:'id,client_id,tool_id,arguments_hash,expires_at,used_at',
      audit_event:'id,ts,principal,action,resource,outcome,detail,latency_ms',skill:'id,name,source,digest,content,approved,created_at',settings:'key,value',schema_migration:'version,applied_at',
    };
    for(const [table,columns] of Object.entries(required))db.prepare(`SELECT ${columns} FROM ${table} LIMIT 0`).all();
    if(version>=2)db.prepare('SELECT profile_id,account_id,account_alias FROM audit_event LIMIT 0').all();
    if((db.pragma('foreign_key_check') as unknown[]).length)throw new Error('Backup foreign-key integrity check failed');
    return db;
  }catch(e){db.close();throw e;}
}
export async function restoreBackup(file:string,key:Buffer,target:string,options:{invalidateClients?:boolean;invalidateSessions?:boolean}={}) {
  const destination=resolve(target);await mkdir(destination,{recursive:true,mode:0o700});
  if((await lstat(destination)).isSymbolicLink())throw new Error('Symlink restore target rejected');
  return withOperationLock(destination,true,async()=>{
    if((await readdir(destination)).some(name=>!['operations-lease.sqlite','runtime-lease.sqlite'].includes(name)))throw new Error('Restore requires an empty directory');
    const envelope=JSON.parse(await readFile(file,'utf8'));
    if(envelope.manifest?.format!==BACKUP_FORMAT||!Number.isInteger(envelope.manifest.schema_version)||envelope.manifest.schema_version<1||envelope.manifest.schema_version>SCHEMA_VERSION)throw new Error('Unsupported backup format/schema');
    const decipher=createDecipheriv('aes-256-gcm',backupKey(key,Buffer.from(envelope.salt,'base64')),Buffer.from(envelope.iv,'base64'));
    decipher.setAAD(Buffer.from(JSON.stringify(envelope.manifest)));decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));
    const bytes=Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext,'base64')),decipher.final()]);if(digest(bytes)!==envelope.manifest.sha256)throw new Error('Backup digest mismatch');
    const scratch=join(destination,`.restore-${randomUUID()}`);
    try {
      await writeFile(scratch,bytes,{mode:0o600,flag:'wx'});const db=validateDatabase(scratch);
      try {db.transaction(()=>{
        if(options.invalidateSessions!==false){db.prepare('DELETE FROM session').run();db.prepare('DELETE FROM oauth_state').run();}
        if(options.invalidateClients)db.prepare("UPDATE client SET status='revoked'").run();
      })();db.pragma('wal_checkpoint(TRUNCATE)');}finally{db.close();}
      const handle=await open(scratch,'r');try{await handle.sync();}finally{await handle.close();}
      await rename(scratch,join(destination,'hub.sqlite'));await syncDir(destination);
      return {target:destination,sessions_invalidated:options.invalidateSessions!==false,clients_invalidated:!!options.invalidateClients};
    }finally{await rm(scratch,{force:true});await rm(`${scratch}-wal`,{force:true});await rm(`${scratch}-shm`,{force:true});}
  });
}
async function durableWrite(path:string,data:string|Buffer) {
  const file=await open(path,'wx',0o600); try {await file.writeFile(data);await file.sync();}finally{await file.close();}
}
async function syncDir(path:string) {const file=await open(path,'r');try{await file.sync();}finally{await file.close();}}
type RotationJournal={format:1;old_db:string;new_db:string;old_key:string;new_key:string;master_key:string};
export async function recoverMasterKeyRotation(config:Hub['config']) {
  return withOperationLock(config.dataDir,true,async()=>{
    const journalPath=join(config.dataDir,'rotation.pending.json'); const journal=JSON.parse(await readFile(journalPath,'utf8')) as RotationJournal;
    if(journal.format!==1||journal.master_key!==config.masterKeyFile)throw new Error('Invalid rotation recovery journal');
    const {Hub:HubClass}=await import('./core.js'); const key=await readFile(journal.old_key);const check=new HubClass(journal.old_db,key,config);check.close();
    const dbTemp=join(config.dataDir,`.recover-${randomUUID()}`); const keyTemp=`${config.masterKeyFile}.recover-${randomUUID()}`;
    await copyFile(journal.old_db,dbTemp);await durableWrite(keyTemp,key);
    await rm(join(config.dataDir,'hub.sqlite-wal'),{force:true});await rm(join(config.dataDir,'hub.sqlite-shm'),{force:true});
    await rename(dbTemp,join(config.dataDir,'hub.sqlite'));await syncDir(config.dataDir);await rename(keyTemp,config.masterKeyFile);await syncDir(dirname(config.masterKeyFile));
    await rm(journalPath);await syncDir(config.dataDir);return {recovered:true};
  });
}
export async function rotateMasterKey(hub:Hub,newKeyFile:string) {
  return withOperationLock(hub.config.dataDir,true,async()=>{
    const oldKey=await readFile(hub.config.masterKeyFile);if(!hub.key.equals(oldKey))throw new Error('Master key changed; reopen the database before rotation'); const newKey=await readFile(newKeyFile); if(newKey.length!==32||oldKey.equals(newKey)) throw new Error('Distinct 32-byte new key required');
    const {Hub:HubClass}=await import('./core.js'); const id=randomUUID();
    const recovery=join(hub.config.dataDir,`rotation-recovery-${id}`);await mkdir(recovery,{mode:0o700});
    // Recovery keys live outside the data directory, including when a legacy key path is inside it.
    const recoveryKeys=join(dirname(hub.config.dataDir),`.unifymcp-rotation-keys-${id}`);await mkdir(recoveryKeys,{mode:0o700});
    const oldDb=join(recovery,'old.sqlite'),newDb=join(recovery,'new.sqlite');
    await durableWrite(join(recoveryKeys,'old.key'),oldKey);await durableWrite(join(recoveryKeys,'new.key'),newKey);
    await hub.db.backup(oldDb);await hub.db.backup(newDb);
    const staging=new Database(newDb);staging.prepare("DELETE FROM settings WHERE key='key_check'").run();staging.close();
    const next=new HubClass(newDb,newKey,hub.config);
    try { next.db.transaction(()=>{
      for(const row of hub.db.prepare('SELECT id,credential FROM connection WHERE credential IS NOT NULL').all() as {id:string;credential:string}[]) next.db.prepare('UPDATE connection SET credential=? WHERE id=?').run(next.seal(hub.open(row.credential,`connection:${row.id}`),`connection:${row.id}`),row.id);
      const owner=hub.db.prepare('SELECT totp_secret FROM owner WHERE id=1').get() as {totp_secret:string}|undefined; if(owner?.totp_secret) next.db.prepare('UPDATE owner SET totp_secret=? WHERE id=1').run(next.seal(hub.open(owner.totp_secret,'owner:totp'),'owner:totp'));
      for(const row of hub.db.prepare('SELECT id,verifier FROM oauth_state WHERE verifier IS NOT NULL').all() as {id:string;verifier:string}[]) next.db.prepare('UPDATE oauth_state SET verifier=? WHERE id=?').run(next.seal(hub.open(row.verifier,`oauth:${row.id}`),`oauth:${row.id}`),row.id);
      for(const row of hub.db.prepare('SELECT id,csrf_token FROM session WHERE csrf_token IS NOT NULL').all() as {id:string;csrf_token:string}[]) next.db.prepare('UPDATE session SET csrf_token=? WHERE id=?').run(next.seal(hub.open(row.csrf_token,`csrf:${row.id}`),`csrf:${row.id}`),row.id);
    })();next.db.pragma('wal_checkpoint(TRUNCATE)');}finally{next.close();}
    for(const path of [oldDb,newDb]) {const f=await open(path,'r');try{await f.sync();}finally{await f.close();}}
    await syncDir(recovery);await syncDir(recoveryKeys);
    const journal:RotationJournal={format:1,old_db:oldDb,new_db:newDb,old_key:join(recoveryKeys,'old.key'),new_key:join(recoveryKeys,'new.key'),master_key:hub.config.masterKeyFile};
    const journalPath=join(hub.config.dataDir,'rotation.pending.json');await durableWrite(journalPath,JSON.stringify(journal));await syncDir(hub.config.dataDir);
    hub.close();const keyTemp=`${hub.config.masterKeyFile}.rotation-${id}`;await durableWrite(keyTemp,newKey);
    await rm(join(hub.config.dataDir,'hub.sqlite-wal'),{force:true});await rm(join(hub.config.dataDir,'hub.sqlite-shm'),{force:true});
    await rename(newDb,join(hub.config.dataDir,'hub.sqlite'));await syncDir(hub.config.dataDir);
    await rename(keyTemp,hub.config.masterKeyFile);await syncDir(dirname(hub.config.masterKeyFile));
    await rm(journalPath);await syncDir(hub.config.dataDir);
    return {recovery_directory:recovery,recovery_keys_directory:recoveryKeys};
  });
}
const idSchema=z.string().uuid();
const publicConnectionConfig=z.object({client_id:z.string().max(512).optional(),issuer:z.string().url().max(2048).optional(),resource:z.string().url().max(2048).optional(),header_name:z.string().regex(/^[a-zA-Z0-9-]{1,80}$/).refine(s=>!/^(host|cookie|content-|mcp-|proxy-|connection|transfer-|accept|origin|forwarded|x-forwarded)/i.test(s)).optional(),allowed_origin:z.string().url().max(2048).optional(),broad_scope_acknowledged:z.boolean().optional()}).strict();
const portableConfigSchema=z.object({
  format:z.literal(2),exported_at:z.number().int().nonnegative().optional(),
  profiles:z.array(z.object({id:idSchema,name:z.string().min(1).max(100),slug:z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/),is_default:z.union([z.literal(0),z.literal(1)])}).strict()).max(100),
  connections:z.array(z.object({id:idSchema,provider:z.enum(['api_key','bearer','github','google','slack','remote_oauth']),alias:z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/),identity:z.string().max(200),scopes:z.array(z.string().min(1).max(200)).max(100),config:publicConnectionConfig}).strict()).max(100),
  upstreams:z.array(z.object({id:idSchema,name:z.string().min(1).max(100),url:z.string().max(2048),connection_id:idSchema.nullable(),allowed_private_ips:z.array(z.string().max(45)).max(16),timeout_ms:z.number().int().min(100).max(60000)}).strict()).max(100),
  tools:z.array(z.object({id:idSchema,upstream_id:idSchema,name:z.string().regex(/^[a-zA-Z0-9_.:-]{1,128}$/),gateway_name:z.string().regex(/^[a-zA-Z0-9_.:-]{1,200}$/),description:z.string().max(12000),input_schema:z.record(z.string(),z.unknown()),annotations:z.record(z.string(),z.unknown()),fingerprint:z.string().regex(/^[a-f0-9]{64}$/),risk:z.enum(['read','write','delete','unreviewed'])}).strict()).max(256),
  grants:z.array(z.object({profile_id:idSchema,tool_id:idSchema,connection_id:idSchema.nullable(),action_class:z.enum(['read','write','delete'])}).strict()).max(2000),
  skills:z.array(z.object({id:idSchema,name:z.string().min(1).max(100),source:z.string().min(1).max(500),digest:z.string().regex(/^[a-f0-9]{64}$/),files:z.record(z.string(),z.string())}).strict()).max(100),
}).strict();
function configError(message:string,statusCode=400):never{throw Object.assign(new Error(message),{statusCode});}
export function exportConfig(hub:Hub) {
  return {
    format:2 as const,exported_at:Date.now(),profiles:hub.db.prepare('SELECT id,name,slug,is_default FROM profile').all(),
    connections:(hub.db.prepare('SELECT id,provider,alias,identity,scopes,config FROM connection').all() as any[]).map(row=>({...row,scopes:JSON.parse(row.scopes),config:publicConnectionConfig.parse(JSON.parse(row.config))})),
    upstreams:(hub.db.prepare('SELECT id,name,url,connection_id,allowed_private_ips,timeout_ms FROM upstream').all() as any[]).map(row=>({...row,allowed_private_ips:JSON.parse(row.allowed_private_ips)})),
    tools:(hub.db.prepare('SELECT id,upstream_id,name,gateway_name,description,input_schema,annotations,fingerprint,risk FROM tool').all() as any[]).map(row=>({...row,input_schema:JSON.parse(row.input_schema),annotations:JSON.parse(row.annotations)})),
    grants:hub.db.prepare('SELECT profile_id,tool_id,connection_id,action_class FROM profile_grant').all(),
    skills:listSkills(hub).map(({id,name,source,digest,files})=>({id,name,source,digest,files})),
  };
}
function validateImportTarget(input:string,allowed:string[]) {
  if(allowed.some(ip=>!isIP(ip)||!isAllowedAddress(ip,[ip])))configError('Invalid private-address exception');
  let url:URL;try{url=new URL(input);}catch{configError('Invalid upstream URL');}
  if(!['https:','http:'].includes(url.protocol)||url.username||url.password||url.hash||url.search)configError('Unsafe upstream URL');
  const hostname=url.hostname.replace(/^\[|\]$/g,'');
  if(isIP(hostname)&&!isAllowedAddress(hostname,allowed))configError('Blocked upstream address');
  if(url.protocol!=='https:'&&(!isIP(hostname)||!allowed.some(ip=>new URL(`http://${isIP(ip)===6?'['+ip+']':ip}`).hostname===url.hostname)))configError('HTTPS required outside an explicit literal-IP exception');
  if(!isIP(hostname)&&(/(^|\.)(localhost|local|internal|home|test)$/.test(hostname)||hostname.includes('%')))configError('Nonpublic hostname requires an explicit literal-IP exception');
  return url;
}
export function importConfig(hub:Hub,input:unknown) {
  const stack:Array<[unknown,number]>=[[input,0]];let nodes=0;
  while(stack.length){const [value,depth]=stack.pop()!;if(depth>24||++nodes>20000)configError('Config structure exceeds import limits');if(value&&typeof value==='object')for(const item of Object.values(value))stack.push([item,depth+1]);}
  if(Buffer.byteLength(JSON.stringify(input)??'')>900*1024)configError('Config exceeds 900 KiB');
  const config=portableConfigSchema.parse(input);
  const connections=new Map(config.connections.map(row=>[row.id,row]));const upstreams=new Map(config.upstreams.map(row=>[row.id,row]));const tools=new Map(config.tools.map(row=>[row.id,row]));const profiles=new Set(config.profiles.map(row=>row.id));
  for(const c of config.connections){
    if(c.provider==='api_key'&&!c.config.header_name)configError('API key requires a safe header_name');
    if(c.provider==='remote_oauth'){
      if(!c.config.client_id||!c.config.issuer||!c.config.resource||!c.config.allowed_origin)configError('Remote OAuth public metadata is incomplete');
      const issuer=validateImportTarget(c.config.issuer,[]),resource=validateImportTarget(c.config.resource,[]);
      if(issuer.protocol!=='https:'||resource.protocol!=='https:'||resource.origin!==c.config.allowed_origin)configError('Remote OAuth issuer/resource binding mismatch');
    }else if(c.config.issuer||c.config.resource)configError('Unexpected OAuth issuer/resource config');
    if(c.config.allowed_origin){const url=validateImportTarget(c.config.allowed_origin,[]);if(url.protocol!=='https:'||url.origin!==c.config.allowed_origin)configError('Credential scope must be an exact HTTPS origin');}
  }
  for(const u of config.upstreams){
    const connection=u.connection_id?connections.get(u.connection_id):undefined;if(u.connection_id&&!connection)configError('Upstream references a missing imported connection');
    if(u.url.startsWith('native://')){
      if(!connection||!['github','google','slack'].includes(connection.provider)||u.url!==`native://${connection.provider}/${connection.id}`||u.allowed_private_ips.length)configError('Native provider binding mismatch');
    }else {const url=validateImportTarget(u.url,u.allowed_private_ips);if(connection?.config.allowed_origin&&url.origin!==connection.config.allowed_origin)configError('Credential origin mismatch');}
  }
  for(const tool of config.tools)if(!upstreams.has(tool.upstream_id))configError('Tool references a missing imported upstream');
  for(const grant of config.grants){const tool=tools.get(grant.tool_id);const upstream=tool?upstreams.get(tool.upstream_id):undefined;
    if(!profiles.has(grant.profile_id)||!tool||!upstream||grant.connection_id!==upstream.connection_id||grant.action_class!==tool.risk)configError('Grant account, risk or imported profile binding mismatch');
  }
  const imported={profiles:config.profiles.length,connections:config.connections.length,upstreams:config.upstreams.length,tools:config.tools.length,grants:config.grants.length,skills:config.skills.length};
  const demoted=config.profiles.filter(p=>p.is_default).map(p=>p.id);const now=Date.now();
  hub.db.transaction(()=>{
    for(const [table,rows] of [['profile',config.profiles],['connection',config.connections],['upstream',config.upstreams],['tool',config.tools],['skill',config.skills]] as const){
      const seen=new Set<string>();for(const row of rows){if(seen.has(row.id)||hub.db.prepare(`SELECT id FROM ${table} WHERE id=?`).get(row.id))configError('Config ID collision',409);seen.add(row.id);}
    }
    for(const p of config.profiles){const slug=p.is_default?`imported-default-${p.id}`:p.slug;if(hub.db.prepare('SELECT id FROM profile WHERE slug=?').get(slug))configError('Config profile slug collision',409);hub.db.prepare('INSERT INTO profile(id,name,slug,is_default,created_at) VALUES(?,?,?,0,?)').run(p.id,p.name,slug,now);}
    for(const c of config.connections){if(hub.db.prepare('SELECT id FROM connection WHERE alias=?').get(c.alias))configError('Config connection alias collision',409);hub.db.prepare('INSERT INTO connection(id,provider,alias,status,identity,scopes,credential,config,created_at) VALUES(?,?,?,?,?,?,NULL,?,?)').run(c.id,c.provider,c.alias,'not_configured',c.identity,JSON.stringify(c.scopes),JSON.stringify(c.config),now);}
    for(const u of config.upstreams){hub.db.prepare('INSERT INTO upstream(id,name,url,connection_id,status,allowed_private_ips,timeout_ms,created_at) VALUES(?,?,?,?,?,?,?,?)').run(u.id,u.name,u.url,u.connection_id,'registered',JSON.stringify(u.allowed_private_ips),u.timeout_ms,now);hub.setSetting(`import_requires_refresh:${u.id}`,'true');}
    for(const t of config.tools){if(hub.db.prepare('SELECT id FROM tool WHERE gateway_name=? OR (upstream_id=? AND name=?)').get(t.gateway_name,t.upstream_id,t.name))configError('Config tool name collision',409);hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,description,input_schema,annotations,fingerprint,approved_fingerprint,risk,enabled) VALUES(?,?,?,?,?,?,?,?,NULL,?,0)').run(t.id,t.upstream_id,t.name,t.gateway_name,t.description,JSON.stringify(t.input_schema),JSON.stringify(t.annotations),t.fingerprint,t.risk);}
    for(const g of config.grants)hub.db.prepare('INSERT INTO profile_grant(profile_id,tool_id,connection_id,action_class) VALUES(?,?,?,?)').run(g.profile_id,g.tool_id,g.connection_id,g.action_class);
    for(const skill of config.skills){const row=importSkill(hub,{name:skill.name,source:skill.source,files:skill.files});if(row.digest!==skill.digest)configError('Imported skill digest mismatch');hub.db.prepare('UPDATE skill SET id=? WHERE id=?').run(skill.id,row.id);}
    hub.audit({action:'config.import',principal:'owner'});
  })();
  return {imported,reauthorization_required:true,review_required:true,default_profiles_demoted:demoted};
}
const stepUpSchema=z.object({password:z.string().min(1).max(1024),totp:z.string().max(10).optional()}).strict();

export async function registerOperations(app:FastifyInstance,hub:Hub,requireOwner:preHandlerHookHandler) {
  app.get('/api/v1/backups',{preHandler:requireOwner},async()=>{const dir=join(hub.config.dataDir,'backups');let names:string[]=[];try{names=await readdir(dir);}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}return {backups:await Promise.all(names.filter(n=>/^backup-[\w-]+\.umcp$/.test(n)).map(async name=>{const s=await stat(join(dir,name));return {name,size:s.size,created_at:s.mtimeMs};}))};});
  app.post('/api/v1/backup/create',{preHandler:requireOwner},async(req,reply)=>{const body=req.body as {password?:string;totp?:string};if(!body?.password||!await hub.verifyStepUp(body.password,body.totp))return reply.code(403).send({error:'step_up_required',message:'Password and MFA verification required',request_id:req.id});return createEncryptedBackup(hub);});
  app.get('/api/v1/config/export',{preHandler:requireOwner},async()=>exportConfig(hub));
  app.post('/api/v1/config/import',{preHandler:requireOwner},async(req,reply)=>{
    const body=z.object({password:z.string().min(1).max(1024),totp:z.string().max(10).optional(),config:z.unknown()}).strict().parse(req.body);
    if(!await hub.verifyStepUp(body.password,body.totp))return reply.code(403).send({error:'step_up_required',message:'Password and MFA verification required',request_id:req.id});
    return withOperationLock(hub.config.dataDir,false,async()=>importConfig(hub,body.config));
  });
  app.post<{Params:{name:string}}>('/api/v1/backups/:name/download',{preHandler:requireOwner},async(req,reply)=>{
    const body=stepUpSchema.parse(req.body);
    if(!await hub.verifyStepUp(body.password,body.totp))return reply.code(403).send({error:'step_up_required',message:'Password and MFA verification required',request_id:req.id});
    const name=req.params.name;if(!/^backup-[\w-]+\.umcp$/.test(name))return reply.code(404).send({error:'not_found',message:'Backup not found',request_id:req.id});
    const directory=resolve(hub.config.dataDir,'backups'),path=resolve(directory,name);
    if(!path.startsWith(directory+sep))return reply.code(404).send({error:'not_found',message:'Backup not found',request_id:req.id});
    let file;try{file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const info=await file.stat();if(!info.isFile())throw new Error();
      hub.audit({action:'backup.download',principal:'owner',resource:name});const stream=file.createReadStream();file=undefined;return reply.type('application/octet-stream').header('content-disposition',`attachment; filename="${name}"`).send(stream);
    }catch{return reply.code(404).send({error:'not_found',message:'Backup not found',request_id:req.id});}finally{await file?.close();}
  });
  app.get('/api/v1/skills',{preHandler:requireOwner},async()=>({skills:listSkills(hub)}));
  app.post('/api/v1/skills',{preHandler:requireOwner},async(req,reply)=>{try{return importSkill(hub,req.body as Parameters<typeof importSkill>[1]);}catch{return reply.code(400).send({error:'invalid_skill',message:'Invalid skill file map or metadata',request_id:req.id});}});
  app.post<{Params:{id:string}}>('/api/v1/skills/:id/approve',{preHandler:requireOwner},async req=>{approveSkill(hub,req.params.id);return {approved:true};});
  app.delete<{Params:{id:string}}>('/api/v1/skills/:id',{preHandler:requireOwner},async req=>{hub.db.prepare('DELETE FROM skill WHERE id=?').run(req.params.id);hub.audit({action:'skill.delete',resource:req.params.id});return {deleted:true};});
}
