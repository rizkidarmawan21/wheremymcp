import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, mkdir, writeFile, symlink, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { createEncryptedBackup, restoreBackup, withOperationLock, acquireRuntimeLease } from '../src/backup.js';
import { importSkill, approveSkill, planSkillSync, applySkillSync } from '../src/skills.js';

async function fixture() {
  const {Hub}=await import('../src/core.js');const {loadConfig}=await import('../src/config.js');
  const dir=await mkdtemp(join(tmpdir(),'unifymcp-ops-'));const key=randomBytes(32),keyFile=join(dir,'external.key');await writeFile(keyFile,key,{mode:0o600});
  const config=loadConfig({HUB_DATA_DIR:dir,HUB_MASTER_KEY_FILE:keyFile});const hub=new Hub(join(dir,'hub.sqlite'),key,config);const db=hub.db;
  db.prepare('INSERT INTO connection(id,provider,alias,status,credential,created_at) VALUES(?,?,?,?,?,0)').run('one','bearer','one','connected','secret-canary');
  return {dir,db,key,hub};
}
test('encrypted online backup restores a consistent database; wrong key/tampering rejected',async()=>{
  const {dir,db,key,hub} = await fixture();
  const profileId=db.prepare('SELECT id FROM profile LIMIT 1').pluck().get();
  db.prepare('INSERT INTO client(id,name,kind,profile_id,token_hash,status,created_at) VALUES(?,?,?,?,?,?,0)').run('client','client','codex',profileId,'token-hash','active');
  db.prepare('INSERT INTO session VALUES(?,?,?,?,?,?,?)').run('session','session-hash','csrf-hash',hub.seal('csrf','csrf:session'),0,0,999999);
  db.prepare('INSERT INTO oauth_state VALUES(?,?,?,?,?)').run('state','one',hub.seal('pkce','oauth:state'),'session',999999);
  const backup = await createEncryptedBackup(hub); const bytes = await readFile(join(dir,'backups',backup.name));
  assert.equal(bytes.includes(Buffer.from('secret-canary')),false);
  await assert.rejects(restoreBackup(join(dir,'backups',backup.name),randomBytes(32),join(dir,'wrong')));
  const tampered = JSON.parse(bytes.toString()); tampered.manifest.created_at++;
  await writeFile(join(dir,'tampered'),JSON.stringify(tampered));
  await assert.rejects(restoreBackup(join(dir,'tampered'),key,join(dir,'tampered-target')));
  const target = join(dir,'restore'); await restoreBackup(join(dir,'backups',backup.name),key,target,{invalidateClients:true});
  const restored = new Database(join(target,'hub.sqlite'));
  assert.equal(restored.prepare('SELECT credential FROM connection').pluck().get(),'secret-canary');
  assert.equal(restored.prepare('SELECT count(*) FROM session').pluck().get(),0);assert.equal(restored.prepare('SELECT count(*) FROM oauth_state').pluck().get(),0);assert.equal(restored.prepare('SELECT status FROM client').pluck().get(),'revoked');restored.close();
  const preserved=join(dir,'preserved');await restoreBackup(join(dir,'backups',backup.name),key,preserved,{invalidateSessions:false});
  const kept=new Database(join(preserved,'hub.sqlite'));assert.equal(kept.prepare('SELECT count(*) FROM session').pluck().get(),1);assert.equal(kept.prepare('SELECT status FROM client').pluck().get(),'active');kept.close();
  await assert.rejects(restoreBackup(join(dir,'backups',backup.name),key,target)); db.close();
});
test('operations lock excludes concurrent mutations and offline mode rejects runtime',async()=>{
  const {dir,db} = await fixture();
  await withOperationLock(dir,false,async()=>{ await assert.rejects(withOperationLock(dir,false,async()=>{})); });
  const release=acquireRuntimeLease(dir);
  await assert.rejects(withOperationLock(dir,true,async()=>{})); release();await withOperationLock(dir,true,async()=>{});db.close();
});
test('reviewed skills require approval, pin digest, preview before apply and backup changed originals',async()=>{
  const {dir,hub,db}=await fixture(); const target=join(dir,'target'); await mkdir(target);
  const skill=importSkill(hub,{name:'example',source:'manual:reviewed@abc123',files:{'SKILL.md':'# Example','data/a.txt':'hello'}});
  await assert.rejects(planSkillSync(hub,skill.id,target)); approveSkill(hub,skill.id);
  const plan=await planSkillSync(hub,skill.id,target); assert.equal((await readdir(target)).length,0);
  await applySkillSync(hub,plan); assert.equal(await readFile(join(target,'SKILL.md'),'utf8'),'# Example');
  await writeFile(join(target,'SKILL.md'),'local'); const change=await planSkillSync(hub,skill.id,target); await applySkillSync(hub,change);
  assert.equal(await readFile(join(target,change.backup_dir,'SKILL.md'),'utf8'),'local'); db.close();
});
test('skill traversal, absolute paths, hooks metadata and symlink targets are rejected',async()=>{
  const {dir,hub,db}=await fixture();
  for(const path of ['../escape','/tmp/escape','a/../../escape','C:\\escape','a\\..\\escape','.unifymcp-backups/x']) {
    assert.throws(()=>importSkill(hub,{name:'bad',source:'manual',files:{'SKILL.md':'x',[path]:'bad'}}));
  }
  const skill=importSkill(hub,{name:'safe',source:'manual',files:{'SKILL.md':'# Safe','nested/file':'x'}}); approveSkill(hub,skill.id);
  const target=join(dir,'target'); const outside=join(dir,'outside'); await mkdir(target); await mkdir(outside); await symlink(outside,join(target,'nested'));
  await assert.rejects(planSkillSync(hub,skill.id,target)); db.close();
});

test('offline rotation preserves credential, TOTP, OAuth and CSRF contexts with a new external key',async()=>{
  const {Hub}=await import('../src/core.js');const {loadConfig}=await import('../src/config.js');
  const {rotateMasterKey}=await import('../src/backup.js');
  const dir=await mkdtemp(join(tmpdir(),'unifymcp-rotate-'));const keyFile=join(dir,'old.key');const nextFile=join(dir,'next.key');
  const key=randomBytes(32),nextKey=randomBytes(32);await writeFile(keyFile,key);await writeFile(nextFile,nextKey);
  const dataDir=join(dir,'data');await mkdir(dataDir);const config=loadConfig({HUB_DATA_DIR:dataDir,HUB_MASTER_KEY_FILE:keyFile});
  const hub=new Hub(join(dataDir,'hub.sqlite'),key,config);
  hub.db.prepare('INSERT INTO owner(id,password_hash,totp_secret,mfa_enabled,created_at) VALUES(1,?,?,1,0)').run('hash',hub.seal('totp-secret','owner:totp'));
  hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,created_at) VALUES(?,?,?,?,?,0)').run('one','bearer','one','active',hub.seal('credential-secret','connection:one'));
  hub.db.prepare('INSERT INTO session VALUES(?,?,?,?,?,?,?)').run('sess','hash','csrf-hash',hub.seal('csrf-secret','csrf:sess'),0,0,999999);
  hub.db.prepare('INSERT INTO oauth_state VALUES(?,?,?,?,?)').run('state','one',hub.seal('oauth-secret','oauth:state'),'sess',999999);
  await rotateMasterKey(hub,nextFile);assert.deepEqual(await readFile(keyFile),nextKey);
  const restored=new Hub(join(dataDir,'hub.sqlite'),nextKey,config);
  assert.equal(restored.open((restored.db.prepare('SELECT credential FROM connection').get() as any).credential,'connection:one'),'credential-secret');
  assert.equal(restored.open((restored.db.prepare('SELECT totp_secret FROM owner').get() as any).totp_secret,'owner:totp'),'totp-secret');
  assert.equal(restored.open((restored.db.prepare('SELECT verifier FROM oauth_state').get() as any).verifier,'oauth:state'),'oauth-secret');
  assert.equal(restored.open((restored.db.prepare('SELECT csrf_token FROM session').get() as any).csrf_token,'csrf:sess'),'csrf-secret');restored.close();
  assert.throws(()=>new Hub(join(dataDir,'hub.sqlite'),key,config));
});

test('changed registry content and stale disk previews cannot silently alter an approved sync',async()=>{
  const {dir,hub,db}=await fixture();const target=join(dir,'target');await mkdir(target);
  const skill=importSkill(hub,{name:'pin',source:'manual:commit123',files:{'SKILL.md':'reviewed'}});approveSkill(hub,skill.id);
  const plan=await planSkillSync(hub,skill.id,target);await writeFile(join(target,'SKILL.md'),'concurrent edit');
  await assert.rejects(applySkillSync(hub,plan),/stale/);assert.equal(await readFile(join(target,'SKILL.md'),'utf8'),'concurrent edit');
  db.prepare('UPDATE skill SET content=? WHERE id=?').run(JSON.stringify({'SKILL.md':'tampered'}),skill.id);
  await assert.rejects(planSkillSync(hub,skill.id,target),/digest/);db.close();
});
test('backup rejects changed key file rather than wrapping an old vault with a new key',async()=>{
  const {hub,db}=await fixture();await writeFile(hub.config.masterKeyFile,randomBytes(32));
  await assert.rejects(createEncryptedBackup(hub),/key changed/);db.close();
});

test('kernel-backed leases release after a killed process and ignore stale PID diagnostics',async()=>{
  const {spawn}=await import('node:child_process');const {once}=await import('node:events');
  const {pathToFileURL}=await import('node:url');
  const dir=await mkdtemp(join(tmpdir(),'unifymcp-lease-'));
  const moduleUrl=new URL('../src/backup.ts',import.meta.url).href;
  const script=`import {acquireRuntimeLease} from ${JSON.stringify(moduleUrl)};acquireRuntimeLease(${JSON.stringify(dir)});console.log('locked');setInterval(()=>{},1000);`;
  const child=spawn(process.execPath,['--import','tsx','--input-type=module','-e',script],{stdio:['ignore','pipe','pipe']});
  const exited=once(child,'exit');try {
    await Promise.race([once(child.stdout,'data'),exited.then(()=>{throw new Error('Lease child failed to start');})]);
    assert.throws(()=>acquireRuntimeLease(dir),/busy/);await assert.rejects(withOperationLock(dir,true,async()=>{}),/busy/);
    child.kill('SIGKILL');await exited;
    await writeFile(join(dir,'runtime.lock'),'1');const release=acquireRuntimeLease(dir);release();
    await withOperationLock(dir,true,async()=>{});
  }finally{if(child.exitCode===null&&!child.killed)child.kill('SIGKILL');}
});
test('interrupted rotation recovery restores the retained DB and original external key',async()=>{
  const {Hub}=await import('../src/core.js');const {loadConfig}=await import('../src/config.js');const {recoverMasterKeyRotation}=await import('../src/backup.js');
  const dir=await mkdtemp(join(tmpdir(),'unifymcp-recover-'));const dataDir=join(dir,'data');await mkdir(dataDir);const keyFile=join(dir,'master.key');const oldKeyFile=join(dir,'old.key');const key=randomBytes(32);
  await writeFile(keyFile,key);await writeFile(oldKeyFile,key);const config=loadConfig({HUB_DATA_DIR:dataDir,HUB_MASTER_KEY_FILE:keyFile});
  const hub=new Hub(join(dataDir,'hub.sqlite'),key,config);const oldDb=join(dataDir,'old.sqlite');await hub.db.backup(oldDb);hub.close();
  await writeFile(keyFile,randomBytes(32));await writeFile(join(dataDir,'hub.sqlite'),'incomplete swap');
  await writeFile(join(dataDir,'rotation.pending.json'),JSON.stringify({format:1,old_db:oldDb,new_db:'unused',old_key:oldKeyFile,new_key:'unused',master_key:keyFile}));
  await recoverMasterKeyRotation(config);assert.deepEqual(await readFile(keyFile),key);
  const recovered=new Hub(join(dataDir,'hub.sqlite'),key,config);assert.equal(recovered.open(recovered.setting('key_check')!,'system:key-check'),'unifymcp');recovered.close();
});

test('skill sync replaces a hardlinked target without modifying the external inode',async()=>{
  const {link}=await import('node:fs/promises');const {dir,hub,db}=await fixture();const target=join(dir,'target');await mkdir(target);const outside=join(dir,'external');await writeFile(outside,'outside original');await link(outside,join(target,'SKILL.md'));
  const skill=importSkill(hub,{name:'link-safe',source:'manual:reviewed',files:{'SKILL.md':'approved'}});approveSkill(hub,skill.id);
  await applySkillSync(hub,await planSkillSync(hub,skill.id,target));
  assert.equal(await readFile(outside,'utf8'),'outside original');assert.equal(await readFile(join(target,'SKILL.md'),'utf8'),'approved');db.close();
});

test('CLI init uses private raw key/token files, preserves keys, and never reopens claimed bootstrap',async()=>{
  const {runCli}=await import('../src/cli.js');const {stat}=await import('node:fs/promises');
  const {Hub}=await import('../src/core.js');const {loadConfig}=await import('../src/config.js');
  const root=await mkdtemp(join(tmpdir(),'unifymcp-cli-'));const vars={HUB_DATA_DIR:join(root,'state'),HUB_MASTER_KEY_FILE:join(root,'secrets/master.key'),HUB_BOOTSTRAP_TOKEN_FILE:join(root,'secrets/bootstrap.token')};
  const previous=Object.fromEntries(Object.keys(vars).map(key=>[key,process.env[key]]));Object.assign(process.env,vars);
  try {
    const result=await runCli(['init']);const key=await readFile(vars.HUB_MASTER_KEY_FILE),token=await readFile(vars.HUB_BOOTSTRAP_TOKEN_FILE,'utf8');
    assert.equal(key.length,32);assert.match(token.trim(),/^[\w-]{43}$/);assert.equal(JSON.stringify(result).includes(token.trim()),false);
    assert.equal((await stat(vars.HUB_MASTER_KEY_FILE)).mode&0o777,0o600);assert.equal((await stat(vars.HUB_BOOTSTRAP_TOKEN_FILE)).mode&0o777,0o600);
    await runCli(['init']);assert.deepEqual(await readFile(vars.HUB_MASTER_KEY_FILE),key);assert.equal(await readFile(vars.HUB_BOOTSTRAP_TOKEN_FILE,'utf8'),token);
    await runCli(['bootstrap-reset']);assert.notEqual(await readFile(vars.HUB_BOOTSTRAP_TOKEN_FILE,'utf8'),token);
    const config=loadConfig();const hub=new Hub(join(config.dataDir,'hub.sqlite'),key,config);hub.db.prepare('INSERT INTO owner(id,password_hash,created_at) VALUES(1,?,0)').run('claimed');hub.close();
    await assert.rejects(runCli(['bootstrap-reset']),/already claimed/);
  }finally{for(const [key,value] of Object.entries(previous)){if(value===undefined)delete process.env[key];else process.env[key]=value;}}
});
test('backup HTTP requires owner guard and fresh password step-up, and exports omit vault ciphertext',async()=>{
  const Fastify=(await import('fastify')).default;const {Hub}=await import('../src/core.js');const {loadConfig}=await import('../src/config.js');
  const {passwordHash}=await import('../src/auth.js');const {registerOperations}=await import('../src/backup.js');
  const dir=await mkdtemp(join(tmpdir(),'unifymcp-http-'));const key=randomBytes(32),keyFile=join(dir,'master.key');await writeFile(keyFile,key);
  const config=loadConfig({HUB_DATA_DIR:dir,HUB_MASTER_KEY_FILE:keyFile});const hub=new Hub(join(dir,'hub.sqlite'),key,config);
  const password='long-operation-password';hub.db.prepare('INSERT INTO owner(id,password_hash,created_at) VALUES(1,?,0)').run(await passwordHash(password));
  const ciphertext=hub.seal('vault-canary','connection:conn');hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,created_at) VALUES(?,?,?,?,?,0)').run('conn','bearer','test','connected',ciphertext);
  const app=Fastify();await registerOperations(app,hub,async(req,reply)=>{if(req.headers['x-test-owner']!=='yes')return reply.code(403).send({error:'owner_required'});});
  try {
    assert.equal((await app.inject({method:'POST',url:'/api/v1/backup/create',payload:{password}})).statusCode,403);
    assert.equal((await app.inject({method:'POST',url:'/api/v1/backup/create',headers:{'x-test-owner':'yes'},payload:{password:'wrong'}})).statusCode,403);
    const created=await app.inject({method:'POST',url:'/api/v1/backup/create',headers:{'x-test-owner':'yes'},payload:{password}});assert.equal(created.statusCode,200);
    const exported=await app.inject({method:'GET',url:'/api/v1/config/export',headers:{'x-test-owner':'yes'}});assert.equal(exported.statusCode,200);assert.equal(exported.body.includes('vault-canary'),false);assert.equal(exported.body.includes(ciphertext),false);assert.equal(exported.body.includes('password_hash'),false);
  }finally{await app.close();hub.close();}
});

test('restore rejects an authenticated snapshot with missing required schema columns',async()=>{
  const {dir,hub,db,key}=await fixture();db.exec('ALTER TABLE session DROP COLUMN csrf_token');
  const backup=await createEncryptedBackup(hub);
  await assert.rejects(restoreBackup(join(dir,'backups',backup.name),key,join(dir,'restore')),/csrf_token/);db.close();
});

async function portableFixture() {
  const {randomUUID}=await import('node:crypto');const source=await fixture();source.db.prepare('DELETE FROM connection').run();
  const connection=randomUUID(),upstream=randomUUID(),tool=randomUUID();const profile=source.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get() as string;
  source.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,config,scopes,created_at) VALUES(?,?,?,?,?,?,?,0)').run(connection,'bearer','portable','connected',source.hub.seal('do-not-export',`connection:${connection}`),JSON.stringify({allowed_origin:'https://api.example.invalid'}),'["read"]');
  source.db.prepare('INSERT INTO upstream(id,name,url,connection_id,status,created_at) VALUES(?,?,?,?,?,0)').run(upstream,'Portable MCP','https://api.example.invalid/mcp',connection,'active');
  source.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,description,input_schema,annotations,fingerprint,approved_fingerprint,risk,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,1)').run(tool,upstream,'list','portable_list','Read data','{"type":"object"}','{"readOnlyHint":true}','a'.repeat(64),'a'.repeat(64),'read');
  source.db.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run(profile,tool,connection,'read');const skill=importSkill(source.hub,{name:'Portable skill',source:'manual:commit123',files:{'SKILL.md':'# Portable'}});approveSkill(source.hub,skill.id);
  return {...source,connection,upstream,tool,profile,skill};
}
test('versioned config roundtrip excludes secrets and imports quarantined metadata without modifying target default',async()=>{
  const {exportConfig,importConfig}=await import('../src/backup.js');const source=await portableFixture(),target=await fixture();
  const config=exportConfig(source.hub);assert.equal(config.format,2);const text=JSON.stringify(config);assert.equal(text.includes('do-not-export'),false);assert.equal(text.includes('credential'),false);assert.equal(text.includes('token_hash'),false);
  const originalDefault=target.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get();
  const result=importConfig(target.hub,config);assert.equal(result.imported.tools,1);assert.equal(result.imported.skills,1);
  assert.equal(target.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get(),originalDefault);
  assert.equal((target.db.prepare('SELECT is_default FROM profile WHERE id=?').get(source.profile) as any).is_default,0);
  assert.equal((target.db.prepare('SELECT status,credential FROM connection WHERE id=?').get(source.connection) as any).credential,null);
  assert.equal((target.db.prepare('SELECT status FROM connection WHERE id=?').get(source.connection) as any).status,'not_configured');
  assert.equal((target.db.prepare('SELECT status FROM upstream WHERE id=?').get(source.upstream) as any).status,'registered');
  const tool=target.db.prepare('SELECT enabled,approved_fingerprint FROM tool WHERE id=?').get(source.tool) as any;assert.equal(tool.enabled,0);assert.equal(tool.approved_fingerprint,null);
  assert.equal((target.db.prepare('SELECT approved FROM skill WHERE id=?').get(source.skill.id) as any).approved,0);
  assert.equal(target.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(source.profile),1);
  const before=target.db.prepare('SELECT count(*) FROM connection').pluck().get();assert.throws(()=>importConfig(target.hub,config),/collision/i);assert.equal(target.db.prepare('SELECT count(*) FROM connection').pluck().get(),before);source.db.close();target.db.close();
});
test('config import atomically rejects credential fields, account/risk mismatch and unsafe/native URLs',async()=>{
  const {exportConfig,importConfig}=await import('../src/backup.js');const source=await portableFixture();
  const cases=[
    (c:any)=>{c.connections[0].credential='injected';},
    (c:any)=>{c.grants[0].connection_id=null;},
    (c:any)=>{c.grants[0].action_class='write';},
    (c:any)=>{c.upstreams[0].url='http://127.0.0.1/mcp';},
    (c:any)=>{c.upstreams[0].url='https://169.254.169.254/mcp';c.upstreams[0].allowed_private_ips=['169.254.169.254'];},
    (c:any)=>{c.upstreams[0].url=`native://google/${source.connection}`;},
  ];
  for(const change of cases){const target=await fixture(),config=structuredClone(exportConfig(source.hub));change(config);assert.throws(()=>importConfig(target.hub,config));assert.equal(target.db.prepare('SELECT count(*) FROM upstream').pluck().get(),0);assert.equal(target.db.prepare('SELECT count(*) FROM profile').pluck().get(),1);target.db.close();}
  source.db.close();
});
test('backup binary download requires step-up and rejects symlink or traversal filenames',async()=>{
  const Fastify=(await import('fastify')).default;const {registerOperations}=await import('../src/backup.js');const {passwordHash}=await import('../src/auth.js');
  const {hub,db,dir}=await fixture();const password='download-stepup-password';db.prepare('INSERT INTO owner(id,password_hash,created_at) VALUES(1,?,0)').run(await passwordHash(password));const backup=await createEncryptedBackup(hub);
  const app=Fastify();await registerOperations(app,hub,async(req,reply)=>{if(req.headers['x-test-owner']!=='yes')return reply.code(403).send({});});
  try {
    const path=`/api/v1/backups/${backup.name}/download`;
    assert.equal((await app.inject({method:'POST',url:path,payload:{password}})).statusCode,403);
    assert.equal((await app.inject({method:'POST',url:path,headers:{'x-test-owner':'yes'},payload:{password:'wrong'}})).statusCode,403);
    const res=await app.inject({method:'POST',url:path,headers:{'x-test-owner':'yes'},payload:{password}});assert.equal(res.statusCode,200);assert.match(res.headers['content-type'] as string,/application\/octet-stream/);assert.deepEqual(res.rawPayload,await readFile(join(dir,'backups',backup.name)));
    const linked='backup-linked.umcp';await symlink(hub.config.masterKeyFile,join(dir,'backups',linked));
    assert.equal((await app.inject({method:'POST',url:`/api/v1/backups/${linked}/download`,headers:{'x-test-owner':'yes'},payload:{password}})).statusCode,404);
    assert.equal((await app.inject({method:'POST',url:'/api/v1/backups/%2E%2E%2Fexternal.key/download',headers:{'x-test-owner':'yes'},payload:{password}})).statusCode,404);
  }finally{await app.close();db.close();}
});

test('config portability preserves undisclosed tool review state and safe remote OAuth metadata',async()=>{
  const {exportConfig,importConfig}=await import('../src/backup.js');const source=await portableFixture(),target=await fixture();
  source.db.prepare('DELETE FROM profile_grant').run();source.db.prepare("UPDATE tool SET risk='unreviewed',enabled=0,approved_fingerprint=NULL").run();
  source.db.prepare('UPDATE connection SET provider=?,config=? WHERE id=?').run('remote_oauth',JSON.stringify({client_id:'app-id',issuer:'https://auth.example.invalid',resource:'https://api.example.invalid/mcp',allowed_origin:'https://api.example.invalid'}),source.connection);
  const config=exportConfig(source.hub);importConfig(target.hub,config);
  assert.equal((target.db.prepare('SELECT risk FROM tool WHERE id=?').get(source.tool) as any).risk,'unreviewed');
  assert.equal((target.db.prepare('SELECT provider FROM connection WHERE id=?').get(source.connection) as any).provider,'remote_oauth');source.db.close();target.db.close();
});
