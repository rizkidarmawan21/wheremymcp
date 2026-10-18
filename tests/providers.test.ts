import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync,rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Hub } from '../src/core.js';
import { loadConfig } from '../src/config.js';
import { ProviderManager } from '../src/providers.js';

test('OAuth state is session/provider bound, single use and carries PKCE',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-oauth-')),hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));
 let calls=0;
 const manager=new ProviderManager(hub,async(input,init)=>{calls++;const url=String(input);if(url.includes('/access_token')){assert.ok(String(init?.body).includes('code_verifier='));return Response.json({access_token:'provider-secret-canary',scope:'read:user',token_type:'bearer'});}return Response.json({id:123,login:'test-identity'});});
 try{const id=randomUUID();hub.db.prepare('INSERT INTO session VALUES(?,?,?,?,?,?,?)').run('session-a','token','csrf','encrypted',Date.now(),Date.now(),Date.now()+600000);hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,config,created_at) VALUES(?,?,?,?,?,?,?)').run(id,'github','work','not_configured',hub.seal(JSON.stringify({client_secret:'byo-secret'}),`connection:${id}`),JSON.stringify({client_id:'byo-id'}),Date.now());
 const start=manager.startOAuth(id,'session-a');const parsed=new URL(start.authorization_url);assert.equal(parsed.searchParams.get('code_challenge_method'),'S256');const state=parsed.searchParams.get('state')!;
 await assert.rejects(manager.finishOAuth('slack',state,'code','session-a'),/OAuth/);assert.equal(calls,0);
 await assert.rejects(manager.finishOAuth('github',state,'code','session-b'),/OAuth/);assert.equal(calls,0);
 const result=await manager.finishOAuth('github',state,'code','session-a');assert.equal(result.connection_id,id);
 await assert.rejects(manager.finishOAuth('github',state,'code','session-a'),/OAuth/);
 assert.equal((hub.db.prepare('SELECT status FROM connection WHERE id=?').get(id) as any).status,'connected');
 assert.ok(!JSON.stringify(hub.db.prepare('SELECT * FROM connection').all()).includes('provider-secret-canary'));
 }finally{hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('logout invalidates an OAuth exchange already in flight',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-oauth-logout-')),hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));const id=randomUUID();let release!:()=>void;const gate=new Promise<void>(r=>release=r);let entered!:()=>void;const started=new Promise<void>(r=>entered=r);
 const manager=new ProviderManager(hub,async input=>{if(String(input).includes('access_token')){entered();await gate;return Response.json({access_token:'provider-token'});}return Response.json({id:42});});
 hub.db.prepare('INSERT INTO session VALUES(?,?,?,?,?,?,?)').run('session-a','token','csrf','encrypted',Date.now(),Date.now(),Date.now()+600000);hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,config,created_at) VALUES(?,?,?,?,?,?,?)').run(id,'github','work','not_configured',hub.seal(JSON.stringify({client_secret:'byo-secret'}),`connection:${id}`),JSON.stringify({client_id:'byo-id'}),Date.now());
 try{const state=new URL(manager.startOAuth(id,'session-a').authorization_url).searchParams.get('state')!;const pending=manager.finishOAuth('github',state,'code','session-a');await started;hub.db.prepare('DELETE FROM session').run();release();await assert.rejects(pending,/session|revoked|changed/);assert.notEqual((hub.db.prepare('SELECT status FROM connection WHERE id=?').get(id) as any).status,'connected');}
 finally{hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('an old provider 401 cannot disable a newly rotated credential',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-provider-401-')),hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));const id=randomUUID();let release!:()=>void;const gate=new Promise<void>(r=>release=r);let entered!:()=>void;const started=new Promise<void>(r=>entered=r);
 const manager=new ProviderManager(hub,async()=>{entered();await gate;return new Response('{}',{status:401});});hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,created_at) VALUES(?,?,?,?,?,?)').run(id,'github','work','connected',hub.seal(JSON.stringify({secret:'old'}),`connection:${id}`),Date.now());
 try{const pending=manager.nativeCall(id,'list_repositories',{});await started;hub.db.prepare('UPDATE connection SET credential=? WHERE id=?').run(hub.seal(JSON.stringify({secret:'new'}),`connection:${id}`),id);release();await assert.rejects(pending,/Provider/);assert.equal((hub.db.prepare('SELECT status FROM connection WHERE id=?').get(id) as any).status,'connected');}
 finally{hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('provider refresh is serialized and revocation wins an in-flight refresh',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-refresh-')),hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));const id=randomUUID();let count=0;let release!:()=>void;
 const gate=new Promise<void>(r=>release=r);const manager=new ProviderManager(hub,async()=>{count++;await gate;return Response.json({access_token:'fresh',expires_in:3600});});
 hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,config,created_at) VALUES(?,?,?,?,?,?,?)').run(id,'google','work','connected',hub.seal(JSON.stringify({secret:'old',refresh_token:'refresh',client_secret:'byo',expires_at:1}),`connection:${id}`),JSON.stringify({client_id:'app'}),Date.now());
 try{const first=manager.resolveCredential(id);const second=manager.resolveCredential(id);await new Promise(r=>setImmediate(r));hub.db.prepare("UPDATE connection SET status='revoked',credential=NULL WHERE id=?").run(id);release();await assert.rejects(first,/revoked|changed/);await assert.rejects(second,/revoked|changed/);assert.equal(count,1);assert.equal((hub.db.prepare('SELECT credential FROM connection WHERE id=?').get(id) as any).credential,null);}
 finally{hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('secret-file import reads approved regular files and rejects escapes, directories and oversized files',async()=>{
 const {mkdir,writeFile,symlink}=await import('node:fs/promises');const Fastify=(await import('fastify')).default;
 const {registerProviders}=await import('../src/providers.js');
 const dir=mkdtempSync(join(tmpdir(),'hub-secret-file-')),approved=join(dir,'approved');await mkdir(approved);
 await writeFile(join(approved,'token.txt'),'file-secret-canary\n',{mode:0o600});
 await writeFile(join(dir,'outside.txt'),'outside-secret');await symlink(join(dir,'outside.txt'),join(approved,'escape.txt'));
 await writeFile(join(approved,'large.txt'),'x'.repeat(16385));await mkdir(join(approved,'directory'));
 const previous=process.env.HUB_CREDENTIAL_FILES_DIR;process.env.HUB_CREDENTIAL_FILES_DIR=approved;
 const hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir})),app=Fastify();
 await registerProviders(app,hub,async()=>{});
 const create=(alias:string,secret_file:string)=>app.inject({method:'POST',url:'/api/v1/connections',payload:{provider:'bearer',alias,secret_file}});
 try{
  const valid=await create('valid-file','token.txt');assert.equal(valid.statusCode,201);assert.equal(valid.body.includes('file-secret-canary'),false);
  const id=valid.json().connection.id;const row=hub.db.prepare('SELECT credential FROM connection WHERE id=?').get(id) as {credential:string};
  assert.equal(JSON.parse(hub.open(row.credential,`connection:${id}`)).secret,'file-secret-canary');
  assert.equal((await create('traversal-file','../outside.txt')).statusCode,403);
  assert.equal((await create('symlink-file','escape.txt')).statusCode,403);
  assert.equal((await create('oversized-file','large.txt')).statusCode,400);
  assert.equal((await create('directory-file','directory')).statusCode,400);
  assert.equal(hub.db.prepare('SELECT count(*) FROM connection').pluck().get(),1);
 }finally{if(previous===undefined)delete process.env.HUB_CREDENTIAL_FILES_DIR;else process.env.HUB_CREDENTIAL_FILES_DIR=previous;await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});
