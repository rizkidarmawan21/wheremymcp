import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hub } from '../src/core.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';

async function ownerApp(t: any) {
  const dir=mkdtempSync(join(tmpdir(),'hub-edit-')); const key=randomBytes(32);
  const config=loadConfig({HUB_DATA_DIR:dir}); writeFileSync(config.bootstrapTokenFile,'setup-test-token',{mode:0o600}); writeFileSync(config.masterKeyFile,key,{mode:0o600});
  const hub=new Hub(':memory:',key,config); const app=await createApp(hub);
  const post=async(url:string,payload:any)=>app.inject({method:'POST',url,payload,headers:{host:'127.0.0.1:8080'}});
  await post('/setup/claim',{setup_token:'setup-test-token',password:'Correct-horse.battery/staple-2026'});
  const login=await post('/auth/session',{password:'Correct-horse.battery/staple-2026'});
  const cookie=String(login.headers['set-cookie']).split(';')[0]!; const csrf=login.json().csrf_token;
  const send=(method:string,url:string,payload?:any)=>app.inject({method,url,payload,headers:{host:'127.0.0.1:8080',cookie,'x-csrf-token':csrf}});
  t.after(()=>{app.close();hub.close();rmSync(dir,{recursive:true,force:true});});
  return {app,hub,send};
}

test('connection edit supports identity, scopes and config; provider config validation still applies', async t => {
  const {send}=await ownerApp(t);
  const created=await send('POST','/api/v1/connections',{provider:'bearer',alias:'n8n-account',identity:'ops@example.test',secret:'jwt-secret'});
  assert.equal(created.statusCode,201);
  const id=created.json().connection.id;
  const edit=await send('PATCH',`/api/v1/connections/${id}`,{identity:'automation@example.test',scopes:['workflow:read'],config:{allowed_origin:'https://example.com'}});
  assert.equal(edit.statusCode,200);
  const row=edit.json().connection;
  assert.equal(row.identity,'automation@example.test');
  assert.deepEqual(row.scopes,['workflow:read']);
  assert.deepEqual(row.config,{allowed_origin:'https://example.com'});
  assert.equal((await send('PATCH',`/api/v1/connections/${id}`,{config:{allowed_origin:'http://insecure.example'}})).statusCode,400);
  assert.equal((await send('POST','/api/v1/connections',{provider:'api_key',alias:'api-acct',secret:'k'})).statusCode,400);
});

test('connection delete guards upstream references and otherwise removes the row', async t => {
  const {hub,send}=await ownerApp(t);
  const created=await send('POST','/api/v1/connections',{provider:'bearer',alias:'loose',secret:'s'});const id=created.json().connection.id;
  assert.equal((await send('DELETE',`/api/v1/connections/${id}`)).statusCode,200);
  assert.equal(hub.db.prepare('SELECT COUNT(*) AS n FROM connection WHERE id=?').get(id)?.['n'],0);
  const bound=await send('POST','/api/v1/connections',{provider:'bearer',alias:'bound',secret:'s'});const bid=bound.json().connection.id;
  hub.db.prepare('INSERT INTO upstream(id,name,url,connection_id,status,allowed_private_ips,timeout_ms,created_at) VALUES(?,?,?,?,?,?,?,?)').run(randomUUID(),'up','http://127.0.0.1:1/mcp',bid,'pending_review','[]',15000,Date.now());
  assert.equal((await send('DELETE',`/api/v1/connections/${bid}`)).statusCode,409);
});

test('upstream records are editable without re-registering, and deletion cascades tools and grants', async t => {
  const {hub,send}=await ownerApp(t);
  const conn=await send('POST','/api/v1/connections',{provider:'bearer',alias:'c',secret:'s'});
  const created=await send('POST','/api/v1/upstreams',{name:'n8n gateway',url:'https://example.com/mcp',connection_id:conn.json().connection.id,timeout_ms:15000});
  assert.equal(created.statusCode,200);
  const id=created.json().upstream.id;
  hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,description,input_schema,annotations,fingerprint,approved_fingerprint,risk,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run('tool',id,'list','list','','{}','{}','fp','fp','read',1);
  hub.db.prepare('INSERT INTO profile_grant(profile_id,tool_id,connection_id,action_class) VALUES(?,?,?,?)').run((hub.db.prepare('SELECT id FROM profile').get() as any).id,'tool',conn.json().connection.id,'read');
  const edit=await send('PATCH',`/api/v1/upstreams/${id}`,{name:'n8n lowcode',url:'https://example.com/mcp-server/http',timeout_ms:30000,allowed_private_ips:[]});
  assert.equal(edit.statusCode,200);
  const up=edit.json().upstream;
  assert.equal(up.name,'n8n lowcode');
  assert.equal(up.url,'https://example.com/mcp-server/http');
  assert.equal(up.status,'registered');
  assert.equal(hub.setting('import_requires_refresh:'+id),'true');
  assert.equal((await send('PATCH',`/api/v1/upstreams/${id}`,{url:'http://127.0.0.1:1/mcp'})).statusCode,400);
  const del=await send('DELETE',`/api/v1/upstreams/${id}`);
  assert.equal(del.statusCode,200);
  assert.equal(hub.db.prepare('SELECT COUNT(*) AS n FROM tool WHERE upstream_id=?').get(id)?.['n'],0);
  assert.equal(hub.db.prepare('SELECT COUNT(*) AS n FROM profile_grant WHERE tool_id=?').get('tool')?.['n'],0);
});

test('owner password policy: 8+ chars with lower, upper, digit and symbol', async t => {
  const ok = await ownerApp(t);
  assert.equal((await ok.send('POST','/auth/password',{password:'Correct-horse.battery/staple-2026', new_password:'Kopi-susu-8!'})).statusCode,200);
  const short = await ownerApp(t);
  assert.equal((await short.send('POST','/auth/password',{password:'Correct-horse.battery/staple-2026', new_password:'short1!'})).statusCode,400);
  const weak = await ownerApp(t);
  assert.equal((await weak.send('POST','/auth/password',{password:'Correct-horse.battery/staple-2026', new_password:'alllowercase1!'})).statusCode,400);
});

test('expired client rotation preserves the token and expiry; valid rotation revokes the old token', async t => {
  const {hub,send}=await ownerApp(t);
  const profile=(hub.db.prepare('SELECT id FROM profile').get() as any).id;
  const created=await send('POST','/api/v1/clients',{name:'rotation-check',kind:'codex',profile_id:profile,ttl_days:1});
  assert.equal(created.statusCode,201);
  const {client,token}=created.json();
  const expiresAt=Date.now()-1000;
  hub.db.prepare('UPDATE client SET expires_at=? WHERE id=?').run(expiresAt,client.id);
  const original=hub.db.prepare('SELECT token_hash FROM client WHERE id=?').get(client.id) as any;
  const denied=await send('POST',`/api/v1/clients/${client.id}/rotate`);
  assert.equal(denied.statusCode,409);
  assert.match(denied.json().message,/Expired client cannot be rotated/);
  assert.deepEqual(hub.db.prepare('SELECT token_hash,expires_at FROM client WHERE id=?').get(client.id),{token_hash:original.token_hash,expires_at:expiresAt});
  hub.db.prepare('UPDATE client SET expires_at=NULL WHERE id=?').run(client.id);
  const rotated=await send('POST',`/api/v1/clients/${client.id}/rotate`);
  assert.equal(rotated.statusCode,200);
  assert.notEqual(rotated.json().token,token);
  assert.throws(()=>hub.requireClient({headers:{authorization:`Bearer ${token}`}} as any));
  assert.equal(hub.requireClient({headers:{authorization:`Bearer ${rotated.json().token}`}} as any).id,client.id);
});

test('connection delete explains retained grant references after an upstream changes accounts', async t => {
  const {hub,send}=await ownerApp(t);
  const oldAccount=(await send('POST','/api/v1/connections',{provider:'bearer',alias:'old-account',secret:'old'})).json().connection.id;
  const newAccount=(await send('POST','/api/v1/connections',{provider:'bearer',alias:'new-account',secret:'new'})).json().connection.id;
  const profile=(hub.db.prepare('SELECT id FROM profile').get() as any).id;
  const upstream=randomUUID(),tool=randomUUID();
  hub.db.prepare('INSERT INTO upstream(id,name,url,connection_id,created_at) VALUES(?,?,?,?,?)').run(upstream,'rebound','https://example.test/mcp',newAccount,Date.now());
  hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,input_schema,fingerprint) VALUES(?,?,?,?,?,?)').run(tool,upstream,'read','rebound__read','{}','fp');
  hub.db.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run(profile,tool,oldAccount,'read');
  const denied=await send('DELETE',`/api/v1/connections/${oldAccount}`);
  assert.equal(denied.statusCode,409);
  assert.match(denied.json().message,/referenced by profile grants/);
  hub.db.prepare('DELETE FROM profile_grant WHERE tool_id=?').run(tool);
  assert.equal((await send('DELETE',`/api/v1/connections/${oldAccount}`)).statusCode,200);
});

test('deleting a bound profile requires an explicit replacement and clears grants and pending approvals atomically',async t=>{
 const {hub,send}=await ownerApp(t);
 const fallback=(hub.db.prepare('SELECT id FROM profile WHERE is_default=1').get() as {id:string}).id;
 const profile=(await send('POST','/api/v1/profiles',{name:'Temporary access'})).json().profile;
 const {client,token}=(await send('POST','/api/v1/clients',{name:'Retained client',kind:'codex',profile_id:profile.id})).json();
 const revoked=(await send('POST','/api/v1/clients',{name:'Revoked client',kind:'other',profile_id:profile.id})).json().client;await send('POST',`/api/v1/clients/${revoked.id}/revoke`);
 const upstream=randomUUID(),tool=randomUUID();
 hub.db.prepare('INSERT INTO upstream(id,name,url,status,created_at) VALUES(?,?,?,?,?)').run(upstream,'Test server','https://example.com/mcp','active',Date.now());
 hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,input_schema,fingerprint,risk,enabled) VALUES(?,?,?,?,?,?,?,1)').run(tool,upstream,'search','test_search','{}','fingerprint','read');
 hub.db.prepare('INSERT INTO profile_grant VALUES(?,?,NULL,?)').run(profile.id,tool,'read');
 hub.db.prepare('INSERT INTO approval VALUES(?,?,?,?,?,NULL)').run(randomUUID(),client.id,tool,'arguments',Date.now()+60000);
 assert.equal((await send('DELETE',`/api/v1/profiles/${fallback}`,{replacement_profile_id:profile.id})).statusCode,409);
 assert.equal((await send('DELETE',`/api/v1/profiles/${profile.id}`)).statusCode,409);
 assert.equal((await send('DELETE',`/api/v1/profiles/${profile.id}`,{replacement_profile_id:profile.id})).statusCode,400);
 assert.equal((await send('DELETE',`/api/v1/profiles/${profile.id}`,{replacement_profile_id:randomUUID()})).statusCode,404);
 assert.equal((hub.db.prepare('SELECT profile_id FROM client WHERE id=?').get(client.id) as {profile_id:string}).profile_id,profile.id);
 assert.equal(hub.db.prepare('SELECT count(*) FROM approval').pluck().get(),1);
 assert.equal((await send('DELETE',`/api/v1/profiles/${profile.id}`,{replacement_profile_id:fallback})).statusCode,200);
 assert.equal(hub.db.prepare('SELECT id FROM profile WHERE id=?').get(profile.id),undefined);
 assert.equal(hub.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(profile.id),0);
 assert.equal(hub.db.prepare('SELECT count(*) FROM approval WHERE client_id=?').pluck().get(client.id),0);
 const retained=hub.requireClient({headers:{authorization:`Bearer ${token}`}} as any);
 assert.equal(retained.id,client.id);assert.equal(retained.profile_id,fallback);
 assert.equal((hub.db.prepare('SELECT status FROM client WHERE id=?').get(revoked.id) as {status:string}).status,'revoked','Moving clients must not reactivate revoked tokens');
 assert.equal(hub.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(fallback),0,'Replacement access must not inherit deleted grants');
});

test('MCP discovery explains missing account authorization without exposing credentials',async t=>{
 const {hub,send}=await ownerApp(t);
 const connection=await send('POST','/api/v1/connections',{provider:'bearer',alias:'needs-login',secret:'credential-error-canary'});
 const id=connection.json().connection.id;
 const created=await send('POST','/api/v1/upstreams',{name:'Needs login',url:'https://example.com/mcp',connection_id:id});
 assert.equal(created.statusCode,200,created.body);
 hub.db.prepare("UPDATE connection SET status='not_configured',credential=NULL WHERE id=?").run(id);
 const result=await send('POST',`/api/v1/upstreams/${created.json().upstream.id}/auto-approve-tools`,{trust_server:true});
 assert.equal(result.statusCode,403,result.body);
 assert.equal(result.json().error,'upstream_auth_required');
 assert.match(result.json().message,/Connections/);
 assert.match(result.json().message,/authoriz/i);
 assert.equal(result.body.includes('credential-error-canary'),false);
 assert.ok(result.json().request_id);
});
