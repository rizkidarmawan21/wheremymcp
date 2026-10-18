import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes,randomUUID } from 'node:crypto';
import { mkdtempSync,rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Hub } from '../src/core.js';
import { loadConfig } from '../src/config.js';
import { registerAdmin } from '../src/admin.js';
import Fastify from 'fastify';

test('audit cursor preserves tied timestamps and account/profile filters preserve historical context',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-audit-'));const hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));const app=Fastify();await registerAdmin(app,hub,async()=>{});
 try{
 const p=(hub.db.prepare('SELECT id FROM profile').get() as any).id,client=randomUUID(),connection=randomUUID(),upstream=randomUUID(),tool=randomUUID();
 hub.db.prepare('INSERT INTO client(id,name,kind,profile_id,token_hash,status,created_at) VALUES(?,?,?,?,?,?,?)').run(client,'c','codex',p,'hash','active',Date.now());hub.db.prepare('INSERT INTO connection(id,provider,alias,status,created_at) VALUES(?,?,?,?,?)').run(connection,'bearer','work-old','connected',Date.now());hub.db.prepare('INSERT INTO upstream(id,name,url,connection_id,created_at) VALUES(?,?,?,?,?)').run(upstream,'u','https://mcp.example',connection,Date.now());hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,input_schema,fingerprint) VALUES(?,?,?,?,?,?)').run(tool,upstream,'read','unique','{}','digest');
 hub.audit({principal:client,action:'tool.call',resource:tool});hub.audit({principal:client,action:'tool.call',resource:tool});hub.db.prepare('UPDATE audit_event SET ts=1000').run();hub.db.prepare("UPDATE connection SET alias='work-new'").run();
 const first=(await app.inject({url:'/api/v1/audit?limit=1'})).json();assert.equal(first.events.length,1);assert.ok(first.next_cursor);
 const second=(await app.inject({url:'/api/v1/audit?limit=1&cursor='+first.next_cursor})).json();assert.equal(second.events.length,1);assert.notEqual(first.events[0].id,second.events[0].id);
 assert.equal(first.events[0].profile_id,p);assert.equal(first.events[0].account_id,connection);assert.equal(first.events[0].account_alias,'work-old');
 const filtered=(await app.inject({url:'/api/v1/audit?profile_id='+p+'&account_alias=work-old'})).json();assert.equal(filtered.events.length,2);
 const none=(await app.inject({url:'/api/v1/audit?account_alias=work-new'})).json();assert.equal(none.events.length,0);
 }finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('overview recent events ship parsed metadata instead of raw audit JSON',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-overview-'));const hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));const app=Fastify();await registerAdmin(app,hub,async()=>{});
 try{
  hub.audit({principal:'owner',action:'client.revoke',resource:'tool-x'});
  const overview=(await app.inject({url:'/api/v1/overview'})).json();
  const event=overview.recent_events.find((e:any)=>e.action==='client.revoke');
  assert.ok(event,'client.revoke event is in recent_events');
  assert.equal(event.detail,'','a bare audit event must not leak serialized detail JSON');
  assert.equal(event.action,'client.revoke');
 }finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});
