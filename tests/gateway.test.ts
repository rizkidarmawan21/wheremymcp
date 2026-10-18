import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import Fastify from 'fastify';
import Database from 'better-sqlite3';
import {Server,createMcpHandler} from '@modelcontextprotocol/server';
import {toNodeHandler} from '@modelcontextprotocol/node';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {registerGateway} from '../src/gateway/index.js';

async function fixture(t:any) {
 const db=new Database(':memory:');
 db.exec(`CREATE TABLE profile(id TEXT PRIMARY KEY); INSERT INTO profile VALUES('profile');
 CREATE TABLE client(id TEXT PRIMARY KEY,name TEXT,kind TEXT,profile_id TEXT,status TEXT,expires_at INTEGER,last_used INTEGER); INSERT INTO client VALUES('client','test','codex','profile','active',NULL,NULL);
 CREATE TABLE connection(id TEXT PRIMARY KEY,provider TEXT,alias TEXT,status TEXT,identity TEXT,scopes TEXT,credential TEXT,config TEXT,expires_at INTEGER,created_at INTEGER);
 CREATE TABLE upstream(id TEXT PRIMARY KEY,name TEXT,url TEXT,connection_id TEXT,status TEXT,allowed_private_ips TEXT,timeout_ms INTEGER,created_at INTEGER);
 CREATE TABLE tool(id TEXT PRIMARY KEY,upstream_id TEXT,name TEXT,gateway_name TEXT UNIQUE,description TEXT,input_schema TEXT,annotations TEXT,fingerprint TEXT,approved_fingerprint TEXT,risk TEXT,enabled INTEGER,previous_metadata TEXT,UNIQUE(upstream_id,name));
 CREATE TABLE profile_grant(profile_id TEXT,tool_id TEXT,connection_id TEXT,action_class TEXT,PRIMARY KEY(profile_id,tool_id));
 CREATE TABLE approval(id TEXT PRIMARY KEY,client_id TEXT,tool_id TEXT,arguments_hash TEXT,expires_at INTEGER,used_at INTEGER);`);
 let description='Echo';let calls=0;let delay=0;let replyText:string|undefined;let inputSchema:any={type:'object',properties:{text:{type:'string'}},required:['text'],additionalProperties:false};const authHeaders:string[]=[];const events:any[]=[];const settings=new Map();
 const handler=createMcpHandler(()=>{
  const server=new Server({name:'fake',version:'1'},{capabilities:{tools:{}}});
  server.setRequestHandler('tools/list',()=>({tools:[{name:'echo',description,inputSchema,annotations:{readOnlyHint:true}}]}));
  server.setRequestHandler('tools/call',async req=>{calls++;if(delay)await new Promise(resolve=>setTimeout(resolve,delay));return {content:[{type:'text',text:replyText??String(req.params.arguments?.text)}]};});return server;
 });
 const nodeHandler=toNodeHandler(handler);const upstream=createServer((req,res)=>{authHeaders.push(req.headers.authorization??'');void nodeHandler(req,res);});
 await new Promise<void>(resolve=>upstream.listen(0,'127.0.0.1',resolve));
 const app=Fastify();
 const hub:any={db,config:{maxBodyBytes:65536,origin:'http://localhost'},open:(s:string)=>s,audit:(e:any)=>events.push(e),setting:(k:string)=>settings.get(k),setSetting:(k:string,v:string)=>settings.set(k,v),requireClient:(req:any)=>{if(req.headers.authorization!=='Bearer agent-secret')throw Object.assign(new Error('unauthorized'),{statusCode:401});const c=db.prepare('SELECT * FROM client WHERE id=?').get('client') as any;if(c.status!=='active')throw Object.assign(new Error('revoked'),{statusCode:401});return c;}};
 await registerGateway(app,hub,async req=>{if(req.headers['x-owner']!=='yes')throw Object.assign(new Error('forbidden'),{statusCode:403});});
 await app.listen({host:'127.0.0.1',port:0});
 t.after(async()=>{await app.close();await handler.close();upstream.closeAllConnections();await new Promise<void>(resolve=>upstream.close(()=>resolve()));db.close();});
 const api=async(method:string,path:string,body?:any)=>{const res=await app.inject({method:method as any,url:path,headers:{'x-owner':'yes'},payload:body});assert.ok(res.statusCode<300,res.body);return res.json();};
 const add=async(connection_id?:string)=>{const {upstream:u}=await api('POST','/api/v1/upstreams',{name:'same-name',url:`http://127.0.0.1:${(upstream.address() as any).port}/mcp`,allowed_private_ips:['127.0.0.1'],connection_id});await api('POST',`/api/v1/upstreams/${u.id}/refresh`);await api('POST',`/api/v1/upstreams/${u.id}/approve`);return u;};
 const client=async(mode:any='auto')=>{const c=new Client({name:'test',version:'1'},{versionNegotiation:{mode}});await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${(app.server.address() as any).port}/mcp`),{requestInit:{headers:{authorization:'Bearer agent-secret'}}}));t.after(()=>c.close());return c;};
 return {db,app,hub,api,add,client,settings,events,authHeaders,setDelay:(n:number)=>{delay=n;},setReply:(s:string)=>{replyText=s;},setSchema:(schema:any)=>{inputSchema=schema;},getCalls:()=>calls,setDescription:(s:string)=>{description=s;}};
}

test('official modern and legacy clients obey deny-default, namespace, fresh grants and drift quarantine',async t=>{
 const f=await fixture(t);await f.add();await f.add();const {tools}=await f.api('GET','/api/v1/tools');
 assert.equal(tools.length,2);assert.notEqual(tools[0].gateway_name,tools[1].gateway_name);
 const modern=await f.client();const legacy=await f.client('legacy');assert.equal(modern.getProtocolEra(),'modern');assert.equal(modern.getNegotiatedProtocolVersion(),'2026-07-28');assert.equal(legacy.getProtocolEra(),'legacy');assert.equal(legacy.getNegotiatedProtocolVersion(),'2025-11-25');
 assert.equal((await modern.listTools()).tools.length,0);assert.equal((await legacy.listTools()).tools.length,0);
 for(const tool of tools){await f.api('POST',`/api/v1/tools/${tool.id}/approve`,{risk:'read',enabled:true});f.db.prepare('INSERT INTO profile_grant VALUES(?,?,NULL,?)').run('profile',tool.id,'read');}
 assert.equal((await modern.listTools()).tools.length,2);assert.equal((await legacy.listTools()).tools.length,2);
 assert.equal((await modern.callTool({name:tools[0].gateway_name,arguments:{text:'ok'}})).content[0]?.type,'text');
 await assert.rejects(modern.callTool({name:tools[0].gateway_name,arguments:{text:42}}));
 f.db.prepare('DELETE FROM profile_grant WHERE tool_id=?').run(tools[0].id);
 await assert.rejects(modern.callTool({name:tools[0].gateway_name,arguments:{text:'blocked'}}));assert.equal(f.getCalls(),1);
 f.setDescription('Changed instructions');await f.api('POST',`/api/v1/upstreams/${tools[1].upstream_id}/refresh`);
 assert.equal((await modern.listTools()).tools.length,0);
 const changed=(await f.api('GET','/api/v1/tools')).tools.find((x:any)=>x.id===tools[1].id);assert.equal(changed.enabled,0);assert.equal(changed.previous_metadata.description,'Echo');
 assert.ok(!JSON.stringify(f.events).includes('agent-secret'));
});

test('write approval is one-use, argument-bound and upstream receives only its credential',async t=>{
 const f=await fixture(t);f.db.prepare('INSERT INTO connection VALUES(?,?,?,?,?,?,?,?,?,?)').run('connection','bearer','account','active',null,'[]',JSON.stringify({secret:'provider-secret'}),'{}',null,Date.now());await f.add('connection');const tool=(await f.api('GET','/api/v1/tools')).tools[0];
 await f.api('POST',`/api/v1/tools/${tool.id}/approve`,{risk:'write',enabled:true});f.db.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run('profile',tool.id,'connection','write');
 const c=await f.client();await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'x'}}));
 const {approval_id}=await f.api('POST','/api/v1/approvals',{client_id:'client',tool_id:tool.id,arguments:{text:'x'}});
 await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'y'},_meta:{unifymcp_approval_id:approval_id}}));
 await c.callTool({name:tool.gateway_name,arguments:{text:'x'},_meta:{unifymcp_approval_id:approval_id}});
 await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'x'},_meta:{unifymcp_approval_id:approval_id}}));assert.equal(f.getCalls(),1);
 assert.ok(f.authHeaders.every(h=>h==='Bearer provider-secret'));
 f.settings.set('emergency_stop','true');assert.equal((await c.listTools()).tools.length,0);await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'x'}}));
 f.settings.set('emergency_stop','false');f.db.prepare("UPDATE connection SET status='revoked'").run();assert.equal((await c.listTools()).tools.length,0);
 f.db.prepare("UPDATE client SET status='revoked'").run();await assert.rejects(c.listTools());
});


test('bounded calls reject overload, abort on emergency stop and never retry writes',async t=>{
 const f=await fixture(t);await f.add();const tool=(await f.api('GET','/api/v1/tools')).tools[0];
 await f.api('POST',`/api/v1/tools/${tool.id}/approve`,{risk:'write',enabled:true});f.db.prepare('INSERT INTO profile_grant VALUES(?,?,NULL,?)').run('profile',tool.id,'write');
 const c=await f.client();const {approval_id}=await f.api('POST','/api/v1/approvals',{client_id:'client',tool_id:tool.id,arguments:{text:'x'}});
 f.setDelay(250);const pending=c.callTool({name:tool.gateway_name,arguments:{text:'x'},_meta:{unifymcp_approval_id:approval_id}});
 while(f.getCalls()===0)await new Promise(resolve=>setTimeout(resolve,5));
 await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'x'},_meta:{unifymcp_approval_id:approval_id}}));
 f.settings.set('emergency_stop','true');await assert.rejects(pending);assert.equal(f.getCalls(),1);
 f.settings.set('emergency_stop','false');f.setDelay(0);await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'x'},_meta:{unifymcp_approval_id:approval_id}}));assert.equal(f.getCalls(),1);
});

test('metadata and output limits, secret redaction, Origin and owner guards',async t=>{
 const f=await fixture(t);f.db.prepare('INSERT INTO connection VALUES(?,?,?,?,?,?,?,?,?,?)').run('connection','bearer','account','active',null,'[]',JSON.stringify({secret:'provider-secret'}),'{}',null,Date.now());await f.add('connection');const tool=(await f.api('GET','/api/v1/tools')).tools[0];
 await f.api('POST',`/api/v1/tools/${tool.id}/approve`,{risk:'read',enabled:true});f.db.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run('profile',tool.id,'connection','read');const c=await f.client();
 f.setReply('upstream provider-secret / agent-secret');const result=await c.callTool({name:tool.gateway_name,arguments:{text:'x'}});assert.equal((result.content[0] as any).text,'upstream [REDACTED] / [REDACTED]');
 f.setReply('x'.repeat(1_100_000));await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'x'}}));assert.equal(f.getCalls(),2);
 assert.equal((await f.app.inject({method:'GET',url:'/api/v1/tools',headers:{authorization:'Bearer agent-secret'}})).statusCode,403);
 assert.equal((await f.app.inject({method:'POST',url:'/mcp',headers:{authorization:'Bearer agent-secret',origin:'https://evil.example'},payload:{jsonrpc:'2.0',id:1,method:'tools/list'}})).statusCode,403);
 f.setSchema({type:'object',properties:{text:{type:'string',pattern:'(a+)+$'}}});const refresh=await f.app.inject({method:'POST',url:`/api/v1/upstreams/${tool.upstream_id}/refresh`,headers:{'x-owner':'yes'}});assert.equal(refresh.statusCode,502);
 assert.equal((await c.listTools()).tools.length,0);
 assert.ok(!JSON.stringify(f.events).includes('provider-secret'));
});


test('native provider adapters retain namespace, deny-default, approval and invocation policy',async t=>{
 const f=await fixture(t);f.db.prepare('INSERT INTO connection VALUES(?,?,?,?,?,?,?,?,?,?)').run('native-account','github','work','active',null,'[]',JSON.stringify({secret:'native-secret'}),'{}',null,Date.now());
 let calls=0;f.hub.nativeTools=async()=>[{name:'create_issue',description:'Create an issue',inputSchema:{type:'object',properties:{title:{type:'string'}},required:['title'],additionalProperties:false}}];
 f.hub.nativeCall=async(connection:string,name:string,args:any,signal:AbortSignal)=>{assert.equal(connection,'native-account');assert.equal(name,'create_issue');assert.equal(signal.aborted,false);calls++;return {content:[{type:'text',text:args.title}]};};
 f.db.prepare('INSERT INTO upstream VALUES(?,?,?,?,?,?,?,?)').run('native-upstream','GitHub work','native://github/native-account','native-account','registered','[]',1000,Date.now());
 await f.api('POST','/api/v1/upstreams/native-upstream/refresh');await f.api('POST','/api/v1/upstreams/native-upstream/approve');const tool=(await f.api('GET','/api/v1/tools')).tools[0];
 const c=await f.client();assert.equal((await c.listTools()).tools.length,0);
 await f.api('POST',`/api/v1/tools/${tool.id}/approve`,{risk:'write',enabled:true});f.db.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run('profile',tool.id,'native-account','write');
 const {approval_id}=await f.api('POST','/api/v1/approvals',{client_id:'client',tool_id:tool.id,arguments:{title:'test'}});await c.callTool({name:tool.gateway_name,arguments:{title:'test'},_meta:{unifymcp_approval_id:approval_id}});assert.equal(calls,1);
 f.db.prepare("UPDATE connection SET status='revoked' WHERE id='native-account'").run();await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{title:'test'},_meta:{unifymcp_approval_id:approval_id}}));assert.equal(calls,1);
});

test('gateway routes integrate with the production Hub schema, client auth and audit',async t=>{
 const {Hub,hashToken}=await import('../src/core.js');const {loadConfig}=await import('../src/config.js');const {randomBytes}=await import('node:crypto');
 const hub=new Hub(':memory:',randomBytes(32),loadConfig({}));const app=Fastify();t.after(async()=>{await app.close();hub.close();});
 const profile=(hub.db.prepare('SELECT id FROM profile WHERE is_default=1').get() as any).id;
 hub.db.prepare('INSERT INTO client(id,name,kind,profile_id,token_hash,status,created_at) VALUES(?,?,?,?,?,?,?)').run('real-client','Real','codex',profile,hashToken('real-client-token'),'active',Date.now());
 hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,created_at) VALUES(?,?,?,?,?,?)').run('real-connection','github','work','connected',hub.seal(JSON.stringify({secret:'stored-encrypted'}),'connection:real-connection'),Date.now());
 hub.db.prepare('INSERT INTO upstream VALUES(?,?,?,?,?,?,?,?)').run('real-upstream','Native','native://github/real-connection','real-connection','registered','[]',1000,Date.now());
 (hub as any).nativeTools=async()=>[{name:'read',description:'Read',inputSchema:{type:'object',properties:{},additionalProperties:false}}];(hub as any).nativeCall=async()=>({content:[{type:'text',text:'verified'}]});
 await registerGateway(app,hub,async()=>{});await app.listen({host:'127.0.0.1',port:0});
 let response=await app.inject({method:'POST',url:'/api/v1/upstreams/real-upstream/refresh'});assert.equal(response.statusCode,200,response.body);
 response=await app.inject({method:'POST',url:'/api/v1/upstreams/real-upstream/approve'});assert.equal(response.statusCode,200,response.body);
 const tool=(hub.db.prepare('SELECT * FROM tool').get() as any);response=await app.inject({method:'POST',url:`/api/v1/tools/${tool.id}/approve`,payload:{risk:'read',enabled:true}});assert.equal(response.statusCode,200,response.body);
 hub.db.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run(profile,tool.id,'real-connection','read');
 const client=new Client({name:'real',version:'1'},{versionNegotiation:{mode:'auto'}});t.after(()=>client.close());await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${(app.server.address() as any).port}/mcp`),{requestInit:{headers:{authorization:'Bearer real-client-token'}}}));
 assert.equal((await client.listTools()).tools.length,1);assert.equal((await client.callTool({name:tool.gateway_name,arguments:{}})).content[0]?.type,'text');
 assert.ok((hub.db.prepare('SELECT COUNT(*) AS n FROM audit_event').get() as any).n>=4);
});

test('imported upstreams cannot approve or execute until successful live rediscovery',async t=>{
 const f=await fixture(t);const upstream=await f.add();const tool=(await f.api('GET','/api/v1/tools')).tools[0];await f.api('POST',`/api/v1/tools/${tool.id}/approve`,{risk:'read',enabled:true});f.db.prepare('INSERT INTO profile_grant VALUES(?,?,NULL,?)').run('profile',tool.id,'read');
 const c=await f.client();f.settings.set('import_requires_refresh:'+upstream.id,'true');assert.equal((await c.listTools()).tools.length,0);
 for(const [url,payload] of [[`/api/v1/upstreams/${upstream.id}/approve`,undefined],[`/api/v1/tools/${tool.id}/approve`,{risk:'read',enabled:true}]] as const){const res=await f.app.inject({method:'POST',url,headers:{'x-owner':'yes'},payload});assert.equal(res.statusCode,403);}
 await assert.rejects(c.callTool({name:tool.gateway_name,arguments:{text:'x'}}));assert.equal(f.getCalls(),0);
 await f.api('POST',`/api/v1/upstreams/${upstream.id}/refresh`);assert.notEqual(f.settings.get('import_requires_refresh:'+upstream.id),'true');assert.equal((await c.listTools()).tools.length,1);
});

test('tool listing carries upstream name and status so review screens show exact state',async t=>{
 const f=await fixture(t);await f.add();
 const tools=(await f.api('GET','/api/v1/tools')).tools;
 assert.equal(tools[0].upstream_name,'same-name');
 assert.equal(tools[0].upstream_status,'active');
});
