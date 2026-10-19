import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {Hub} from '../src/core.js';
import {loadConfig} from '../src/config.js';
import {createApp} from '../src/app.js';
const password='Management-local-test-123!';
async function fixture(t:any){
 const reservation=createServer();await new Promise<void>(resolve=>reservation.listen(0,'127.0.0.1',resolve));const reservedPort=(reservation.address() as any).port;await new Promise<void>(resolve=>reservation.close(()=>resolve()));
 const dir=await mkdtemp(join(tmpdir(),'wmcp-management-')),key=randomBytes(32),config=loadConfig({HUB_DATA_DIR:dir,HUB_PORT:String(reservedPort)});
 await writeFile(config.masterKeyFile,key,{mode:0o600});await writeFile(config.bootstrapTokenFile,'setup-token',{mode:0o600});
 const hub=new Hub(':memory:',key,config),app=await createApp(hub);const host=`127.0.0.1:${reservedPort}`;
 await app.inject({method:'POST',url:'/setup/claim',headers:{host},payload:{setup_token:'setup-token',password}});
 const login=await app.inject({method:'POST',url:'/auth/session',headers:{host},payload:{password}}),cookie=String(login.headers['set-cookie']).split(';')[0]!,csrf=login.json().csrf_token;
 const owner=(method:string,url:string,payload?:any)=>app.inject({method:method as any,url,headers:{host,cookie,'x-csrf-token':csrf},payload});
 const issue=async(scopes=['read'])=>{const r=await owner('POST','/api/v1/management/clients',{name:'Manager',scopes,password});assert.equal(r.statusCode,201,r.body);return r.json();};
 const clients:Client[]=[];
 await app.listen({host:'127.0.0.1',port:reservedPort});const port=(app.server.address() as any).port;
 const connect=async(token:string,path='/mcp/manage')=>{const c=new Client({name:'management-test',version:'1'},{versionNegotiation:{mode:'auto'}});clients.push(c);await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}${path}`),{requestInit:{headers:{authorization:'Bearer '+token,host}}}));return c;};
 t.after(async()=>{for(const c of clients)await c.close().catch(()=>{});await app.close();hub.close();await rm(dir,{recursive:true,force:true});});
 return {app,hub,owner,issue,connect,host};
}
test('management discovery is scoped and tokens cannot cross into owner REST or agent gateway',async t=>{
 const f=await fixture(t),issued=await f.issue();
 assert.equal(JSON.stringify(f.hub.db.prepare('SELECT * FROM management_client').all()).includes(issued.token),false);
 assert.ok(issued.config.includes(']\nurl = '));assert.equal(issued.config.includes('\\n'),false);
 const c=await f.connect(issued.token),names=(await c.listTools()).tools.map(x=>x.name);
 assert.ok(names.includes('servers_list'));assert.equal(names.includes('server_create'),false);
 const result=await c.callTool({name:'servers_list',arguments:{}});assert.equal(result.isError,undefined,JSON.stringify(result));
 assert.equal((await c.callTool({name:'server_delete',arguments:{id:'00000000-0000-4000-8000-000000000000',confirm:true}})).isError,true);
 assert.equal(f.hub.db.prepare("SELECT count(*) FROM audit_event WHERE principal=? AND action='management.tool.call' AND resource='server_delete' AND outcome='deny'").pluck().get('management:'+issued.client.id),1);
 assert.equal((await f.app.inject({url:'/api/v1/profiles',headers:{host:f.host,authorization:'Bearer '+issued.token}})).statusCode,403);
 const profile=f.hub.db.prepare('SELECT id FROM profile WHERE is_default=1').get() as any;
 const ordinary=await f.owner('POST','/api/v1/clients',{name:'Ordinary',kind:'codex',profile_id:profile.id});
 await assert.rejects(f.connect(ordinary.json().token));await assert.rejects(f.connect(issued.token,'/mcp'));
});

const value=(result:any)=>{assert.notEqual(result.isError,true,JSON.stringify(result));return JSON.parse(result.content[0].text);};
test('management creates a server, bulk grants access and issues a working agent client using shared policy',async t=>{
 const {Server,createMcpHandler}=await import('@modelcontextprotocol/server');const {toNodeHandler}=await import('@modelcontextprotocol/node');
 const handler=createMcpHandler(()=>{const server=new Server({name:'managed-fixture',version:'1'},{capabilities:{tools:{}}});server.setRequestHandler('tools/list',()=>({tools:[{name:'read_project',description:'Read a project',inputSchema:{type:'object',properties:{}},annotations:{readOnlyHint:true}},{name:'write_project',description:'Write a project',inputSchema:{type:'object',properties:{}}}]}));server.setRequestHandler('tools/call',()=>({content:[{type:'text',text:'fixture-ok'}]}));return server;});
 const node=toNodeHandler(handler),upstream=createServer((req,res)=>{void node(req,res);});await new Promise<void>(resolve=>upstream.listen(0,'127.0.0.1',resolve));
 t.after(async()=>{await handler.close();upstream.closeAllConnections();await new Promise<void>(resolve=>upstream.close(()=>resolve()));});
 const f=await fixture(t),issued=await f.issue(['read','write','delete']),manager=await f.connect(issued.token);
 const server=value(await manager.callTool({name:'server_create',arguments:{name:'Managed MCP',url:`http://127.0.0.1:${(upstream.address() as any).port}/mcp`,allowed_private_ips:['127.0.0.1']}})).upstream;
 const approved=value(await manager.callTool({name:'server_auto_approve',arguments:{id:server.id,trust_server:true}}));assert.equal(approved.approved,2);
 const tools=value(await manager.callTool({name:'tools_list',arguments:{server_id:server.id,limit:1}}));assert.equal(tools.items.length,1);assert.equal(tools.total,2);assert.equal(tools.next_offset,1);
 const secondPage=value(await manager.callTool({name:'tools_list',arguments:{server_id:server.id,offset:1,limit:1,include_metadata:true}}));assert.equal(secondPage.items.length,1);assert.equal(secondPage.next_offset,null);assert.notEqual(secondPage.items[0].id,tools.items[0].id);assert.equal(typeof secondPage.items[0].input_schema,'object');
 const filtered=value(await manager.callTool({name:'tools_list',arguments:{search:'READ_PROJECT',limit:1}}));assert.equal(filtered.total,1);assert.equal(filtered.items[0].name,'read_project');assert.equal('input_schema' in filtered.items[0],false);
 const profile=value(await manager.callTool({name:'profile_create',arguments:{name:'Managed profile'}})).profile;
 value(await manager.callTool({name:'profile_set_access',arguments:{id:profile.id,server_ids:[server.id],confirm_replace:true}}));
 assert.equal(f.hub.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(profile.id),2);
 const invalid=await manager.callTool({name:'profile_set_access',arguments:{id:profile.id,tool_ids:['00000000-0000-4000-8000-000000000000'],confirm_replace:true}});assert.equal(invalid.isError,true);assert.equal(f.hub.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(profile.id),2);
 const issuedAgent=value(await manager.callTool({name:'client_create',arguments:{name:'Managed agent',kind:'codex',profile_id:profile.id}}));
 const agent=await f.connect(issuedAgent.token,'/mcp'),agentTools=(await agent.listTools()).tools;assert.equal(agentTools.length,2);
 const read=agentTools.find(tool=>tool.description==='Read a project')!;assert.equal((await agent.callTool({name:read.name,arguments:{}})).content[0]?.type,'text');
 for(const importedName of ['wheremymcp_manage_custom','wheremymcp_manage_servers_list']){
  f.hub.db.prepare("UPDATE tool SET gateway_name=? WHERE upstream_id=? AND name='read_project'").run(importedName,server.id);
  await agent.listTools();assert.equal((await agent.callTool({name:importedName,arguments:{}})).content[0]?.type,'text');
  assert.match(JSON.stringify(await agent.callTool({name:importedName,arguments:{}})),/fixture-ok/);
 }
 assert.equal((await f.owner('PUT',`/api/v1/clients/${issuedAgent.client.id}/management`,{management_scopes:['read'],password})).statusCode,200);
 const combined=(await agent.listTools()).tools;assert.equal(new Set(combined.map(tool=>tool.name)).size,combined.length);
 assert.ok(combined.some(tool=>tool.name==='wheremymcp_manage_servers_list_builtin_1'));
 assert.equal(value(await agent.callTool({name:'wheremymcp_manage_servers_list_builtin_1',arguments:{}})).upstreams.length,1);
 const write=agentTools.find(tool=>tool.description==='Write a project')!;await assert.rejects(agent.callTool({name:write.name,arguments:{}}));
 const audit=f.hub.db.prepare("SELECT principal FROM audit_event WHERE action='upstream.create' AND resource=?").get(server.id) as any;assert.equal(audit.principal,'management:'+issued.client.id);
 assert.equal((await manager.callTool({name:'server_delete',arguments:{id:server.id,confirm:false}})).isError,true);
 value(await manager.callTool({name:'client_revoke',arguments:{id:issuedAgent.client.id,confirm:true}}));await assert.rejects(agent.listTools());
 const defaultProfile=f.hub.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get() as string;
 assert.equal((await manager.callTool({name:'profile_delete',arguments:{id:defaultProfile,confirm:true}})).isError,true);
 assert.equal(f.hub.db.prepare("SELECT count(*) FROM audit_event WHERE principal=? AND action='management.tool.call' AND resource='profile_delete' AND outcome='deny'").pluck().get('management:'+issued.client.id),1);
 value(await manager.callTool({name:'profile_delete',arguments:{id:profile.id,replacement_profile_id:defaultProfile,confirm:true}}));
 value(await manager.callTool({name:'server_delete',arguments:{id:server.id,confirm:true}}));assert.equal(f.hub.db.prepare('SELECT count(*) FROM upstream WHERE id=?').pluck().get(server.id),0);
});

test('management rotation, expiry and revocation apply to established clients without exposing secrets',async t=>{
 const f=await fixture(t);
 assert.equal((await f.owner('POST','/api/v1/management/clients',{name:'Bad',scopes:['read'],password:'wrong'})).statusCode,403);
 const issued=await f.issue(['read','write']),old=await f.connect(issued.token);
 assert.equal((await old.listTools()).tools.some(tool=>tool.name==='server_delete'),false);
 assert.equal((await old.callTool({name:'management_client_create',arguments:{}})).isError,true);
 assert.equal((await f.app.inject({url:'/api/v1/system/diagnostics',headers:{host:f.host,'x-wheremymcp-dispatch':'forged'}})).statusCode,403);
 assert.equal((await f.owner('POST','/mcp/manage',{})).statusCode,401);
 const metadata=await f.owner('GET','/api/v1/management/clients');assert.equal(metadata.body.includes(issued.token),false);assert.equal(metadata.body.includes('token_hash'),false);
 const rotated=await f.owner('POST',`/api/v1/management/clients/${issued.client.id}/rotate`,{password});assert.equal(rotated.statusCode,200,rotated.body);await assert.rejects(old.listTools());
 const replacement=await f.connect(rotated.json().token);assert.ok((await replacement.listTools()).tools.length>0);
 await f.owner('POST',`/api/v1/management/clients/${issued.client.id}/revoke`);await assert.rejects(replacement.listTools());
 const expiring=await f.issue(),expired=await f.connect(expiring.token);f.hub.db.prepare('UPDATE management_client SET expires_at=? WHERE id=?').run(Date.now()-1,expiring.client.id);await assert.rejects(expired.listTools());
});

test('management token issuance enforces enabled owner MFA',async t=>{
 const {TOTP,Secret}=await import('otpauth');const f=await fixture(t),secret=new Secret({size:20});
 f.hub.db.prepare('UPDATE owner SET mfa_enabled=1,totp_secret=? WHERE id=1').run(f.hub.seal(secret.base32,'owner:totp'));
 const payload={name:'MFA manager',scopes:['read'],password};
 assert.equal((await f.owner('POST','/api/v1/management/clients',payload)).statusCode,403);
 const totp=new TOTP({issuer:'WhereMyMCP',label:'Owner',algorithm:'SHA1',digits:6,period:30,secret});
 assert.equal((await f.owner('POST','/api/v1/management/clients',{...payload,totp:totp.generate()})).statusCode,201);
});

test('management dispatch retains TLS/proxy checks on external public-mode requests',async t=>{
 const f=await fixture(t),issued=await f.issue();
 f.hub.config.publicMode=true;f.hub.config.trustedProxies=['127.0.0.1'];
 const client=new Client({name:'public-management-test',version:'1'});
 t.after(()=>client.close().catch(()=>{}));
 await client.connect(new StreamableHTTPClientTransport(new URL(f.hub.config.origin+'/mcp/manage'),{fetch:async(input,init)=>{
  const request=input instanceof Request?input:new Request(input,init),headers=Object.fromEntries(request.headers);
  headers.host=f.host;headers.authorization='Bearer '+issued.token;headers['x-forwarded-proto']='https';
  const response=await f.app.inject({method:request.method as any,url:new URL(request.url).pathname,headers,remoteAddress:'127.0.0.1',...(request.method==='POST'?{payload:await request.text()}:{})});
  return new Response(response.rawPayload,{status:response.statusCode,headers:response.headers as Record<string,string>});
 }}));
 const result=await client.callTool({name:'diagnostics_get',arguments:{}});assert.equal(value(result).public_mode,true);
 assert.equal((await f.app.inject({url:'/api/v1/profiles',headers:{host:f.host,authorization:'Bearer '+issued.token}})).statusCode,403);
});

test('one agent token gains scoped management on the same MCP endpoint only after owner step-up',async t=>{
 const f=await fixture(t),profileId=f.hub.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get() as string;
 const issued=await f.owner('POST','/api/v1/clients',{name:'Unified client',kind:'codex',profile_id:profileId});assert.equal(issued.statusCode,201);
 const token=issued.json().token,clientId=issued.json().client.id,c=await f.connect(token,'/mcp');assert.equal((await c.listTools()).tools.length,0);
 const access=`/api/v1/clients/${clientId}/management`;
 assert.equal((await f.owner('PUT',access,{management_scopes:['read','write'],password:'wrong'})).statusCode,403);
 assert.equal((await f.owner('PUT',access,{management_scopes:['read','write'],password})).statusCode,200);
 let tools=(await c.listTools()).tools;assert.equal(tools.length,21);assert.ok(tools.some(tool=>tool.name==='wheremymcp_manage_servers_list'));assert.equal(tools.some(tool=>tool.name==='wheremymcp_manage_server_delete'),false);
 const created=value(await c.callTool({name:'wheremymcp_manage_profile_create',arguments:{name:'Unified managed'}})).profile;
 assert.equal(f.hub.db.prepare("SELECT principal FROM audit_event WHERE action='profile.create' AND resource=?").pluck().get(created.id),'management:'+clientId);
 assert.equal((await c.callTool({name:'wheremymcp_manage_client_create',arguments:{name:'Escalation',kind:'codex',profile_id:profileId,management_scopes:['delete'],password}})).isError,true);
 assert.equal((await c.callTool({name:'wheremymcp_manage_client_rotate',arguments:{id:clientId}})).isError,true,'management Write must not steal a privileged token');
 assert.equal((await f.app.inject({method:'PUT',url:access,headers:{host:f.host,authorization:'Bearer '+token},payload:{management_scopes:['delete'],password}})).statusCode,403);
 assert.equal((await f.owner('POST',`/api/v1/clients/${clientId}/rotate`)).statusCode,403,'privileged rotation needs owner verification');
 const rotated=await f.owner('POST',`/api/v1/clients/${clientId}/rotate`,{password});assert.equal(rotated.statusCode,200);await assert.rejects(c.listTools());
 const replacement=await f.connect(rotated.json().token,'/mcp');assert.equal((await replacement.listTools()).tools.length,21);
 assert.equal((await f.owner('PUT',access,{management_scopes:[]})).statusCode,200);assert.equal((await replacement.listTools()).tools.length,0);assert.equal((await replacement.callTool({name:'wheremymcp_manage_servers_list',arguments:{}})).isError,true);
 await f.owner('POST',`/api/v1/clients/${clientId}/revoke`);await assert.rejects(replacement.listTools());
});

test('owner can issue one privileged client atomically, but delegated managers cannot rotate it',async t=>{
 const f=await fixture(t),profileId=f.hub.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get() as string;
 const body={name:'Owner admin',kind:'claude',profile_id:profileId,management_scopes:['read','write','delete']};
 assert.equal((await f.owner('POST','/api/v1/clients',body)).statusCode,403);
 assert.equal(f.hub.db.prepare('SELECT count(*) FROM client').pluck().get(),0);
 const response=await f.owner('POST','/api/v1/clients',{...body,password});assert.equal(response.statusCode,201,response.body);
 const issued=response.json(),manager=await f.connect(issued.token,'/mcp');assert.equal((await manager.listTools()).tools.length,24);
 const legacy=await f.issue(['read','write']),legacyClient=await f.connect(legacy.token);
 assert.equal((await legacyClient.callTool({name:'client_rotate',arguments:{id:issued.client.id}})).isError,true);
 for(const kind of ['codex','claude','cursor','gemini','hermes','other']){
  const config=(await f.owner('GET',`/api/v1/clients/${issued.client.id}/config?kind=${kind}`)).json();assert.ok(config.snippet.includes('/mcp'));assert.equal(config.snippet.includes('/mcp/manage'),false);assert.equal(config.snippet.includes(issued.token),false);
 }
 const metadata=await f.owner('GET','/api/v1/clients');assert.deepEqual(metadata.json().clients[0].management_scopes,['read','write','delete']);assert.equal(metadata.body.includes('token_hash'),false);
 f.hub.db.prepare('UPDATE client SET expires_at=? WHERE id=?').run(Date.now()-1,issued.client.id);await assert.rejects(manager.listTools());
});

test('merged provider and management discovery paginates without duplicates and stop blocks only provider access',async t=>{
 const f=await fixture(t),profileId=f.hub.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get() as string;
 const issued=await f.owner('POST','/api/v1/clients',{name:'Paged manager',kind:'codex',profile_id:profileId,management_scopes:['read'],password});assert.equal(issued.statusCode,201,issued.body);
 const c=await f.connect(issued.json().token,'/mcp');
 f.hub.db.prepare("INSERT INTO upstream(id,name,url,status,created_at) VALUES('fixture','Fixture','https://example.invalid/mcp','active',0)").run();
 for(let i=0;i<65;i++){const id='fixture-'+i;f.hub.db.prepare(`INSERT INTO tool(id,upstream_id,name,gateway_name,input_schema,fingerprint,approved_fingerprint,risk,enabled) VALUES(?,'fixture',?,?,'{"type":"object"}','fp','fp','read',1)`).run(id,id,id);f.hub.db.prepare("INSERT INTO profile_grant VALUES(?,?,NULL,'read')").run(profileId,id);}
 const all=await c.listTools(),first=await c.listTools({cursor:'0'}),second=await c.listTools({cursor:first.nextCursor});assert.equal(all.tools.length,75);assert.equal(first.tools.length,64);assert.equal(second.tools.length,11);assert.equal(second.nextCursor,undefined);assert.equal(new Set([...first.tools,...second.tools].map(tool=>tool.name)).size,75);
 f.hub.setSetting('emergency_stop','true');assert.equal((await c.listTools()).tools.length,10);assert.equal(value(await c.callTool({name:'wheremymcp_manage_diagnostics_get',arguments:{}})).schema_version,4);await assert.rejects(c.callTool({name:'fixture-0',arguments:{}}));
});

test('unified management issuance requires the owner second factor when MFA is enabled',async t=>{
 const {TOTP,Secret}=await import('otpauth'),f=await fixture(t),secret=new Secret({size:20});
 f.hub.db.prepare('UPDATE owner SET mfa_enabled=1,totp_secret=? WHERE id=1').run(f.hub.seal(secret.base32,'owner:totp'));
 const profile_id=f.hub.db.prepare('SELECT id FROM profile WHERE is_default=1').pluck().get();
 const body={name:'MFA unified',kind:'codex',profile_id,management_scopes:['read'],password};
 assert.equal((await f.owner('POST','/api/v1/clients',body)).statusCode,403);
 assert.equal(f.hub.db.prepare('SELECT count(*) FROM client').pluck().get(),0);
 const otp=new TOTP({issuer:'WhereMyMCP',label:'Owner',algorithm:'SHA1',digits:6,period:30,secret});
 assert.equal((await f.owner('POST','/api/v1/clients',{...body,totp:otp.generate()})).statusCode,201);
});
