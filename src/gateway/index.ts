import { createHash, randomUUID } from 'node:crypto';
import type {FastifyInstance,FastifyRequest,preHandlerHookHandler} from 'fastify';
import {Server,createMcpHandler,ProtocolError,type Tool,type CallToolResult} from '@modelcontextprotocol/server';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {Ajv} from 'ajv';
import {Ajv2020} from 'ajv/dist/2020.js';
import safeRegex from 'safe-regex2';
import type {Hub} from '../core.js';
import {safeFetch,validateTarget} from './network.js';
export {safeFetch,validateTarget} from './network.js';

type Upstream={id:string;name:string;url:string;connection_id:string|null;status:string;allowed_private_ips:string;timeout_ms:number;created_at:number};
type ToolRow={id:string;upstream_id:string;name:string;gateway_name:string;description:string;input_schema:string;annotations:string;fingerprint:string;approved_fingerprint:string|null;risk:string;enabled:number;previous_metadata:string|null};
type NativeHub=Hub & {nativeTools?:(connectionId:string)=>Promise<Tool[]>;nativeCall?:(connectionId:string,name:string,args:Record<string,unknown>,signal?:AbortSignal)=>Promise<CallToolResult>};
function cancellable<T>(promise:Promise<T>,signal:AbortSignal):Promise<T>{signal.throwIfAborted();return new Promise((resolve,reject)=>{const abort=()=>reject(new Error('upstream_cancelled'));signal.addEventListener('abort',abort,{once:true});promise.then(resolve,reject).finally(()=>signal.removeEventListener('abort',abort));});}
type ClientRow={id:string;profile_id:string;status:string;expires_at:number|null};
const ajv=new Ajv({allErrors:false,strict:false,validateFormats:false,ownProperties:true,addUsedSchema:false});
const ajv2020=new Ajv2020({allErrors:false,strict:false,validateFormats:false,ownProperties:true,addUsedSchema:false});
function schemaValidator(schema:Record<string,unknown>){return typeof schema.$schema==='string'&&/^https:\/\/json-schema\.org\/draft\/2020-12\/schema#?$/.test(schema.$schema)?ajv2020:ajv;}
const maxTools=256;
function safeSchema(schema:unknown):void {
 let nodes=0;
 const visit=(value:unknown):void=>{if(++nodes>2048)fail('schema_too_complex');if(value&&typeof value==='object')for(const[key,item]of Object.entries(value)){if((key==='pattern'&&typeof item==='string'&&(!safeRegex(item,{limit:16})||item.length>256))||key==='patternProperties')fail('unsafe_schema_pattern');visit(item);}};visit(schema);
}
function redact(value:unknown,secrets:string[]):unknown {
 if(typeof value==='string'){let text=value;for(const secret of secrets)if(secret)text=text.split(secret).join('[REDACTED]');return text;}
 if(Array.isArray(value))return value.map(item=>redact(item,secrets));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[redact(key,secrets) as string,redact(item,secrets)]));return value;
}
function fail(code:string,statusCode=400):never {throw Object.assign(new Error(code),{statusCode});}
function protocolFail():never {throw new ProtocolError(-32000,'Gateway policy denied or upstream unavailable');}
function canonical(value:unknown):string {
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
 return JSON.stringify(value)??'null';
}
export function argumentHash(value:unknown):string{return createHash('sha256').update(canonical(value)).digest('hex');}
function bounded(value:unknown,maxBytes=65536,depth=0):void {
 if(depth===0 && Buffer.byteLength(JSON.stringify(value)??'')>maxBytes)fail('payload_too_large',413);
 if(depth>24)fail('payload_too_deep');
 if(value&&typeof value==='object')for(const item of Object.values(value))bounded(item,maxBytes,depth+1);
}
function body(req:FastifyRequest):Record<string,unknown>{if(!req.body||typeof req.body!=='object'||Array.isArray(req.body))fail('invalid_body');bounded(req.body);return req.body as Record<string,unknown>;}
function identifier(req:FastifyRequest):string{return (req.params as {id:string}).id;}
function parseTool(tool:ToolRow){return {...tool,input_schema:JSON.parse(tool.input_schema),annotations:JSON.parse(tool.annotations),previous_metadata:tool.previous_metadata?JSON.parse(tool.previous_metadata):null};}
function toolDefinition(tool:ToolRow):Tool{return {name:tool.gateway_name,description:tool.description,inputSchema:JSON.parse(tool.input_schema),annotations:JSON.parse(tool.annotations)};}

export async function registerGateway(app:FastifyInstance,hub:Hub,requireOwner:preHandlerHookHandler):Promise<void>{
 const locks=new Set<string>();const failures=new Map<string,number>();let active=0;
 const audit=(action:string,resource:string,outcome='success',detail?:string,principal='owner',latency_ms?:number)=>hub.audit({action,resource,outcome,detail,principal,latency_ms});
 const stopped=()=>['true','1'].includes(hub.setting('emergency_stop')??'false');
 const getUpstream=(id:string):Upstream=>{const u=hub.db.prepare('SELECT * FROM upstream WHERE id=?').get(id) as Upstream|undefined;if(!u)fail('upstream_not_found',404);return u;};
 const getTool=(id:string):ToolRow=>{const tool=hub.db.prepare('SELECT * FROM tool WHERE id=?').get(id) as ToolRow|undefined;if(!tool)fail('tool_not_found',404);return tool;};
 const lock=(u:Upstream)=>{if(active>=8||locks.has(u.id))fail('upstream_busy',429);locks.add(u.id);active++;return ()=>{locks.delete(u.id);active--;};};
 function authorization(client:ClientRow,tool:ToolRow):Upstream {
  const fresh=hub.db.prepare('SELECT * FROM client WHERE id=?').get(client.id) as ClientRow|undefined;
  if(stopped()||!fresh||fresh.status!=='active'||(fresh.expires_at!=null&&fresh.expires_at<=Date.now())||!hub.db.prepare('SELECT id FROM profile WHERE id=?').get(fresh.profile_id))fail('policy_denied',403);
  const current=getTool(tool.id);const u=getUpstream(current.upstream_id);
  if(hub.setting('import_requires_refresh:'+u.id)==='true'||u.status!=='active'||!current.enabled||current.fingerprint!==current.approved_fingerprint||current.fingerprint!==tool.fingerprint||current.risk!==tool.risk||!['read','write','delete'].includes(current.risk))fail('policy_denied',403);
  const grant=hub.db.prepare('SELECT * FROM profile_grant WHERE profile_id=? AND tool_id=? AND connection_id IS ? AND action_class=?').get(fresh.profile_id,current.id,u.connection_id,current.risk);
  if(!grant)fail('policy_denied',403);
  if(u.connection_id){const c=hub.db.prepare('SELECT status,expires_at FROM connection WHERE id=?').get(u.connection_id) as {status:string;expires_at:number|null}|undefined;if(!c||!['active','connected'].includes(c.status)||(c.expires_at!=null&&c.expires_at<=Date.now()))fail('connection_unavailable',403);}
  return u;
 }
 async function credentials(u:Upstream):Promise<{headers:Headers;secret:string;allowedOrigin?:string}>{
  const headers=new Headers();if(!u.connection_id)return {headers,secret:''};
  const c=hub.db.prepare('SELECT * FROM connection WHERE id=?').get(u.connection_id) as {id:string;provider:string;credential:string;config:string;status:string;expires_at:number|null}|undefined;
  if(!c||!['active','connected'].includes(c.status)||(c.expires_at!=null&&c.expires_at<=Date.now()))fail('connection_unavailable',403);
  const resolver=(hub as Hub & {resolveConnectionCredential?:(id:string)=>Promise<{secret?:string;access_token?:string}>}).resolveConnectionCredential;const secretData=resolver?await resolver.call(hub,c.id):JSON.parse(hub.open(c.credential,'connection:'+c.id)) as {secret?:string;access_token?:string};const config=JSON.parse(c.config||'{}') as {header_name?:string;allowed_origin?:string};const secret=secretData.secret??secretData.access_token;
  if(!secret||typeof secret!=='string'||/[\r\n]/.test(secret))fail('invalid_connection',403);
  if(c.provider==='api_key'){
   const name=config.header_name??'';if(!/^[a-zA-Z0-9_-]{1,80}$/.test(name)||/^(host|cookie|content-|mcp-|proxy-|connection|transfer-|accept|origin)/i.test(name))fail('invalid_credential_header');headers.set(name,secret);
  }else headers.set('authorization','Bearer '+secret);
  const origin=new URL(u.url).origin;if(config.allowed_origin&&config.allowed_origin!==origin)fail('credential_origin_mismatch',403);
  return {headers,secret,allowedOrigin:origin};
 }
 async function connected<T>(u:Upstream,signal:AbortSignal,work:(client:Client,secret:string)=>Promise<T>):Promise<T>{
  const auth=await credentials(u);const client=new Client({name:'wheremymcp',version:'0.1.0'},{inputRequired:{autoFulfill:false},versionNegotiation:{mode:'auto',probe:{timeoutMs:Math.min(u.timeout_ms,3000),maxRetries:0}},listMaxPages:8});
  const transport=new StreamableHTTPClientTransport(new URL(u.url),{requestInit:{headers:auth.headers,redirect:'manual'},onInsufficientScope:'throw',reconnectionOptions:{maxRetries:0,maxReconnectionDelay:1000,initialReconnectionDelay:1000,reconnectionDelayGrowFactor:1},fetch:(input,init)=>safeFetch(input, {...init,signal:AbortSignal.any([signal,...(init?.signal?[init.signal]:[])])},{allowedPrivateIps:JSON.parse(u.allowed_private_ips),timeoutMs:u.timeout_ms,maxResponseBytes:1_048_576,allowedOrigin:auth.allowedOrigin})});
  try{try{await client.connect(transport,{signal,timeout:u.timeout_ms});}catch{throw Object.assign(new Error('upstream_connect_failure'),{upstream_id:u.id});}return await work(client,auth.secret);}finally{await client.close().catch(()=>{});}
 }
 async function refresh(u:Upstream):Promise<{tools_count:number;names:string[]}>{
  const release=lock(u);const signal=AbortSignal.timeout(u.timeout_ms);try{
   const native=(hub as NativeHub);
   const {tools,version}=u.url.startsWith('native://')?{tools:await cancellable(native.nativeTools!(u.connection_id!),signal),version:{name:'unifymcp-native',version:'1'}}:await connected(u,signal,async client=>{
    const tools:Tool[]=[];let cursor:string|undefined;const cursors=new Set<string>();
    for(let page=0;page<8;page++){
     const result=await client.listTools(cursor?{cursor}:undefined,{signal,timeout:u.timeout_ms,maxTotalTimeout:u.timeout_ms});
     tools.push(...result.tools);if(tools.length>maxTools)fail('too_many_tools');
     cursor=result.nextCursor;if(!cursor)break;if(cursors.has(cursor)||page===7)fail('invalid_pagination');cursors.add(cursor);
    }
    return {tools,version:client.getServerVersion()};
   });
   if(tools.length>maxTools)fail('too_many_tools');
   const seen=new Set<string>();
   const validated=tools.map(tool=>{
    bounded(tool);if(!/^[a-zA-Z0-9_.:-]{1,128}$/.test(tool.name)||seen.has(tool.name))fail('invalid_tool');seen.add(tool.name);
    if(tool.description&&tool.description.length>12000)fail('invalid_tool');
    safeSchema(tool.inputSchema);const validator=schemaValidator(tool.inputSchema);if(!validator.validateSchema(tool.inputSchema))fail('invalid_schema');validator.compile(tool.inputSchema);
    const metadata={description:tool.description??'',input_schema:tool.inputSchema,annotations:tool.annotations??{}};
    return {tool,metadata,fingerprint:argumentHash({...tool,server:version})};
   });
   const current=getUpstream(u.id);
   if(current.url!==u.url||current.connection_id!==u.connection_id||current.allowed_private_ips!==u.allowed_private_ips)fail('upstream_changed_during_discovery',409);
   hub.db.transaction(()=>{
    const existing=hub.db.prepare('SELECT * FROM tool WHERE upstream_id=?').all(u.id) as ToolRow[];
    for(const {tool,metadata,fingerprint}of validated){
     const old=existing.find(t=>t.name===tool.name);
     if(!old){const id=randomUUID();const gatewayName='u_'+u.id.replaceAll('-','')+'__'+createHash('sha256').update(tool.name).digest('hex');hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,description,input_schema,annotations,fingerprint,approved_fingerprint,risk,enabled) VALUES(?,?,?,?,?,?,?,?,NULL,?,0)').run(id,u.id,tool.name,gatewayName,metadata.description,JSON.stringify(metadata.input_schema),JSON.stringify(metadata.annotations),fingerprint,'unreviewed');}
     else if(old.fingerprint!==fingerprint){const previous=old.approved_fingerprint===old.fingerprint?JSON.stringify({description:old.description,input_schema:JSON.parse(old.input_schema),annotations:JSON.parse(old.annotations),fingerprint:old.fingerprint}):old.previous_metadata;hub.db.prepare('UPDATE tool SET description=?,input_schema=?,annotations=?,fingerprint=?,enabled=0,previous_metadata=? WHERE id=?').run(metadata.description,JSON.stringify(metadata.input_schema),JSON.stringify(metadata.annotations),fingerprint,previous,old.id);audit('tool.drift',old.id,'quarantined','metadata_changed');}
    }
    for(const old of existing)if(!seen.has(old.name))hub.db.prepare('UPDATE tool SET enabled=0,approved_fingerprint=NULL WHERE id=?').run(old.id);
    hub.setSetting('import_requires_refresh:'+u.id,'false');failures.delete(u.id);if(u.status==='error')hub.db.prepare("UPDATE upstream SET status='pending_review' WHERE id=?").run(u.id);
   })();audit('upstream.refresh',u.id);return {tools_count:tools.length,names:tools.map(tool=>tool.name)};
  }catch{hub.db.prepare("UPDATE upstream SET status='error' WHERE id=? AND status!='disabled'").run(u.id);audit('upstream.refresh',u.id,'failure','discovery_failed');fail('upstream_discovery_failed',502);}finally{release();}
 }
 app.get('/api/v1/upstreams',{preHandler:requireOwner},async()=>({upstreams:(hub.db.prepare('SELECT * FROM upstream ORDER BY created_at,id').all() as Upstream[]).map(u=>({...u,allowed_private_ips:JSON.parse(u.allowed_private_ips)}))}));
 app.post('/api/v1/upstreams',{preHandler:requireOwner},async req=>{
  const b=body(req);if(typeof b.name!=='string'||!b.name.trim()||b.name.length>120||typeof b.url!=='string')fail('invalid_upstream');
  if(b.transport&&b.transport!=='streamable_http')fail('unsupported_transport');
  if(Number((hub.db.prepare('SELECT COUNT(*) AS n FROM upstream').get() as {n:number}).n)>=128)fail('upstream_limit',429);
  const allowed=b.allowed_private_ips??[];if(!Array.isArray(allowed)||allowed.some(ip=>typeof ip!=='string'))fail('invalid_private_exception');
  try{await validateTarget(b.url,allowed);}catch{fail('invalid_or_blocked_target');}
  if(b.connection_id!=null&&(typeof b.connection_id!=='string'||!hub.db.prepare("SELECT id FROM connection WHERE id=? AND status IN ('active','connected')").get(b.connection_id)))fail('invalid_connection');
  const timeout=Number(b.timeout_ms??15_000);if(!Number.isInteger(timeout)||timeout<100||timeout>60_000)fail('invalid_timeout');
  const id=randomUUID();hub.db.prepare('INSERT INTO upstream VALUES(?,?,?,?,?,?,?,?)').run(id,b.name.trim(),b.url,b.connection_id??null,'pending_review',JSON.stringify(allowed),timeout,Date.now());audit('upstream.create',id);if(allowed.length)audit('upstream.private_exception',id,'success','exact_ip_allowlist');return {upstream:{...getUpstream(id),allowed_private_ips:allowed}};
 });
 app.post('/api/v1/upstreams/:id/refresh',{preHandler:requireOwner},async req=>({tools_count:(await refresh(getUpstream(identifier(req)))).tools_count}));
 app.post('/api/v1/upstreams/:id/auto-approve-tools',{preHandler:requireOwner},async req=>{
  if(body(req).trust_server!==true)fail('explicit_server_trust_required');
  const original=getUpstream(identifier(req)),discovery=await refresh(original);
  if(!discovery.names.length)fail('no_current_tools_discovered',409);
  const names=new Set(discovery.names),riskCounts={read:0,write:0,delete:0};let approved=0;
  hub.db.transaction(()=>{
   const current=getUpstream(original.id);
   if(current.url!==original.url||current.connection_id!==original.connection_id||current.allowed_private_ips!==original.allowed_private_ips||(current.status!==original.status&&!(original.status==='error'&&current.status==='pending_review')))fail('upstream_changed_during_review',409);
   const tools=hub.db.prepare('SELECT * FROM tool WHERE upstream_id=?').all(original.id) as ToolRow[];
   for(const tool of tools){
    if(!names.has(tool.name))continue;
    const hints=JSON.parse(tool.annotations),risk=hints.destructiveHint===true?'delete':hints.readOnlyHint===true?'read':'write';
    hub.db.prepare('UPDATE tool SET risk=?,enabled=1,approved_fingerprint=fingerprint,previous_metadata=NULL WHERE id=?').run(risk,tool.id);
    hub.db.prepare('DELETE FROM approval WHERE tool_id=?').run(tool.id);riskCounts[risk]++;approved++;audit('tool.approve',tool.id,'success','trusted_server_annotations');
   }
   hub.db.prepare("UPDATE upstream SET status='active' WHERE id=?").run(original.id);audit('upstream.tools.auto_approve',original.id,'success','explicit_server_trust');
  })();return {approved,risk_counts:riskCounts};
 });
 app.post('/api/v1/upstreams/:id/approve',{preHandler:requireOwner},async req=>{const u=getUpstream(identifier(req));if(hub.setting('import_requires_refresh:'+u.id)==='true')fail('live_refresh_required',403);if(u.status==='error')fail('refresh_required');hub.db.prepare("UPDATE upstream SET status='active' WHERE id=?").run(u.id);audit('upstream.approve',u.id);return {upstream:getUpstream(u.id)};});
 app.post('/api/v1/upstreams/:id/disable',{preHandler:requireOwner},async req=>{const u=getUpstream(identifier(req));hub.db.prepare("UPDATE upstream SET status='disabled' WHERE id=?").run(u.id);audit('upstream.disable',u.id);return {upstream:getUpstream(u.id)};});
 app.patch('/api/v1/upstreams/:id',{preHandler:requireOwner},async req=>{
  const u=getUpstream(identifier(req));const b=body(req);
  const name=typeof b.name==='string'&&b.name.trim()?(b.name.trim() as string).slice(0,120):u.name;
  const url=typeof b.url==='string'?b.url:u.url;
  const allowed=b.allowed_private_ips??JSON.parse(u.allowed_private_ips||'[]');
  if(!Array.isArray(allowed)||allowed.some((ip:any)=>typeof ip!=='string'))fail('invalid_private_exception');
  const connectionId=b.connection_id===undefined?u.connection_id:b.connection_id;
  if(connectionId!=null&&(typeof connectionId!=='string'||!hub.db.prepare("SELECT id FROM connection WHERE id=? AND status IN ('active','connected')").get(connectionId)))fail('invalid_connection');
  const timeout=Number(b.timeout_ms??u.timeout_ms);if(!Number.isInteger(timeout)||timeout<100||timeout>60_000)fail('invalid_timeout');
  try{await validateTarget(url,allowed as string[]);}catch{fail('invalid_or_blocked_target');}
  const urlChanged=url!==u.url,allowedChanged=JSON.stringify(allowed)!==JSON.stringify(JSON.parse(u.allowed_private_ips||'[]'));
  hub.db.prepare('UPDATE upstream SET name=?,url=?,connection_id=?,status=?,allowed_private_ips=?,timeout_ms=? WHERE id=?').run(name,url,connectionId??null,'registered',JSON.stringify(allowed),timeout,u.id);
  if(urlChanged||allowedChanged)hub.setSetting('import_requires_refresh:'+u.id,'true');
  audit('upstream.update',u.id);if(allowedChanged&&(allowed as string[]).length)audit('upstream.private_exception',u.id,'success','exact_ip_allowlist');
  return {upstream:{...getUpstream(u.id),allowed_private_ips:allowed}};
 });
 app.delete('/api/v1/upstreams/:id',{preHandler:requireOwner},async req=>{
  const u=getUpstream(identifier(req));
  hub.db.prepare('DELETE FROM upstream WHERE id=?').run(u.id);
  hub.db.prepare('DELETE FROM settings WHERE key=?').run(`import_requires_refresh:${u.id}`);
  audit('upstream.delete',u.id);return {deleted:true};
 });
 app.get('/api/v1/tools',{preHandler:requireOwner},async()=>({tools:(hub.db.prepare('SELECT tool.*,upstream.connection_id,upstream.name AS upstream_name,upstream.status AS upstream_status FROM tool JOIN upstream ON upstream.id=tool.upstream_id ORDER BY gateway_name').all() as ToolRow[]).map(parseTool)}));
 app.post('/api/v1/tools/:id/approve',{preHandler:requireOwner},async req=>{const tool=getTool(identifier(req));if(hub.setting('import_requires_refresh:'+tool.upstream_id)==='true')fail('live_refresh_required',403);const b=body(req);if(!['read','write','delete'].includes(String(b.risk))||typeof b.enabled!=='boolean')fail('invalid_tool_approval');hub.db.prepare('UPDATE tool SET risk=?,enabled=?,approved_fingerprint=fingerprint,previous_metadata=NULL WHERE id=?').run(b.risk,b.enabled?1:0,tool.id);hub.db.prepare('DELETE FROM approval WHERE tool_id=?').run(tool.id);audit('tool.approve',tool.id);return {tool:parseTool(getTool(tool.id))};});
 app.post('/api/v1/approvals',{preHandler:requireOwner},async req=>{const b=body(req);if(typeof b.client_id!=='string'||typeof b.tool_id!=='string'||!b.arguments||typeof b.arguments!=='object'||Array.isArray(b.arguments))fail('invalid_approval');const tool=getTool(b.tool_id);const c=hub.db.prepare('SELECT * FROM client WHERE id=?').get(b.client_id) as ClientRow|undefined;if(!c)fail('invalid_client');authorization(c,tool);if(!['write','delete'].includes(tool.risk))fail('approval_not_required');const schema=JSON.parse(tool.input_schema);if(!schemaValidator(schema).compile(schema)(b.arguments))fail('invalid_arguments');const ttl=Number(b.ttl_seconds??120);if(!Number.isInteger(ttl)||ttl<1||ttl>300)fail('invalid_approval_ttl');const id=randomUUID();hub.db.prepare('INSERT INTO approval VALUES(?,?,?,?,?,NULL)').run(id,c.id,tool.id,argumentHash(b.arguments),Date.now()+ttl*1000);audit('approval.create',id);return {approval_id:id};});

 async function invoke(req:FastifyRequest,name:string,args:Record<string,unknown>,approval:unknown,cancel:AbortSignal):Promise<CallToolResult>{
  const start=Date.now();let principal='client';let resource='unknown';let release:(()=>void)|undefined;let timer:NodeJS.Timeout|undefined;let calledUpstream:string|undefined;
  try{
   const c=hub.requireClient(req);principal=c.id;const tool=hub.db.prepare('SELECT * FROM tool WHERE gateway_name=?').get(name) as ToolRow|undefined;if(!tool)fail('policy_denied',403);resource=tool.id;
   bounded(args);const u=authorization(c,tool);const schema=JSON.parse(tool.input_schema);if(!schemaValidator(schema).compile(schema)(args))fail('invalid_arguments');release=lock(u);
   const revoked=new AbortController();const signal=AbortSignal.any([cancel,revoked.signal,AbortSignal.timeout(u.timeout_ms)]);
   timer=setInterval(()=>{try{authorization(c,tool);}catch{revoked.abort();}},50);timer.unref();
   const execute=async(call:()=>Promise<CallToolResult>,secrets:string[]):Promise<CallToolResult>=>{
    authorization(hub.requireClient(req),tool);signal.throwIfAborted();
    if(tool.risk!=='read'){
     if(typeof approval!=='string')fail('approval_required',403);
     const consumed=hub.db.prepare('UPDATE approval SET used_at=? WHERE id=? AND client_id=? AND tool_id=? AND arguments_hash=? AND expires_at>? AND used_at IS NULL').run(Date.now(),approval,c.id,tool.id,argumentHash(args),Date.now());if(consumed.changes!==1)fail('approval_required',403);
    }
    calledUpstream=u.id;const output=await cancellable(call(),signal);
    authorization(hub.requireClient(req),tool);signal.throwIfAborted();bounded(output,1_048_576);
    const incoming=req.headers.authorization?.replace(/^Bearer /i,'')??'';
    failures.delete(u.id);return redact(output,[...secrets,incoming]) as CallToolResult;
   };
   const native=hub as NativeHub;let result:CallToolResult;
   if(u.url.startsWith('native://')){const resolver=(hub as Hub & {resolveConnectionCredential?:(id:string)=>Promise<Record<string,unknown>>}).resolveConnectionCredential;const connection=hub.db.prepare('SELECT credential FROM connection WHERE id=?').get(u.connection_id) as {credential:string};const data=resolver?await cancellable(resolver.call(hub,u.connection_id!),signal):JSON.parse(hub.open(connection.credential,'connection:'+u.connection_id));const secrets=[data.secret,data.access_token,data.refresh_token].filter((value):value is string=>typeof value==='string');result=await execute(()=>native.nativeCall!(u.connection_id!,tool.name,args,signal),secrets);}
   else result=await connected(u,signal,(client,secret)=>execute(()=>client.callTool({name:tool.name,arguments:args},{signal,timeout:u.timeout_ms,maxTotalTimeout:u.timeout_ms,toolDefinition:{...toolDefinition(tool),name:tool.name}}),[secret]));audit('tool.call',resource,'success',undefined,principal,Date.now()-start);return result;
  }catch(error){calledUpstream??=(error as {upstream_id?:string})?.upstream_id;if(calledUpstream){const count=(failures.get(calledUpstream)??0)+1;failures.set(calledUpstream,count);if(count>=3||(resource!=='unknown'&&getTool(resource).risk!=='read')){hub.db.prepare("UPDATE upstream SET status='error' WHERE id=? AND status='active'").run(calledUpstream);audit('upstream.circuit_open',calledUpstream,'quarantined','repeated_or_uncertain_failure');}}audit('tool.call',resource,calledUpstream?'failure':'denied',calledUpstream?'upstream_outcome_unknown':'policy_or_upstream_failure',principal,Date.now()-start);return protocolFail();}finally{if(timer)clearInterval(timer);release?.();}
 }
 app.route({method:['GET','POST','DELETE'],url:'/mcp',handler:async(req,reply)=>{
  hub.requireClient(req);if(req.headers.origin&&req.headers.origin!==hub.config.origin)fail('invalid_origin',403);
  if(req.method!=='POST')return reply.code(405).send({error:'method_not_allowed'});
  bounded(req.body,hub.config.maxBodyBytes);
  const disconnect=new AbortController();const abort=()=>{if(!reply.raw.writableEnded)disconnect.abort();};reply.raw.once('close',abort);
  const handler=createMcpHandler(()=>{
   const server=new Server({name:'wheremymcp',version:'0.1.0'},{capabilities:{tools:{}},cacheHints:{'tools/list':{ttlMs:0,cacheScope:'private'}}});
   server.setRequestHandler('tools/list',request=>{
    const client=hub.requireClient(req),now=Date.now();
    const candidates=hub.db.prepare(`SELECT t.* FROM client cl JOIN profile p ON p.id=cl.profile_id
      JOIN profile_grant g ON g.profile_id=p.id JOIN tool t ON t.id=g.tool_id JOIN upstream u ON u.id=t.upstream_id
      LEFT JOIN connection c ON c.id=u.connection_id
      WHERE cl.id=? AND cl.status='active' AND (cl.expires_at IS NULL OR cl.expires_at>?)
      AND t.enabled=1 AND t.fingerprint=t.approved_fingerprint AND t.risk IN ('read','write','delete')
      AND u.status='active' AND g.connection_id IS u.connection_id AND g.action_class=t.risk
      AND (u.connection_id IS NULL OR (c.status IN ('active','connected') AND (c.expires_at IS NULL OR c.expires_at>?)))
      ORDER BY t.gateway_name`).all(client.id,now,now) as ToolRow[];
    const refreshRequired=new Map<string,boolean>();
    const tools=stopped()?[]:candidates.filter(tool=>{if(!refreshRequired.has(tool.upstream_id))refreshRequired.set(tool.upstream_id,hub.setting('import_requires_refresh:'+tool.upstream_id)==='true');return !refreshRequired.get(tool.upstream_id);});
    const cursor=request.params?.cursor;const offset=cursor?Number(cursor):0;if(!Number.isSafeInteger(offset)||offset<0||offset>tools.length)throw new ProtocolError(-32602,'Invalid cursor');const page=tools.slice(offset,offset+64);return {tools:page.map(toolDefinition),...(offset+64<tools.length?{nextCursor:String(offset+64)}:{})};
   });
   server.setRequestHandler('tools/call',(request,ctx)=>invoke(req,request.params.name,request.params.arguments??{},ctx.mcpReq._meta?.wheremymcp_approval_id??ctx.mcpReq._meta?.unifymcp_approval_id,AbortSignal.any([ctx.mcpReq.signal,disconnect.signal])));
   return server;
  },{legacy:'stateless',maxRequestBodySize:hub.config.maxBodyBytes,maxSubscriptions:0,onerror:()=>{}});
  try{
   const headers=new Headers();for(const[k,v]of Object.entries(req.headers))if(v)headers.set(k,Array.isArray(v)?v.join(','):v);
   const response=await handler.fetch(new Request(hub.config.origin+'/mcp',{method:req.method,headers,body:JSON.stringify(req.body),signal:disconnect.signal}),{parsedBody:req.body});
   reply.code(response.status);response.headers.forEach((value,key)=>reply.header(key,value));return reply.send(Buffer.from(await response.arrayBuffer()));
  }finally{reply.raw.off('close',abort);await handler.close();}
 }});
}
