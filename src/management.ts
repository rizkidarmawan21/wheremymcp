import {randomBytes,randomUUID} from 'node:crypto';
import type {FastifyInstance,FastifyRequest,HTTPMethods} from 'fastify';
import {Server,createMcpHandler,type Tool,type CallToolResult} from '@modelcontextprotocol/server';
import {z} from 'zod';
import {Hub,hashToken,httpError,type OwnerGuard} from './core.js';

type Scope='read'|'write'|'delete';
type CredentialSource='client'|'legacy';
type Manager={id:string;name:string;scopes:string;token_hash:string;status:string;expires_at:number|null;source:CredentialSource};
type Dispatch={id:string;hash:string;scope:Scope;method:HTTPMethods;url:string;source:CredentialSource};
// Owner REST accepts delegation only through an exact one-use in-process ticket, never a management bearer header.
const dispatchTickets=new Map<string,Dispatch>();
const dispatchRequests=new WeakMap<FastifyRequest,Dispatch>();
const id=z.string().uuid(),scope=z.enum(['read','write','delete']);
export const managementScopes=z.array(scope).max(3).refine(v=>new Set(v).size===v.length);
export const managementToolPrefix='wheremymcp_manage_';
const tokenInput=z.object({name:z.string().trim().min(1).max(100),scopes:z.array(scope).min(1).max(3).refine(v=>new Set(v).size===v.length),ttl_days:z.number().int().min(1).max(365).default(30),password:z.string().max(1024),totp:z.string().max(10).optional()}).strict();
const reauth=z.object({password:z.string().max(1024),totp:z.string().max(10).optional()}).strict();
const page={offset:z.number().int().min(0).max(100000).default(0),limit:z.number().int().min(1).max(100).default(25)};
const publicColumns='id,name,scopes,status,expires_at,created_at,last_used';
const publicManager=(row:any)=>({...row,status:row.status==='active'&&row.expires_at<=Date.now()?'expired':row.status,scopes:JSON.parse(row.scopes)});
function requireManager(hub:Hub,request:FastifyRequest,source:CredentialSource='legacy'):Manager{
 const header=request.headers.authorization;
 if(!header?.startsWith(source==='legacy'?'Bearer wmm_':'Bearer umcp_')||header.length>512)throw httpError(401,'Management bearer token required');
 const row=hub.db.prepare(source==='legacy'?'SELECT * FROM management_client WHERE token_hash=?':'SELECT id,name,management_scopes AS scopes,token_hash,status,expires_at FROM client WHERE token_hash=?').get(hashToken(header.slice(7))) as Manager|undefined;
 if(!row||row.status!=='active'||(row.expires_at!==null&&row.expires_at<=Date.now()))throw httpError(401,'Management token is invalid or expired');
 hub.db.prepare(source==='legacy'?'UPDATE management_client SET last_used=? WHERE id=?':'UPDATE client SET last_used=? WHERE id=?').run(Date.now(),row.id);return {...row,source};
}
function authorize(hub:Hub,context:Dispatch):void{
 const row=hub.db.prepare(context.source==='legacy'?'SELECT * FROM management_client WHERE id=?':'SELECT token_hash,status,expires_at,management_scopes AS scopes FROM client WHERE id=?').get(context.id) as Manager|undefined;
 if(!row||row.token_hash!==context.hash||row.status!=='active'||(row.expires_at!==null&&row.expires_at<=Date.now()))throw httpError(401,'Management token is invalid or expired');
 if(!JSON.parse(row.scopes).includes(context.scope))throw httpError(403,'Management scope required: '+context.scope);
}
export async function verifyOwnerStepUp(hub:Hub,request:FastifyRequest,body:{password?:string;totp?:string}):Promise<void>{
 if(!request.ownerSession)throw httpError(403,'Owner session required for management credentials');
 if(!await hub.verifyStepUp(body.password??'',body.totp))throw httpError(403,'Owner password and MFA verification required');
 const session=hub.db.prepare('SELECT expires_at,last_used FROM session WHERE id=?').get(request.ownerSession.id) as {expires_at:number;last_used:number}|undefined;
 if(!session||session.expires_at<=Date.now()||session.last_used<Date.now()-hub.config.sessionIdleMs)throw httpError(403,'Owner session required');
}
export function isManagementDispatch(hub:Hub,request:FastifyRequest):boolean{
 const ticket=request.headers['x-wheremymcp-dispatch'];
 if(ticket===undefined)return false;
 const context=typeof ticket==='string'?dispatchTickets.get(ticket):undefined;
 if(typeof ticket==='string')dispatchTickets.delete(ticket);
 if(!context||request.method!==context.method||request.url!==context.url)throw httpError(403,'Invalid management dispatch');
 authorize(hub,context);dispatchRequests.set(request,context);return true;
}
export function withManagementAudit<T>(hub:Hub,request:FastifyRequest,work:()=>T):T{
 const context=dispatchRequests.get(request);return context?hub.withAuditPrincipal('management:'+context.id,work):work();
}
export function managementApiGuard(hub:Hub,owner:OwnerGuard):OwnerGuard{
 return async(request,reply)=>{
  const context=dispatchRequests.get(request);
  if(!context)return (owner as any)(request,reply);
  if(request.method!==context.method||request.url!==context.url)throw httpError(403,'Management dispatch target mismatch');
  authorize(hub,context);
 };
}

type Operation={name:string;scope:Scope;description:string;schema:z.ZodType;method:HTTPMethods;url:(input:any)=>string;body?:(input:any,hub:Hub)=>unknown;result?:(value:any,input:any)=>unknown};
const fixed=(url:string)=>()=>url;
const target=(root:string,suffix='')=>(input:any)=>`/api/v1/${root}/${encodeURIComponent(input.id)}${suffix}`;
const empty=z.object({}).strict();
const paginate=(values:any[],input:any)=>({items:values.slice(input.offset,input.offset+input.limit),total:values.length,next_offset:input.offset+input.limit<values.length?input.offset+input.limit:null});
const serverInput={name:z.string().trim().min(1).max(120),url:z.string().url(),connection_id:id.nullable().optional(),allowed_private_ips:z.array(z.string().max(45)).max(16).optional(),timeout_ms:z.number().int().min(100).max(60000).optional()};
const operations:Operation[]=[
 {name:'overview_get',scope:'read',description:'Read gateway counts, emergency stop state and recent policy events.',schema:empty,method:'GET',url:fixed('/api/v1/overview')},
 {name:'diagnostics_get',scope:'read',description:'Read instance health/configuration diagnostics without credentials.',schema:empty,method:'GET',url:fixed('/api/v1/system/diagnostics')},
 {name:'connections_list',scope:'read',description:'List account connections and their authorization state. Credentials are never returned. Provider consent still happens in the dashboard.',schema:empty,method:'GET',url:fixed('/api/v1/connections')},
 {name:'servers_list',scope:'read',description:'List registered MCP endpoints, account bindings and routing state.',schema:empty,method:'GET',url:fixed('/api/v1/upstreams')},
 {name:'server_create',scope:'write',description:'Register an HTTP MCP endpoint. Then explicitly trust and enable its current tools with server_auto_approve.',schema:z.object(serverInput).strict(),method:'POST',url:fixed('/api/v1/upstreams'),body:input=>input},
 {name:'server_update',scope:'write',description:'Edit a registered MCP server. Endpoint or account changes require live rediscovery.',schema:z.object({id,...Object.fromEntries(Object.entries(serverInput).map(([key,value])=>[key,value.optional()]))}).strict(),method:'PATCH',url:target('upstreams'),body:({id,...body})=>body},
 {name:'server_refresh',scope:'write',description:'Rediscover tool metadata. Changed tools are quarantined until explicitly approved.',schema:z.object({id}).strict(),method:'POST',url:target('upstreams','/refresh')},
 {name:'server_auto_approve',scope:'write',description:'Explicitly trust this server and enable its currently advertised tools. Uses annotation risk hints; unknown behavior is Write. Does not grant profile access.',schema:z.object({id,trust_server:z.literal(true)}).strict(),method:'POST',url:target('upstreams','/auto-approve-tools'),body:()=>({trust_server:true})},
 {name:'server_disable',scope:'write',description:'Disable routing to an MCP server.',schema:z.object({id}).strict(),method:'POST',url:target('upstreams','/disable')},
 {name:'server_delete',scope:'delete',description:'Permanently delete a server, its tools, grants and pending approvals. Requires explicit confirmation.',schema:z.object({id,confirm:z.literal(true)}).strict(),method:'DELETE',url:target('upstreams')},
 {name:'tools_list',scope:'read',description:'List tools with readable names and IDs, optionally filtered by server or search. Paginated; full metadata is optional.',schema:z.object({...page,server_id:id.optional(),search:z.string().max(200).optional(),include_metadata:z.boolean().default(false)}).strict(),method:'GET',url:input=>'/api/v1/tools?'+new URLSearchParams(Object.fromEntries(Object.entries(input).map(([key,value])=>[key,String(value)]))).toString()},
 {name:'tool_approve',scope:'write',description:'Classify and enable or disable one tool using its current discovered metadata.',schema:z.object({id,risk:z.enum(['read','write','delete']),enabled:z.boolean()}).strict(),method:'POST',url:target('tools','/approve'),body:({id,...body})=>body},
 {name:'profiles_list',scope:'read',description:'List client permission profiles. Default already exists.',schema:empty,method:'GET',url:fixed('/api/v1/profiles')},
 {name:'profile_get',scope:'read',description:'Read one profile and a page of its exact account/action tool grants.',schema:z.object({id,...page}).strict(),method:'GET',url:target('profiles'),result:(value,input)=>({profile:value.profile,grants:paginate(value.grants,input)})},
 {name:'profile_create',scope:'write',description:'Create an empty access profile.',schema:z.object({name:z.string().trim().min(1).max(100),slug:z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/).optional()}).strict(),method:'POST',url:fixed('/api/v1/profiles'),body:input=>input},
 {name:'profile_clone',scope:'write',description:'Clone an existing profile and its grants.',schema:z.object({id,name:z.string().trim().min(1).max(100)}).strict(),method:'POST',url:target('profiles','/clone'),body:({id,...body})=>body},
 {name:'profile_set_access',scope:'write',description:'Replace profile access with enabled tools selected by whole MCP servers, exact tool IDs, or all_available. Use exactly one selector. Empty tool_ids clears access. Requires confirm_replace=true; write/delete calls still need one-use approval.',schema:z.object({id,server_ids:z.array(id).max(128).optional(),tool_ids:z.array(id).max(5000).optional(),all_available:z.literal(true).optional(),confirm_replace:z.literal(true)}).strict().refine(input=>[input.server_ids,input.tool_ids,input.all_available].filter(v=>v!==undefined).length===1,'Choose exactly one tool selector'),method:'PUT',url:target('profiles','/grants'),body:(input,hub)=>{
   const tools=hub.db.prepare("SELECT t.id AS tool_id,u.id AS server_id,u.connection_id,t.risk AS action_class FROM tool t JOIN upstream u ON u.id=t.upstream_id LEFT JOIN connection c ON c.id=u.connection_id WHERE t.enabled=1 AND t.fingerprint=t.approved_fingerprint AND t.risk IN ('read','write','delete') AND u.status='active' AND (u.connection_id IS NULL OR (c.status IN ('active','connected') AND (c.expires_at IS NULL OR c.expires_at>?)))").all(Date.now()) as any[];
   const selected=tools.filter(tool=>(input.all_available||input.server_ids?.includes(tool.server_id)||input.tool_ids?.includes(tool.tool_id))&&hub.setting('import_requires_refresh:'+tool.server_id)!=='true');
   if(input.tool_ids?.some((id:string)=>!selected.some(tool=>tool.tool_id===id)))throw httpError(409,'Some selected tools are unavailable; refresh the tool list before replacing access');
   if(input.server_ids?.some((id:string)=>!hub.db.prepare('SELECT id FROM upstream WHERE id=?').get(id)))throw httpError(404,'Selected MCP server not found');
   return {grants:selected.map(({tool_id,connection_id,action_class})=>({tool_id,connection_id,action_class}))};
  }},
 {name:'profile_delete',scope:'delete',description:'Delete a custom profile and its grants. Default cannot be deleted. If clients use it, supply an explicit replacement profile.',schema:z.object({id,replacement_profile_id:id.optional(),confirm:z.literal(true)}).strict(),method:'DELETE',url:target('profiles'),body:input=>input.replacement_profile_id?{replacement_profile_id:input.replacement_profile_id}:undefined},
 {name:'clients_list',scope:'read',description:'List agent clients and token status without returning tokens or hashes.',schema:empty,method:'GET',url:fixed('/api/v1/clients')},
 {name:'client_create',scope:'write',description:'Issue an agent client token bound to a profile. The secret token appears once in this tool result; keep the conversation private.',schema:z.object({name:z.string().trim().min(1).max(100),kind:z.enum(['codex','claude','cursor','gemini','hermes','other']),profile_id:id,ttl_days:z.number().int().min(1).max(3650).optional()}).strict(),method:'POST',url:fixed('/api/v1/clients'),body:input=>input},
 {name:'client_rotate',scope:'write',description:'Rotate an agent client token. Invalidates the old token immediately and returns the replacement secret once.',schema:z.object({id}).strict(),method:'POST',url:target('clients','/rotate')},
 {name:'client_revoke',scope:'delete',description:'Revoke an agent client token and its pending approvals. Requires explicit confirmation.',schema:z.object({id,confirm:z.literal(true)}).strict(),method:'POST',url:target('clients','/revoke')},
 {name:'client_config',scope:'read',description:'Generate a credential-free client configuration snippet for an existing agent client.',schema:z.object({id,kind:z.enum(['codex','claude','cursor','gemini','hermes','other']).default('codex')}).strict(),method:'GET',url:input=>target('clients','/config')(input)+'?kind='+encodeURIComponent(input.kind)},
 {name:'audit_list',scope:'read',description:'Read bounded audit events without tool arguments, results or secrets.',schema:z.object({limit:z.number().int().min(1).max(100).default(25),cursor:z.string().max(256).optional(),principal:z.string().max(160).optional()}).strict(),method:'GET',url:input=>'/api/v1/audit?'+new URLSearchParams(Object.fromEntries(Object.entries(input).map(([k,v])=>[k,String(v)]))).toString()},
];

function namedOperations(hub:Hub,source:CredentialSource):Map<string,Operation>{
 if(source==='legacy')return new Map(operations.map(operation=>[operation.name,operation]));
 // Imported provider names predate this namespace; preserve them and alias the built-in tool instead.
 const occupied=new Set((hub.db.prepare("SELECT gateway_name FROM tool WHERE gateway_name GLOB 'wheremymcp_manage_*'").all() as {gateway_name:string}[]).map(row=>row.gateway_name));
 return new Map(operations.map(operation=>{const base=managementToolPrefix+operation.name;let name=base,index=0;while(occupied.has(name))name=base+'_builtin_'+(++index);occupied.add(name);return [name,operation];}));
}
export function isManagementTool(hub:Hub,name:string):boolean{return name.startsWith(managementToolPrefix)&&namedOperations(hub,'client').has(name);}
export function listManagementTools(hub:Hub,req:FastifyRequest,source:CredentialSource='legacy'):Tool[]{
 const manager=requireManager(hub,req,source);
 return [...namedOperations(hub,source)].filter(([,operation])=>JSON.parse(manager.scopes).includes(operation.scope)).map(([name,operation])=>({name,description:operation.description,inputSchema:z.toJSONSchema(operation.schema,{unrepresentable:'any'}) as any,annotations:{readOnlyHint:operation.scope==='read',destructiveHint:operation.scope!=='read'}}));
}

export async function callManagementTool(app:FastifyInstance,hub:Hub,req:FastifyRequest,name:string,args:unknown,source:CredentialSource='legacy'):Promise<CallToolResult>{
 const manager=requireManager(hub,req,source),operation=namedOperations(hub,source).get(name);
 if(!operation||!JSON.parse(manager.scopes).includes(operation.scope)){hub.audit({principal:'management:'+manager.id,action:'management.tool.call',resource:operation?.name??'unknown',outcome:'deny',detail:'scope_or_tool_denied'});return {isError:true,content:[{type:'text',text:'Unknown tool or management scope denied'}]};}
 try{
  const input=operation.schema.parse(args??{}),url=operation.url(input),body=operation.body?.(input,hub);
  const ticket=randomBytes(32).toString('base64url');
  dispatchTickets.set(ticket,{id:manager.id,hash:manager.token_hash,scope:operation.scope,method:operation.method,url,source});
  let result;
  try{result=await app.inject({method:operation.method,url,headers:{host:new URL(hub.config.origin).host,'x-wheremymcp-dispatch':ticket},...(body===undefined?{}:{payload:body as Record<string,unknown>})});}finally{dispatchTickets.delete(ticket);}
  const payload=result.json();
  if(result.statusCode>=300){hub.audit({principal:'management:'+manager.id,action:'management.tool.call',resource:operation.name,outcome:'deny',detail:'http_'+result.statusCode});return {isError:true,content:[{type:'text',text:JSON.stringify({error:payload.error,message:payload.message,request_id:payload.request_id})}]};}
  const value=JSON.stringify(operation.result?operation.result(payload,input):operation.name==='profile_set_access'?{...payload,selected_tools:(body as {grants:unknown[]}).grants.length}:payload);
  if(Buffer.byteLength(value)>1048576){hub.audit({principal:'management:'+manager.id,action:'management.tool.call',resource:operation.name,outcome:'deny',detail:'result_too_large'});return {isError:true,content:[{type:'text',text:'Result too large. Use a smaller page or omit full metadata.'}]};}
  hub.audit({principal:'management:'+manager.id,action:'management.tool.call',resource:operation.name});return {content:[{type:'text',text:value}]};
 }catch(error){hub.audit({principal:'management:'+manager.id,action:'management.tool.call',resource:operation.name,outcome:'deny',detail:'invalid_or_denied'});return {isError:true,content:[{type:'text',text:error instanceof z.ZodError?'Invalid tool arguments. Check the tool schema and required confirmations.':(error as {statusCode?:number}).statusCode&&((error as {statusCode:number}).statusCode<500)?(error as Error).message:'Management operation failed'}]};}
}

export async function registerManagement(app:FastifyInstance,hub:Hub,owner:OwnerGuard):Promise<void>{
 const ownerRoute={preHandler:owner},stepUpRoute={preHandler:owner,config:{rateLimit:{max:8,timeWindow:'1 minute'}}};
 const endpoint=hub.config.origin+'/mcp/manage';
 const configSnippet=`[mcp_servers.wheremymcp_management]\nurl = ${JSON.stringify(endpoint)}\nbearer_token_env_var = "WHEREMYMCP_MANAGEMENT_TOKEN"`;
 const stepUp=(request:FastifyRequest,body:{password?:string;totp?:string})=>verifyOwnerStepUp(hub,request,body);
 app.get('/api/v1/management/clients',ownerRoute,async()=>({endpoint,config:configSnippet,unified_endpoint:hub.config.origin+'/mcp',tools_count:operations.length,clients:hub.db.prepare(`SELECT ${publicColumns} FROM management_client ORDER BY created_at`).all().map(publicManager)}));
 app.put('/api/v1/clients/:id/management',stepUpRoute,async request=>{
  const target=id.parse((request.params as any).id),body=z.object({management_scopes:managementScopes,password:z.string().max(1024).optional(),totp:z.string().max(10).optional()}).strict().parse(request.body);
  if(!hub.db.prepare('SELECT id FROM client WHERE id=?').get(target))throw httpError(404,'Client not found');
  if(body.management_scopes.length)await stepUp(request,body);
  hub.db.prepare('UPDATE client SET management_scopes=? WHERE id=?').run(JSON.stringify(body.management_scopes),target);
  hub.audit({principal:'owner',action:'client.management.update',resource:target});return {ok:true,management_scopes:body.management_scopes};
 });
 app.post('/api/v1/management/clients',stepUpRoute,async(request,reply)=>{
  const body=tokenInput.parse(request.body);await stepUp(request,body);
  const id=randomUUID(),token='wmm_'+randomBytes(32).toString('base64url');
  hub.db.prepare('INSERT INTO management_client(id,name,scopes,token_hash,expires_at,created_at) VALUES(?,?,?,?,?,?)').run(id,body.name,JSON.stringify(body.scopes),hashToken(token),Date.now()+body.ttl_days*86400000,Date.now());
  hub.audit({principal:'owner',action:'management.client.create',resource:id});
  return reply.code(201).send({client:publicManager(hub.db.prepare(`SELECT ${publicColumns} FROM management_client WHERE id=?`).get(id)),token,endpoint,config:configSnippet});
 });
 app.post('/api/v1/management/clients/:id/revoke',ownerRoute,async request=>{
  const target=id.parse((request.params as any).id);if(!hub.db.prepare("UPDATE management_client SET status='revoked' WHERE id=?").run(target).changes)throw httpError(404,'Management client not found');
  hub.audit({principal:'owner',action:'management.client.revoke',resource:target});return {ok:true};
 });
 app.post('/api/v1/management/clients/:id/rotate',stepUpRoute,async request=>{
  const target=id.parse((request.params as any).id),body=reauth.parse(request.body);await stepUp(request,body);
  const row=hub.db.prepare('SELECT expires_at,status FROM management_client WHERE id=?').get(target) as {expires_at:number;status:string}|undefined;
  if(!row)throw httpError(404,'Management client not found');if(row.expires_at<=Date.now()||row.status!=='active')throw httpError(409,'Issue a new token for a revoked or expired management client');
  const token='wmm_'+randomBytes(32).toString('base64url');hub.db.prepare('UPDATE management_client SET token_hash=? WHERE id=?').run(hashToken(token),target);
  hub.audit({principal:'owner',action:'management.client.rotate',resource:target});return {token,endpoint,config:configSnippet};
 });
 app.route({method:['GET','POST','DELETE'],url:'/mcp/manage',bodyLimit:hub.config.maxBodyBytes,preHandler:async request=>{requireManager(hub,request);},handler:async(req,reply)=>{
 if(req.method!=='POST')return reply.code(405).send({error:'method_not_allowed'});
 const handler=createMcpHandler(()=>{
  const server=new Server({name:'wheremymcp-management',version:'0.1.0'},{capabilities:{tools:{}},cacheHints:{'tools/list':{ttlMs:0,cacheScope:'private'}}});
  server.setRequestHandler('tools/list',()=>({tools:listManagementTools(hub,req)}));
  server.setRequestHandler('tools/call',request=>callManagementTool(app,hub,req,request.params.name,request.params.arguments));return server;
 });
 try{
  const headers=new Headers();for(const [key,value] of Object.entries(req.headers))if(value)headers.set(key,Array.isArray(value)?value.join(','):value);
  const response=await handler.fetch(new Request(hub.config.origin+'/mcp/manage',{method:'POST',headers,body:JSON.stringify(req.body)}),{parsedBody:req.body});
  reply.code(response.status);response.headers.forEach((value,key)=>reply.header(key,value));return reply.send(Buffer.from(await response.arrayBuffer()));
 }finally{await handler.close();}
 }});
}
