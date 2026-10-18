import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { open, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, sep } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { Hub, httpError, type OwnerGuard } from './core.js';
import { safeFetch, type FetchPolicy } from './gateway/network.js';
import { RemoteOAuthManager } from './gateway/remote-oauth.js';

type Fetcher=(input:string|URL|Request,init?:RequestInit,policy?:FetchPolicy)=>Promise<Response>;
type Connection={id:string;provider:string;alias:string;status:string;identity:string;scopes:string;credential:string|null;config:string;expires_at:number|null;created_at:number};
type Credential={secret?:string;access_token?:string;client_secret?:string;refresh_token?:string;expires_at?:number;token_type?:string};
type Provider={authorize:string;token:string;identity:string;origin:string;issuer?:string};
const providers:Record<string,Provider>={
 github:{authorize:'https://github.com/login/oauth/authorize',token:'https://github.com/login/oauth/access_token',identity:'https://api.github.com/user',origin:'https://api.github.com'},
 google:{authorize:'https://accounts.google.com/o/oauth2/v2/auth',token:'https://oauth2.googleapis.com/token',identity:'https://openidconnect.googleapis.com/v1/userinfo',origin:'https://www.googleapis.com',issuer:'https://accounts.google.com'},
 slack:{authorize:'https://slack.com/oauth/v2/authorize',token:'https://slack.com/api/oauth.v2.access',identity:'https://slack.com/api/auth.test',origin:'https://slack.com'},
};
const aliasSchema=z.string().trim().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/);
const headerSchema=z.string().regex(/^[a-zA-Z0-9-]{1,80}$/).refine(s=>!['host','cookie','connection','content-length','transfer-encoding','proxy-authorization','forwarded','x-forwarded-host','x-forwarded-for','x-forwarded-proto'].includes(s.toLowerCase()),'Reserved header');
const connectionInput=z.object({provider:z.enum(['api_key','bearer','github','google','slack','remote_oauth']),alias:aliasSchema,secret:z.string().min(1).max(16384).optional(),secret_file:z.string().max(4096).optional(),identity:z.string().max(200).optional(),scopes:z.array(z.string().min(1).max(200)).max(100).optional(),config:z.object({client_id:z.string().max(512).optional(),header_name:headerSchema.optional(),allowed_origin:z.string().url().optional(),issuer:z.string().url().optional(),resource:z.string().url().optional(),broad_scope_acknowledged:z.boolean().optional()}).strict().optional()}).strict();
function publicConnection(c:Connection){return {id:c.id,provider:c.provider,alias:c.alias,status:c.status,identity:c.identity,scopes:JSON.parse(c.scopes),config:JSON.parse(c.config),expires_at:c.expires_at,created_at:c.created_at,has_credential:!!c.credential};}
function requireConnection(hub:Hub,id:string):Connection {const row=hub.db.prepare('SELECT * FROM connection WHERE id=?').get(id) as Connection|undefined;if(!row)throw httpError(404,'Connection not found');return row;}

export class ProviderManager {
 private readonly refreshes=new Map<string,Promise<Credential>>();
 readonly remote:RemoteOAuthManager;
 constructor(readonly hub:Hub,readonly fetcher:Fetcher=safeFetch){this.remote=new RemoteOAuthManager(hub,fetcher);}
 startOAuth(id:string,sessionId:string):{authorization_url:string}{
  const row=requireConnection(this.hub,id),provider=providers[row.provider],config=JSON.parse(row.config);
  if(!provider || !config.client_id)throw httpError(400,'Configure BYO OAuth client ID and secret first');
  const credential:Credential=row.credential?JSON.parse(this.hub.open(row.credential,`connection:${id}`)):{};
  if(!credential.client_secret)throw httpError(400,'OAuth client secret is missing');
  const scopes:string[]=JSON.parse(row.scopes);
  if(row.provider==='google' && !scopes.includes('openid'))scopes.unshift('openid');
  if(row.provider==='google' && scopes.some(s=>s==='https://www.googleapis.com/auth/drive'||s==='https://www.googleapis.com/auth/drive.readonly') && !config.broad_scope_acknowledged)throw httpError(400,'Broad Google Drive scope requires informed acknowledgment and provider verification');
  const state=randomBytes(32).toString('base64url'),verifier=randomBytes(48).toString('base64url'),nonce=randomBytes(32).toString('base64url');
  const redirect=`${this.hub.config.origin}/oauth/callback/${row.provider}`;
  const snapshot={verifier,nonce,provider:row.provider,client_id:config.client_id,redirect_uri:redirect};
  this.hub.db.transaction(()=>{this.hub.db.prepare('DELETE FROM oauth_state WHERE connection_id=? OR expires_at<?').run(id,Date.now());this.hub.db.prepare('INSERT INTO oauth_state VALUES(?,?,?,?,?)').run(state,id,this.hub.seal(JSON.stringify(snapshot),`oauth:${state}`),sessionId,Date.now()+600_000);this.hub.setSetting(`oauth_generation:${id}`,state);this.hub.db.prepare("UPDATE connection SET status='pending_consent' WHERE id=?").run(id);})();
  const url=new URL(provider.authorize);const query={client_id:config.client_id,redirect_uri:redirect,response_type:'code',scope:scopes.join(row.provider==='slack'?',':' '),state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'};
  for(const[k,v]of Object.entries(query))url.searchParams.set(k,String(v));
  if(row.provider==='google'){url.searchParams.set('nonce',nonce);url.searchParams.set('access_type','offline');url.searchParams.set('prompt','consent');}
  this.hub.audit({principal:'owner',action:'oauth.start',resource:id});return {authorization_url:url.toString()};
 }
 async finishOAuth(providerName:string,state:string,code:string,sessionId:string):Promise<{connection_id:string}>{
  const saved=this.hub.db.prepare('SELECT * FROM oauth_state WHERE id=?').get(state) as any;
  if(!saved || saved.session_id!==sessionId || saved.expires_at<=Date.now())throw httpError(400,'OAuth state is invalid, expired, or belongs to another session');
  const row=requireConnection(this.hub,saved.connection_id),provider=providers[providerName];
  const snapshot=JSON.parse(this.hub.open(saved.verifier,`oauth:${state}`));const config=JSON.parse(row.config);
  if(!provider || row.provider!==providerName || snapshot.provider!==providerName || snapshot.client_id!==config.client_id || snapshot.redirect_uri!==`${this.hub.config.origin}/oauth/callback/${providerName}`)throw httpError(400,'OAuth provider binding is invalid');
  if(!this.hub.db.prepare('DELETE FROM oauth_state WHERE id=?').run(state).changes)throw httpError(400,'OAuth state has already been used');
  const original=row.credential;const credential:Credential=original?JSON.parse(this.hub.open(original,`connection:${row.id}`)):{};
  try{
    const form=new URLSearchParams({grant_type:'authorization_code',client_id:config.client_id,client_secret:credential.client_secret||'',redirect_uri:snapshot.redirect_uri,code,code_verifier:snapshot.verifier});
    const response=await this.fetcher(provider.token,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',accept:'application/json'},body:form.toString()});const token:any=await response.json();
    if(!response.ok || token.error || token.ok===false || typeof token.access_token!=='string')throw httpError(400,'OAuth token exchange failed');
    if(token.token_type && token.token_type.toLowerCase()!=='bearer')throw httpError(400,'Unsupported OAuth token type');
    let identitySubject:string|undefined;
    if(providerName==='google'){
      if(typeof token.id_token!=='string')throw httpError(400,'Google identity token is missing');
      const jwksResponse=await this.fetcher('https://www.googleapis.com/oauth2/v3/certs');if(!jwksResponse.ok)throw httpError(503,'Google signing keys unavailable');
      const jwks=createLocalJWKSet(await jwksResponse.json() as any);const {payload}=await jwtVerify(token.id_token,jwks,{issuer:['https://accounts.google.com','accounts.google.com'],audience:config.client_id,algorithms:['RS256']});
      if(payload.nonce!==snapshot.nonce || typeof payload.sub!=='string')throw httpError(400,'Google identity binding is invalid');
      identitySubject=payload.sub;
    }
    const identityResponse=await this.fetcher(provider.identity,{method:providerName==='slack'?'POST':'GET',headers:{authorization:`Bearer ${token.access_token}`,accept:'application/json','user-agent':'WhereMyMCP/0.1'}});
    const identity:any=await identityResponse.json();if(!identityResponse.ok || identity.ok===false)throw httpError(400,'Provider identity verification failed');
    const principal=providerName==='github'?String(identity.id):providerName==='google'?String(identity.sub):`${identity.team_id}:${identity.user_id}`;
    if(!principal || principal.includes('undefined'))throw httpError(400,'Provider identity is incomplete');
    if(identitySubject && principal!==identitySubject)throw httpError(400,'Provider identity does not match the identity token');
    const granted=typeof token.scope==='string'?token.scope.split(/[ ,]+/).filter(Boolean):JSON.parse(row.scopes);
    const next:Credential={...credential,secret:token.access_token,access_token:token.access_token,refresh_token:token.refresh_token||credential.refresh_token,expires_at:token.expires_in?Date.now()+Number(token.expires_in)*1000:undefined,token_type:'bearer'};
    const current=requireConnection(this.hub,row.id);
    const session=this.hub.db.prepare('SELECT expires_at,last_used FROM session WHERE id=?').get(saved.session_id) as any;
    if(!session || session.expires_at<=Date.now() || session.last_used<Date.now()-this.hub.config.sessionIdleMs)throw httpError(409,'Owner session was revoked or expired during authorization');
    if(current.status!=='pending_consent'||current.credential!==original||this.hub.setting(`oauth_generation:${row.id}`)!==state)throw httpError(409,'Connection was revoked or changed during authorization');
    this.hub.db.prepare("UPDATE connection SET credential=?,status='connected',identity=?,scopes=?,expires_at=NULL WHERE id=?").run(this.hub.seal(JSON.stringify(next),`connection:${row.id}`),principal,JSON.stringify(granted),row.id);this.ensureNative(row.id);this.hub.audit({principal:'owner',action:'oauth.connected',resource:row.id});return {connection_id:row.id};
  }catch(error){if(this.hub.setting(`oauth_generation:${row.id}`)===state)this.hub.db.prepare("UPDATE connection SET status='reauth_required' WHERE id=? AND status='pending_consent'").run(row.id);this.hub.audit({principal:'owner',action:'oauth.callback',resource:row.id,outcome:'deny',detail:'exchange_failed'});if((error as any).statusCode)throw error;throw httpError(400,'OAuth authorization failed');}
 }
 async resolveCredential(id:string):Promise<Credential>{
  if(requireConnection(this.hub,id).provider==='remote_oauth')return this.remote.resolve(id);
  const row=requireConnection(this.hub,id);if(row.status!=='connected'||!row.credential)throw httpError(403,'Connection is revoked or requires authorization');
  const credential:Credential=JSON.parse(this.hub.open(row.credential,`connection:${id}`));
  if(!credential.expires_at || credential.expires_at>Date.now()+60_000)return credential;
  const existing=this.refreshes.get(id);if(existing)return existing;
  const promise=this.refresh(row,credential);this.refreshes.set(id,promise);try{return await promise;}finally{this.refreshes.delete(id);}
 }
 private async refresh(row:Connection,credential:Credential):Promise<Credential>{
  const provider=providers[row.provider],config=JSON.parse(row.config);
  if(!provider||!credential.refresh_token){this.hub.db.prepare("UPDATE connection SET status='reauth_required' WHERE id=? AND credential=?").run(row.id,row.credential);throw httpError(403,'Connection requires reauthorization');}
  try{
    const form=new URLSearchParams({grant_type:'refresh_token',refresh_token:credential.refresh_token,client_id:config.client_id,client_secret:credential.client_secret||''});
    const response=await this.fetcher(provider.token,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',accept:'application/json'},body:form.toString()});const token:any=await response.json();
    if(!response.ok||token.error||token.ok===false||typeof token.access_token!=='string')throw new Error('refresh_failed');
    const current=requireConnection(this.hub,row.id);if(current.status!=='connected'||current.credential!==row.credential)throw httpError(409,'Connection was revoked or changed during refresh');
    const next={...credential,secret:token.access_token,access_token:token.access_token,refresh_token:token.refresh_token||credential.refresh_token,expires_at:token.expires_in?Date.now()+Number(token.expires_in)*1000:undefined};
    this.hub.db.prepare('UPDATE connection SET credential=? WHERE id=?').run(this.hub.seal(JSON.stringify(next),`connection:${row.id}`),row.id);this.hub.audit({action:'oauth.refresh',resource:row.id});return next;
  }catch(error){this.hub.db.prepare("UPDATE connection SET status='reauth_required' WHERE id=? AND status='connected' AND credential=?").run(row.id,row.credential);if((error as any).statusCode)throw error;throw httpError(403,'Connection requires reauthorization');}
 }
 ensureNative(id:string):void {
  const row=requireConnection(this.hub,id);if(!providers[row.provider])return;
  const existing=this.hub.db.prepare('SELECT id FROM upstream WHERE connection_id=? AND url LIKE ?').get(id,'native://%');
  if(!existing)this.hub.db.prepare('INSERT INTO upstream(id,name,url,connection_id,status,created_at) VALUES(?,?,?,?,?,?)').run(randomUUID(),`${row.provider} / ${row.alias}`,`native://${row.provider}/${id}`,id,'registered',Date.now());
 }
 async nativeTools(id:string){const row=requireConnection(this.hub,id);return nativeDefinitions(row.provider).map(t=>({name:t.name,description:t.description,inputSchema:t.schema,annotations:{readOnlyHint:t.read}}));}
 async nativeCall(id:string,name:string,args:Record<string,unknown>,signal?:AbortSignal){
  const row=requireConnection(this.hub,id),definition=nativeDefinitions(row.provider).find(t=>t.name===name);if(!definition)throw httpError(404,'Provider tool not found');
  const credential=await this.resolveCredential(id);const current=requireConnection(this.hub,id);if(current.status!=='connected')throw httpError(403,'Connection is revoked');
  const req=definition.request(args);const allowed=providers[row.provider]!.origin;
  if(new URL(req.url).origin!==allowed)throw httpError(403,'Provider destination mismatch');
  const response=await this.fetcher(req.url,{method:req.method||'GET',headers:{authorization:`Bearer ${credential.secret||credential.access_token}`,'content-type':'application/json',accept:'application/json','user-agent':'WhereMyMCP/0.1',...(row.provider==='github'?{'x-github-api-version':'2022-11-28'}:{})},body:req.body?JSON.stringify(req.body):undefined,signal},{allowedOrigin:allowed,allowQuery:true,maxResponseBytes:2*1024*1024,timeoutMs:15000});
  if(!response.ok){if(response.status===401)this.hub.db.prepare("UPDATE connection SET status='reauth_required' WHERE id=? AND status='connected' AND credential=?").run(id,current.credential);throw httpError(response.status===429?429:502,response.status===429?'Provider rate limit reached':'Provider request failed');}
  const type=response.headers.get('content-type')||'';const data=type.includes('json')?await response.json():await response.text();
  if(typeof data==='object' && data && 'ok' in data && (data as any).ok===false)throw httpError(502,'Provider operation failed');
  return {content:[{type:'text' as const,text:typeof data==='string'?data:JSON.stringify(data)}]};
 }
 async revoke(id:string):Promise<{ok:boolean;provider_revocation:string}>{
  if(requireConnection(this.hub,id).provider==='remote_oauth')return {ok:true,...await this.remote.revoke(id)};
  const row=requireConnection(this.hub,id);const credential:Credential=row.credential?JSON.parse(this.hub.open(row.credential,`connection:${id}`)):{};
  this.hub.db.transaction(()=>{this.hub.db.prepare("UPDATE connection SET status='revoked',credential=NULL WHERE id=?").run(id);this.hub.db.prepare('DELETE FROM oauth_state WHERE connection_id=?').run(id);this.hub.db.prepare('DELETE FROM approval WHERE tool_id IN (SELECT t.id FROM tool t JOIN upstream u ON u.id=t.upstream_id WHERE u.connection_id=?)').run(id);})();
  this.hub.audit({principal:'owner',action:'connection.revoke',resource:id});let status='not_supported';
  try{const token=credential.refresh_token||credential.secret;if(token&&row.provider==='google'){const r=await this.fetcher('https://oauth2.googleapis.com/revoke',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({token}).toString()});status=r.ok?'succeeded':'failed';}
  else if(token&&row.provider==='slack'){const r=await this.fetcher('https://slack.com/api/auth.revoke',{method:'POST',headers:{authorization:`Bearer ${token}`}});const data:any=await r.json();status=r.ok&&data.ok?'succeeded':'failed';}
  else if(token&&row.provider==='github'&&credential.client_secret){const config=JSON.parse(row.config);const r=await this.fetcher(`https://api.github.com/applications/${encodeURIComponent(config.client_id)}/token`,{method:'DELETE',headers:{authorization:`Basic ${Buffer.from(`${config.client_id}:${credential.client_secret}`).toString('base64')}`,'content-type':'application/json',accept:'application/json','user-agent':'WhereMyMCP/0.1'},body:JSON.stringify({access_token:token})});status=r.ok?'succeeded':'failed';}}
  catch{status='failed';}this.hub.audit({action:'connection.provider_revoke',resource:id,detail:status});return {ok:true,provider_revocation:status};
 }
}

export async function registerProviders(app:FastifyInstance,hub:Hub,guard:OwnerGuard):Promise<ProviderManager>{
 const manager=new ProviderManager(hub);hub.resolveConnectionCredential=(id)=>manager.resolveCredential(id);hub.nativeTools=(id)=>manager.nativeTools(id);hub.nativeCall=(id,name,args,signal)=>manager.nativeCall(id,name,args,signal);
 const route={preHandler:guard};
 app.get('/api/v1/connections',route,async()=>({connections:(hub.db.prepare('SELECT * FROM connection ORDER BY created_at').all() as Connection[]).map(publicConnection)}));
 app.post('/api/v1/connections',route,async(request,reply)=>{
  const body=connectionInput.parse(request.body),id=randomUUID(),config=body.config||{};let secret=body.secret;
  if(body.secret_file){
    if(secret)throw httpError(400,'Choose a secret value or a secret file');
    const root=process.env.HUB_CREDENTIAL_FILES_DIR;if(!root)throw httpError(403,'Secret-file import requires HUB_CREDENTIAL_FILES_DIR');
    const base=await realpath(root),path=await realpath(resolve(base,body.secret_file));
    if(!path.startsWith(base+sep))throw httpError(403,'Secret file is outside the approved directory');
    const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try{const info=await file.stat();if(!info.isFile()||info.size>16384)throw httpError(400,'Secret file must be a small regular file');secret=(await file.readFile('utf8')).trim();}
    finally{await file.close();}
  }
  if(config.allowed_origin){const u=new URL(config.allowed_origin);if(u.origin!==config.allowed_origin || u.username||u.password||u.protocol!=='https:')throw httpError(400,'Credential allowed_origin must be an exact HTTPS origin');}
  if(body.provider==='api_key'&&!config.header_name)throw httpError(400,'API key connection requires header_name');
  const oauth=(!!providers[body.provider]||body.provider==='remote_oauth')&&!!config.client_id;
  if(body.provider==='remote_oauth'&&(!config.client_id||!config.issuer||!config.resource||!config.allowed_origin))throw httpError(400,'Remote OAuth requires client_id, issuer, resource and allowed_origin');
  const credential=secret?hub.seal(JSON.stringify(oauth?{client_secret:secret}:{secret}),`connection:${id}`):null;
  hub.db.prepare('INSERT INTO connection(id,provider,alias,status,identity,scopes,credential,config,created_at) VALUES(?,?,?,?,?,?,?,?,?)').run(id,body.provider,body.alias,secret&&!oauth?'connected':'not_configured',body.identity||'',JSON.stringify(body.scopes||[]),credential,JSON.stringify(config),Date.now());
  if(secret&&!oauth&&providers[body.provider])manager.ensureNative(id);hub.audit({principal:'owner',action:'connection.create',resource:id});return reply.code(201).send({connection:publicConnection(requireConnection(hub,id))});
 });
 app.patch('/api/v1/connections/:id',route,async(request)=>{
  const id=z.string().uuid().parse((request.params as any).id),row=requireConnection(hub,id);const body=z.object({alias:aliasSchema.optional(),secret:z.string().min(1).max(16384).optional(),identity:z.string().max(200).optional(),scopes:z.array(z.string().min(1).max(200)).max(100).optional(),config:connectionInput.shape.config.optional()}).strict().parse(request.body);
  const config=body.config?{...JSON.parse(row.config),...body.config}:JSON.parse(row.config);
  if(config.allowed_origin){const u=new URL(config.allowed_origin);if(u.origin!==config.allowed_origin||u.username||u.password||u.protocol!=='https:')throw httpError(400,'Credential allowed_origin must be an exact HTTPS origin');}
  if(row.provider==='api_key'&&!config.header_name)throw httpError(400,'API key connection requires header_name');
  if(row.provider==='remote_oauth'&&(!config.client_id||!config.issuer||!config.resource||!config.allowed_origin))throw httpError(400,'Remote OAuth requires client_id, issuer, resource and allowed_origin');
  const credential:Credential=row.credential?JSON.parse(hub.open(row.credential,`connection:${id}`)):{};
  if(body.secret){if(config.client_id)credential.client_secret=body.secret;else{credential.secret=body.secret;delete credential.expires_at;}}
  const scopes=body.scopes?JSON.stringify(body.scopes):row.scopes,identity=body.identity??row.identity;
  const status=body.secret?(config.client_id?'not_configured':'connected'):(config.client_id&&!JSON.parse(row.config).client_id?'not_configured':row.status);
  hub.db.transaction(()=>{hub.db.prepare('UPDATE connection SET alias=?,identity=?,scopes=?,config=?,credential=?,status=? WHERE id=?').run(body.alias||row.alias,identity,scopes,JSON.stringify(config),body.secret?hub.seal(JSON.stringify(credential),`connection:${id}`):row.credential,status,id);hub.db.prepare('DELETE FROM oauth_state WHERE connection_id=?').run(id);})();
  if(body.secret&&!config.client_id)manager.ensureNative(id);hub.audit({principal:'owner',action:body.secret?'connection.rotate':'connection.update',resource:id});return {connection:publicConnection(requireConnection(hub,id))};
 });
 app.delete('/api/v1/connections/:id',route,async(request)=>{
  const id=z.string().uuid().parse((request.params as any).id);requireConnection(hub,id);
  if((hub.db.prepare('SELECT COUNT(*) AS n FROM upstream WHERE connection_id=?').get(id) as any).n)throw httpError(409,'Connection is bound to an MCP server. Unbind or delete the server first.');
  if((hub.db.prepare('SELECT COUNT(*) AS n FROM profile_grant WHERE connection_id=?').get(id) as any).n)throw httpError(409,'Connection is referenced by profile grants. Remove those grants before deleting the account.');
  hub.db.transaction(()=>{hub.db.prepare('DELETE FROM oauth_state WHERE connection_id=?').run(id);hub.db.prepare('DELETE FROM connection WHERE id=?').run(id);})();
  hub.audit({principal:'owner',action:'connection.delete',resource:id});return {deleted:true};
 });
 app.post('/api/v1/connections/:id/revoke',route,async(request)=>manager.revoke(z.string().uuid().parse((request.params as any).id)));
 app.post('/api/v1/connections/:id/oauth/start',route,async(request)=>{const id=z.string().uuid().parse((request.params as any).id);return requireConnection(hub,id).provider==='remote_oauth'?manager.remote.start(id,request.ownerSession!.id):manager.startOAuth(id,request.ownerSession!.id);});
 app.get('/oauth/callback/:provider',route,async(request,reply)=>{
  const q=z.object({state:z.string().max(128),code:z.string().max(4096),iss:z.string().url().optional()}).parse(request.query);const provider=(request.params as any).provider;
  if(provider==='remote_oauth'){const row=hub.db.prepare('SELECT connection_id FROM oauth_state WHERE id=?').get(q.state) as any;if(!row)throw httpError(400,'OAuth state is invalid or expired');await manager.remote.finish(row.connection_id,q.state,q.code,request.ownerSession!.id,q.iss);return reply.redirect('/#connections');}
  if(q.iss&&q.iss!==providers[provider]?.issuer)throw httpError(400,'OAuth issuer mismatch');
  await manager.finishOAuth(provider,q.state,q.code,request.ownerSession!.id);return reply.redirect('/#connections');
 });
 return manager;
}

type ToolDefinition={name:string;description:string;read:boolean;schema:Record<string,unknown>;request:(args:Record<string,unknown>)=>{url:string;method?:string;body?:unknown}};
const str={type:'string',minLength:1,maxLength:4096};const short={type:'string',minLength:1,maxLength:200};
function schema(properties:Record<string,unknown>,required:string[]=[]){return {type:'object',properties,required,additionalProperties:false};}
function text(value:unknown):string{if(typeof value!=='string'||!value||value.length>20000)throw httpError(400,'Invalid provider argument');return value;}
function part(value:unknown){return encodeURIComponent(text(value));}
function number(value:unknown,fallback:number){return typeof value==='number'&&Number.isInteger(value)&&value>0?value:fallback;}
function repo(a:Record<string,unknown>){return `https://api.github.com/repos/${part(a.owner)}/${part(a.repo)}`;}
function nativeDefinitions(provider:string):ToolDefinition[]{
 if(provider==='github')return [
  {name:'list_repositories',description:'List repositories visible to this GitHub account. Provider token repository permissions still apply.',read:true,schema:schema({page:{type:'integer',minimum:1,maximum:1000}}),request:a=>({url:`https://api.github.com/user/repos?per_page=50&page=${number(a.page,1)}`})},
  {name:'list_issues',description:'List issues in an explicitly selected GitHub repository.',read:true,schema:schema({owner:short,repo:short,state:{type:'string',enum:['open','closed','all']},page:{type:'integer',minimum:1,maximum:1000}},['owner','repo']),request:a=>({url:`${repo(a)}/issues?per_page=50&state=${part(a.state||'open')}&page=${number(a.page,1)}`})},
  {name:'get_file',description:'Read file metadata/content from a selected GitHub repository. GitHub may return base64 content.',read:true,schema:schema({owner:short,repo:short,path:str,ref:short},['owner','repo','path']),request:a=>({url:`${repo(a)}/contents/${text(a.path).split('/').map(encodeURIComponent).join('/')}?ref=${part(a.ref||'HEAD')}`})},
  {name:'create_issue',description:'Create an issue in the selected repository. Requires a one-use owner approval.',read:false,schema:schema({owner:short,repo:short,title:short,body:{type:'string',maxLength:20000}},['owner','repo','title']),request:a=>({url:`${repo(a)}/issues`,method:'POST',body:{title:text(a.title),body:a.body||''}})},
  {name:'comment_issue',description:'Add a comment to an issue. Requires a one-use owner approval.',read:false,schema:schema({owner:short,repo:short,issue_number:{type:'integer',minimum:1},body:{type:'string',minLength:1,maxLength:20000}},['owner','repo','issue_number','body']),request:a=>({url:`${repo(a)}/issues/${number(a.issue_number,0)}/comments`,method:'POST',body:{body:text(a.body)}})},
 ];
 if(provider==='google')return [
  {name:'calendar_list',description:'List Google calendars granted to this account.',read:true,schema:schema({page_token:short}),request:a=>({url:`https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=50${a.page_token?'&pageToken='+part(a.page_token):''}`})},
  {name:'calendar_events',description:'List events from an explicitly selected Google calendar.',read:true,schema:schema({calendar_id:short,time_min:short,page_token:short},['calendar_id']),request:a=>({url:`https://www.googleapis.com/calendar/v3/calendars/${part(a.calendar_id)}/events?maxResults=50${a.time_min?'&timeMin='+part(a.time_min):''}${a.page_token?'&pageToken='+part(a.page_token):''}`})},
  {name:'calendar_create_event',description:'Create a Google Calendar event in the selected calendar. Requires owner approval.',read:false,schema:schema({calendar_id:short,summary:short,start:{type:'string',format:'date-time'},end:{type:'string',format:'date-time'},timezone:short,description:{type:'string',maxLength:10000}},['calendar_id','summary','start','end']),request:a=>({url:`https://www.googleapis.com/calendar/v3/calendars/${part(a.calendar_id)}/events`,method:'POST',body:{summary:text(a.summary),description:a.description||'',start:{dateTime:text(a.start),timeZone:a.timezone||'UTC'},end:{dateTime:text(a.end),timeZone:a.timezone||'UTC'}}})},
  {name:'drive_list_files',description:'List Drive file metadata permitted by the granted scope. drive.file does not provide access to all files.',read:true,schema:schema({page_token:short,query:{type:'string',maxLength:1000}}),request:a=>({url:`https://www.googleapis.com/drive/v3/files?pageSize=50&fields=nextPageToken,files(id,name,mimeType,modifiedTime)${a.page_token?'&pageToken='+part(a.page_token):''}${a.query?'&q='+part(a.query):''}`})},
  {name:'drive_get_file',description:'Read Google Drive file metadata and permission capabilities for a granted file.',read:true,schema:schema({file_id:short},['file_id']),request:a=>({url:`https://www.googleapis.com/drive/v3/files/${part(a.file_id)}?fields=id,name,mimeType,modifiedTime,capabilities`})},
  {name:'drive_export_text',description:'Export a granted Google Workspace document as plain text. Output is bounded.',read:true,schema:schema({file_id:short},['file_id']),request:a=>({url:`https://www.googleapis.com/drive/v3/files/${part(a.file_id)}/export?mimeType=text%2Fplain`})},
 ];
 if(provider==='slack')return [
  {name:'list_channels',description:'List Slack conversations accessible to this workspace identity.',read:true,schema:schema({cursor:short}),request:a=>({url:`https://slack.com/api/conversations.list?limit=50${a.cursor?'&cursor='+part(a.cursor):''}`})},
  {name:'channel_history',description:'Read bounded message history from an explicitly selected Slack channel.',read:true,schema:schema({channel:short,cursor:short},['channel']),request:a=>({url:`https://slack.com/api/conversations.history?channel=${part(a.channel)}&limit=50${a.cursor?'&cursor='+part(a.cursor):''}`})},
  {name:'post_message',description:'Send a Slack message to an explicitly selected channel. Requires one-use owner approval.',read:false,schema:schema({channel:short,text:{type:'string',minLength:1,maxLength:12000},thread_ts:short},['channel','text']),request:a=>({url:'https://slack.com/api/chat.postMessage',method:'POST',body:{channel:text(a.channel),text:text(a.text),...(a.thread_ts?{thread_ts:text(a.thread_ts)}:{})}})},
 ];
 return [];
}
