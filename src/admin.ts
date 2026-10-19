import { randomBytes, randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { Hub, hashToken, httpError, SCHEMA_VERSION, type OwnerGuard } from './core.js';
import {managementScopes,verifyOwnerStepUp} from './management.js';

const idSchema=z.string().uuid();
const profileInput=z.object({name:z.string().trim().min(1).max(100),slug:z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/).optional()}).strict();
const params=(request:any)=>idSchema.parse(request.params.id);
const clientColumns='id,name,kind,profile_id,status,expires_at,created_at,last_used,management_scopes';
const publicClient=(row:any)=>({...row,management_scopes:JSON.parse(row.management_scopes)});
export async function registerAdmin(app:FastifyInstance,hub:Hub,guard:OwnerGuard):Promise<void>{
  const route={preHandler:guard};
  const parseDetail=(event:any)=>{try{const detail=JSON.parse(event.detail);if(detail&&typeof detail==='object'&&!Array.isArray(detail)){Object.assign(event,detail);event.detail=detail.code||'';delete event.code;}}catch{/* Older metadata-only events use a plain controlled code. */}return event;};
  app.get('/api/v1/profiles',route,async()=>({profiles:hub.db.prepare('SELECT * FROM profile ORDER BY created_at').all()}));
  app.post('/api/v1/profiles',route,async(request,reply)=>{
    const body=profileInput.parse(request.body),id=randomUUID(),slug=body.slug||`profile-${id.slice(0,8)}`;
    hub.db.prepare('INSERT INTO profile VALUES(?,?,?,?,?)').run(id,body.name,slug,0,Date.now());hub.audit({principal:'owner',action:'profile.create',resource:id});
    return reply.code(201).send({profile:hub.db.prepare('SELECT * FROM profile WHERE id=?').get(id)});
  });
  app.get('/api/v1/profiles/:id',route,async(request)=>{
    const id=params(request);const profile=hub.db.prepare('SELECT * FROM profile WHERE id=?').get(id);if(!profile)throw httpError(404,'Profile not found');
    return {...profile,profile,grants:hub.db.prepare('SELECT * FROM profile_grant WHERE profile_id=?').all(id)};
  });
  app.put('/api/v1/profiles/:id/grants',route,async(request)=>{
    const id=params(request);if(!hub.db.prepare('SELECT id FROM profile WHERE id=?').get(id))throw httpError(404,'Profile not found');
    const body=z.object({grants:z.array(z.object({tool_id:idSchema,connection_id:idSchema.nullable().optional(),action_class:z.enum(['read','write','delete'])}).strict()).max(5000)}).strict().parse(request.body);
    hub.db.transaction(()=>{
      hub.db.prepare('DELETE FROM profile_grant WHERE profile_id=?').run(id);const seen=new Set<string>();
      for(const grant of body.grants){
        if(seen.has(grant.tool_id))throw httpError(400,'Duplicate tool grant');seen.add(grant.tool_id);
        const tool=hub.db.prepare('SELECT t.risk,u.connection_id FROM tool t JOIN upstream u ON u.id=t.upstream_id WHERE t.id=?').get(grant.tool_id) as any;
        if(!tool || tool.risk!==grant.action_class || (grant.connection_id??null)!==tool.connection_id)throw httpError(400,'Grant must match tool risk and upstream account');
        hub.db.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run(id,grant.tool_id,grant.connection_id??null,grant.action_class);
      }
      hub.db.prepare('DELETE FROM approval WHERE client_id IN (SELECT id FROM client WHERE profile_id=?)').run(id);
    })();hub.audit({principal:'owner',action:'profile.grants.update',resource:id});return {ok:true};
  });
  app.post('/api/v1/profiles/:id/clone',route,async(request,reply)=>{
    const source=params(request);if(!hub.db.prepare('SELECT id FROM profile WHERE id=?').get(source))throw httpError(404,'Profile not found');
    const body=profileInput.parse(request.body),id=randomUUID();hub.db.transaction(()=>{
      hub.db.prepare('INSERT INTO profile VALUES(?,?,?,?,?)').run(id,body.name,body.slug||`profile-${id.slice(0,8)}`,0,Date.now());
      hub.db.prepare('INSERT INTO profile_grant SELECT ?,tool_id,connection_id,action_class FROM profile_grant WHERE profile_id=?').run(id,source);
    })();hub.audit({principal:'owner',action:'profile.clone',resource:id});return reply.code(201).send({profile:hub.db.prepare('SELECT * FROM profile WHERE id=?').get(id)});
  });
  app.delete('/api/v1/profiles/:id',route,async(request)=>{
    const id=params(request),body=z.object({replacement_profile_id:idSchema.optional()}).strict().parse(request.body??{});
    hub.db.transaction(()=>{
      const profile=hub.db.prepare('SELECT is_default FROM profile WHERE id=?').get(id) as {is_default:number}|undefined;
      if(!profile)throw httpError(404,'Profile not found');if(profile.is_default)throw httpError(409,'Default profile cannot be deleted');
      const replacement=body.replacement_profile_id;
      if(replacement===id)throw httpError(400,'Choose a different replacement profile');
      if(replacement&&!hub.db.prepare('SELECT id FROM profile WHERE id=?').get(replacement))throw httpError(404,'Replacement profile not found');
      if(hub.db.prepare('SELECT id FROM client WHERE profile_id=?').get(id)){
        if(!replacement)throw httpError(409,'Choose a replacement profile for the clients using this profile');
        hub.db.prepare('DELETE FROM approval WHERE client_id IN (SELECT id FROM client WHERE profile_id=?)').run(id);
        hub.db.prepare('UPDATE client SET profile_id=? WHERE profile_id=?').run(replacement,id);
      }
      hub.db.prepare('DELETE FROM profile WHERE id=?').run(id);hub.audit({principal:'owner',action:'profile.delete',resource:id});
    })();return {ok:true};
  });
  app.get('/api/v1/clients',route,async()=>({clients:hub.db.prepare(`SELECT ${clientColumns} FROM client ORDER BY created_at`).all().map(publicClient)}));
  app.post('/api/v1/clients',{...route,config:{rateLimit:{max:8,timeWindow:'1 minute'}}},async(request,reply)=>{
    const body=z.object({name:z.string().trim().min(1).max(100),kind:z.enum(['codex','claude','cursor','gemini','hermes','other']),profile_id:idSchema,ttl_days:z.number().int().min(1).max(3650).optional(),management_scopes:managementScopes.default([]),password:z.string().max(1024).optional(),totp:z.string().max(10).optional()}).strict().parse(request.body);
    if(body.management_scopes.length)await verifyOwnerStepUp(hub,request,body);
    if(!hub.db.prepare('SELECT id FROM profile WHERE id=?').get(body.profile_id))throw httpError(400,'Profile not found');
    const id=randomUUID(),token=`umcp_${randomBytes(32).toString('base64url')}`;hub.db.prepare('INSERT INTO client(id,name,kind,profile_id,token_hash,status,expires_at,created_at,management_scopes) VALUES(?,?,?,?,?,?,?,?,?)').run(id,body.name,body.kind,body.profile_id,hashToken(token),'active',body.ttl_days?Date.now()+body.ttl_days*86400_000:null,Date.now(),JSON.stringify(body.management_scopes));
    hub.audit({principal:'owner',action:'client.create',resource:id});return reply.code(201).send({client:publicClient(hub.db.prepare(`SELECT ${clientColumns} FROM client WHERE id=?`).get(id)),token});
  });
  app.post('/api/v1/clients/:id/revoke',route,async(request)=>{const id=params(request);if(!hub.db.prepare("UPDATE client SET status='revoked' WHERE id=?").run(id).changes)throw httpError(404,'Client not found');hub.db.prepare('DELETE FROM approval WHERE client_id=?').run(id);hub.audit({principal:'owner',action:'client.revoke',resource:id});return {ok:true};});
  app.post('/api/v1/clients/:id/rotate',{...route,config:{rateLimit:{max:8,timeWindow:'1 minute'}}},async(request)=>{
    const id=params(request),client=hub.db.prepare('SELECT expires_at,management_scopes FROM client WHERE id=?').get(id) as any;
    if(!client)throw httpError(404,'Client not found');if(client.expires_at!==null&&client.expires_at<=Date.now())throw httpError(409,'Expired client cannot be rotated. Create a new client with a new expiry period.');
    // Delegated rotation must never reveal a token that carries management authority.
    if(JSON.parse(client.management_scopes).length)await verifyOwnerStepUp(hub,request,z.object({password:z.string().max(1024).optional(),totp:z.string().max(10).optional()}).strict().parse(request.body??{}));
    const token=`umcp_${randomBytes(32).toString('base64url')}`;hub.db.prepare("UPDATE client SET token_hash=?,status='active' WHERE id=?").run(hashToken(token),id);hub.db.prepare('DELETE FROM approval WHERE client_id=?').run(id);hub.audit({principal:'owner',action:'client.rotate',resource:id});return {token};
  });
  app.get('/api/v1/clients/:id/config',route,async(request)=>{
    const id=params(request),client=hub.db.prepare('SELECT kind FROM client WHERE id=?').get(id) as any;if(!client)throw httpError(404,'Client not found');
    const kind=z.enum(['codex','claude','cursor','gemini','hermes','other']).parse((request.query as any).kind||client.kind);const url=`${hub.config.origin}/mcp`;
    const snippets:Record<string,string>={
      codex:`[mcp_servers.wheremymcp]\nurl = ${JSON.stringify(url)}\nbearer_token_env_var = "WHEREMYMCP_TOKEN"`,
      claude:JSON.stringify({mcpServers:{wheremymcp:{type:'http',url,headers:{Authorization:'Bearer ${WHEREMYMCP_TOKEN}'}}}},null,2),
      cursor:JSON.stringify({mcpServers:{wheremymcp:{url,headers:{Authorization:'Bearer ${env:WHEREMYMCP_TOKEN}'}}}},null,2),
      gemini:JSON.stringify({mcpServers:{wheremymcp:{httpUrl:url,headers:{Authorization:'Bearer ${WHEREMYMCP_TOKEN}'}}}},null,2),
      hermes:JSON.stringify({url,authorization_env:'WHEREMYMCP_TOKEN'},null,2),other:JSON.stringify({url,authorization_env:'WHEREMYMCP_TOKEN'},null,2),
    };
    return {snippet:snippets[kind],instructions:'Set WHEREMYMCP_TOKEN in the client environment using the token shown at creation or rotation. Restart or reload MCP configuration. Exact client-version compatibility must be verified; Hermes/other output is transport guidance, not a verified native config.'};
  });
  app.post('/api/v1/emergency-stop',route,async(request)=>{const body=z.object({enabled:z.boolean()}).strict().parse(request.body);hub.setSetting('emergency_stop',String(body.enabled));if(body.enabled)hub.db.prepare('DELETE FROM approval').run();hub.audit({principal:'owner',action:'emergency_stop.update',detail:body.enabled?'enabled':'disabled'});return {enabled:body.enabled};});
  app.get('/api/v1/audit',route,async(request)=>{
    const q=z.object({limit:z.coerce.number().int().min(1).max(500).default(100),cursor:z.string().max(256).optional(),before:z.coerce.number().int().optional(),from:z.coerce.number().int().optional(),to:z.coerce.number().int().optional(),action:z.string().max(160).optional(),outcome:z.string().max(160).optional(),principal:z.string().max(160).optional(),resource:z.string().max(160).optional(),profile_id:z.string().uuid().optional(),account_id:z.string().uuid().optional(),account_alias:z.string().max(80).optional()}).parse(request.query);
    const where:string[]=[],values:(string|number)[]=[];
    if(q.cursor){let cursor:{ts:number;id:string};try{cursor=z.object({ts:z.number().int(),id:z.string().uuid()}).strict().parse(JSON.parse(Buffer.from(q.cursor,'base64url').toString('utf8')));}catch{throw httpError(400,'Invalid audit cursor');}where.push('(ts<? OR (ts=? AND id<?))');values.push(cursor.ts,cursor.ts,cursor.id);}
    for(const [field,op,value] of [['ts','<',q.before],['ts','>=',q.from],['ts','<=',q.to],['action','=',q.action],['outcome','=',q.outcome],['principal','=',q.principal],['resource','=',q.resource]] as const){if(value!==undefined){where.push(`${field}${op}?`);values.push(value);}}
    for(const [field,value] of [['profile_id',q.profile_id],['account_id',q.account_id],['account_alias',q.account_alias]] as const){if(value!==undefined){where.push(`${field}=?`);values.push(value);}}
    const events=hub.db.prepare(`SELECT * FROM audit_event${where.length?' WHERE '+where.join(' AND '):''} ORDER BY ts DESC,id DESC LIMIT ?`).all(...values,q.limit) as any[];
    for(const event of events)parseDetail(event);
    const last=events.at(-1);return {events,next_before:events.length===q.limit?last.ts:null,next_cursor:events.length===q.limit?Buffer.from(JSON.stringify({ts:last.ts,id:last.id})).toString('base64url'):null};
  });
  const counts=()=>({...Object.fromEntries(['connection','upstream','tool','client','profile','skill'].map(table=>[`${table}s`,(hub.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as {count:number}).count])),
    enabled_tools:hub.db.prepare("SELECT count(*) FROM tool t JOIN upstream u ON u.id=t.upstream_id WHERE t.enabled=1 AND t.approved_fingerprint=t.fingerprint AND u.status='active'").pluck().get(),
    grants:hub.db.prepare("SELECT count(*) FROM profile_grant g JOIN tool t ON t.id=g.tool_id JOIN upstream u ON u.id=t.upstream_id WHERE t.enabled=1 AND t.approved_fingerprint=t.fingerprint AND u.status='active' AND g.action_class=t.risk AND g.connection_id IS u.connection_id").pluck().get(),
    active_clients:hub.db.prepare("SELECT count(*) FROM client WHERE status='active' AND (expires_at IS NULL OR expires_at>?)").pluck().get(Date.now())});
  app.get('/api/v1/overview',route,async()=>({counts:counts(),emergency_stop:hub.setting('emergency_stop')==='true',recent_events:(hub.db.prepare('SELECT * FROM audit_event ORDER BY ts DESC LIMIT 12').all() as any[]).map(e=>parseDetail(e))}));
  app.get('/api/v1/system/diagnostics',route,async()=>({version:'0.1.0',schema_version:SCHEMA_VERSION,supported_schema_version:SCHEMA_VERSION,migration_status:'current',public_mode:hub.config.publicMode,origin:hub.config.origin,tls_status:hub.config.publicMode?'https_required_at_trusted_proxy':'loopback_http_only',trusted_proxy_count:hub.config.trustedProxies.length,master_key_loaded:hub.key.length===32,sqlite_integrity:hub.db.pragma('quick_check',{simple:true}),counts:counts(),stdio_enabled:false,telemetry_enabled:false,license:'MIT',protocol:'Official MCP SDK v2; tested revisions recorded in compatibility docs'}));
  app.get('/api/v1/settings',route,async()=>({audit_retention_days:Number(hub.setting('audit_retention_days')||hub.config.auditRetentionDays),public_mode:hub.config.publicMode,origin:hub.config.origin,telemetry_enabled:false,stdio_enabled:false}));
  app.patch('/api/v1/settings',route,async(request)=>{const body=z.object({audit_retention_days:z.number().int().min(1).max(365)}).strict().parse(request.body);hub.setSetting('audit_retention_days',String(body.audit_retention_days));hub.audit({principal:'owner',action:'settings.update'});return {ok:true};});
}
