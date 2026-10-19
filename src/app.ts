import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import staticPlugin from '@fastify/static';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { Hub, equalSecret, httpError } from './core.js';
import { registerAuth, ownerGuard } from './auth.js';
import { registerAdmin } from './admin.js';
import { registerProviders } from './providers.js';
import { registerGateway } from './gateway/index.js';
import { registerOperations } from './backup.js';
import {registerManagement,managementApiGuard,isManagementDispatch,withManagementAudit} from './management.js';

export async function createApp(hub:Hub){
  const config=hub.config;
  if(config.publicMode && !(hub.db.prepare('SELECT mfa_enabled FROM owner WHERE id=1').get() as any)?.mfa_enabled)throw new Error('Public mode requires a claimed owner with MFA enabled; configure it in local mode first');
  const app=Fastify({logger:false,bodyLimit:config.maxBodyBytes,requestTimeout:30000,connectionTimeout:10000,keepAliveTimeout:5000,trustProxy:config.publicMode?config.trustedProxies:false,routerOptions:{maxParamLength:256}});
  app.decorateRequest('ownerSession',undefined);
  // Injection starts a new async context; bind the manager principal when the delegated handler runs.
  app.addHook('onRoute',options=>{const handler=options.handler;options.handler=function(request,reply){return withManagementAudit(hub,request,()=>handler.call(this,request,reply));};});
  await app.register(cookie);
  await app.register(rateLimit,{global:true,max:300,timeWindow:'1 minute',keyGenerator:req=>req.ip,cache:10000});
  const expected=new URL(config.origin);const hosts=new Set([expected.host]);
  if(!config.publicMode){hosts.add(`localhost:${config.port}`);hosts.add(`127.0.0.1:${config.port}`);hosts.add(`[::1]:${config.port}`);}
  app.addHook('onRequest',async(request,reply)=>{
    reply.header('x-content-type-options','nosniff').header('x-frame-options','DENY').header('referrer-policy','no-referrer').header('cache-control','no-store').header('permissions-policy','camera=(), microphone=(), geolocation=()').header('content-security-policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if(config.publicMode)reply.header('strict-transport-security','max-age=31536000');
    // Probes expose only process/store availability and never configuration or credentials.
    if(request.method==='GET' && ['/health/live','/health/ready'].includes(request.url)) return;
    if(!request.headers.host || !hosts.has(request.headers.host.toLowerCase()))throw httpError(403,'Host is not allowed');
    if(request.headers.origin && request.headers.origin!==config.origin)throw httpError(403,'Origin is not allowed');
    if(isManagementDispatch(hub,request))return;
    const forwarded=Object.keys(request.headers).some(k=>k==='forwarded'||k.startsWith('x-forwarded-'));
    if(forwarded){
      const direct=request.raw.socket.remoteAddress?.replace(/^::ffff:/,'');
      if(!config.publicMode || !direct || !config.trustedProxies.includes(direct))throw httpError(403,'Forwarded headers from untrusted proxy');
      if(request.headers.forwarded || (request.headers['x-forwarded-host']&&request.headers['x-forwarded-host']!==expected.host) || request.headers['x-forwarded-proto']!=='https')throw httpError(403,'Invalid proxy forwarding configuration');
    }
    if(config.publicMode && request.headers['x-forwarded-proto']!=='https')throw httpError(403,'TLS proxy required');
    if(request.method==='OPTIONS')throw httpError(403,'Cross-origin access is disabled');
  });
  app.addHook('preValidation',async(request)=>{
    if(request.body && typeof request.body==='object'){
      const stack:Array<[unknown,number]>=[[request.body,0]];let nodes=0;
      while(stack.length){const [value,depth]=stack.pop()!;if(depth>32 || ++nodes>20000)throw httpError(413,'JSON structure is too large');if(value&&typeof value==='object')for(const item of Object.values(value))stack.push([item,depth+1]);}
    }
  });
  app.setErrorHandler((error,request,reply)=>{
    let status=(error as any).statusCode||500;let message='Request failed';
    const discoveryMessages:Record<string,string>={upstream_auth_required:'MCP server authentication is missing, expired or rejected. Open Connections, authorize or update its account, then retry Auto approve tools.',upstream_discovery_failed:'Could not discover tools from this MCP server. Check its endpoint, server availability and tool schemas, then retry Refresh tools.'};
    const discoveryCode=Object.hasOwn(discoveryMessages,(error as Error).message)?(error as Error).message:undefined;
    if(error instanceof z.ZodError){status=400;message='Invalid request: '+error.issues.slice(0,4).map(i=>i.path.join('.')||'body').join(', ');}
    else if((error as any).code?.startsWith('SQLITE_CONSTRAINT')){status=409;message='Record conflicts with existing state';}
    else if(status<500){message=(error as Error).message;}
    else if(status===503){message='Service temporarily unavailable';}
    if(discoveryCode)message=discoveryMessages[discoveryCode]!;
    if(status>=500)hub.audit({action:'http.error',outcome:'error',detail:'internal_error'});
    reply.code(status).send({error:discoveryCode??(status===429?'rate_limited':status===400?'invalid_request':status===401?'unauthorized':status===403?'forbidden':'request_failed'),message,request_id:request.id});
  });
  app.get('/health/live',async()=>({status:'alive'}));
  app.get('/health/ready',async(_request,reply)=>{
    try{hub.db.prepare('SELECT 1').get();const key=await readFile(config.masterKeyFile);if(key.length!==32||!equalSecret(key.toString('hex'),hub.key.toString('hex')))throw new Error();return {status:'ready'};}
    catch{return reply.code(503).send({status:'unavailable'});}
  });
  const owner=ownerGuard(hub),guard=managementApiGuard(hub,owner);
  await registerAuth(app,hub,owner);await registerAdmin(app,hub,guard);await registerProviders(app,hub,guard);await registerGateway(app,hub,guard);await registerOperations(app,hub,owner);await registerManagement(app,hub,owner);
  await app.register(staticPlugin,{root:fileURLToPath(new URL('../public/',import.meta.url)),prefix:'/',index:['index.html'],setHeaders(reply){reply.header('Cache-Control','no-cache');}});
  let pruning=false;const interval=setInterval(()=>{if(pruning)return;pruning=true;try{hub.prune();}finally{pruning=false;}},60000);interval.unref();
  app.addHook('onClose',async()=>{clearInterval(interval);});
  return app;
}
