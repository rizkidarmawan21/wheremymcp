import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {Hub} from '../src/core.js';
import {loadConfig} from '../src/config.js';
import {RemoteOAuthManager} from '../src/gateway/remote-oauth.js';

function fixture(t:any){
 const hub=new Hub(':memory:',randomBytes(32),loadConfig({}));t.after(()=>hub.close());
 const id=randomUUID(),sessionId=randomUUID(),config={client_id:'byo-client',issuer:'https://auth.example/tenant',resource:'https://mcp.example/mcp',allowed_origin:'https://mcp.example'};
 hub.db.prepare('INSERT INTO session VALUES(?,?,?,?,?,?,?)').run(sessionId,'session-hash','csrf-hash','encrypted-csrf',Date.now(),Date.now(),Date.now()+3600000);
 hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,config,scopes,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id,'remote_oauth','remote','not_configured',hub.seal(JSON.stringify({client_secret:'byo-secret'}),'connection:'+id),JSON.stringify(config),'["tools:read"]',Date.now());
 const metadata:any={issuer:config.issuer,authorization_endpoint:'https://auth.example/authorize',token_endpoint:'https://auth.example/token',revocation_endpoint:'https://auth.example/revoke',code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['client_secret_post'],authorization_response_iss_parameter_supported:true};
 let token:any={access_token:'opaque-access',refresh_token:'opaque-refresh',token_type:'Bearer',expires_in:3600,scope:'tools:read'};let hook:((input:string,init:RequestInit)=>Promise<Response|undefined>)|undefined;const calls:{url:string;init:RequestInit}[]=[];
 const manager=new RemoteOAuthManager(hub,async(input,init={})=>{const url=String(input);calls.push({url,init});const overridden=await hook?.(url,init);if(overridden)return overridden;if(url.includes('/.well-known/'))return Response.json(metadata);if(url==='https://auth.example/token')return Response.json(token);if(url==='https://auth.example/revoke')return new Response('',{status:200});throw new Error('unexpected_endpoint');});
 return {hub,id,sessionId,config,metadata,calls,manager,setToken:(value:any)=>{token=value;},setHook:(value:typeof hook)=>{hook=value;}};
}

test('resource-bound PKCE authorization is session-bound, encrypted and single-use',async t=>{
 const f=fixture(t);const start=await f.manager.start(f.id,f.sessionId);const auth=new URL(start.authorization_url),state=auth.searchParams.get('state')!;
 assert.equal(auth.searchParams.get('resource'),f.config.resource);assert.equal(auth.searchParams.get('code_challenge_method'),'S256');assert.equal(auth.searchParams.get('code_challenge')?.length,43);
 await assert.rejects(f.manager.finish(f.id,state,'code','other-session',f.config.issuer));
 await assert.rejects(f.manager.finish(f.id,state,'code',f.sessionId,'https://wrong.example'));
 assert.deepEqual(await f.manager.finish(f.id,state,'code',f.sessionId,f.config.issuer),{connection_id:f.id});
 const posted=new URLSearchParams(String(f.calls.find(c=>c.url.endsWith('/token'))!.init.body));assert.equal(posted.get('resource'),f.config.resource);assert.ok(posted.get('code_verifier'));assert.equal(posted.get('client_secret'),'byo-secret');
 assert.equal((await f.manager.resolve(f.id)).secret,'opaque-access');await assert.rejects(f.manager.finish(f.id,state,'code',f.sessionId,f.config.issuer));
 assert.ok(!JSON.stringify(f.hub.db.prepare('SELECT * FROM connection').all()).includes('opaque-access'));
});

test('discovery rejects issuer mismatch, cross-origin credentials and missing S256',async t=>{
 for(const mutation of [(m:any)=>{m.issuer='https://other.example';},(m:any)=>{m.token_endpoint='https://evil.example/token';},(m:any)=>{m.code_challenge_methods_supported=['plain'];}]){
  const f=fixture(t);mutation(f.metadata);await assert.rejects(f.manager.start(f.id,f.sessionId));assert.equal(f.calls.filter(c=>c.url.endsWith('/token')).length,0);
 }
});

test('logout and a newer authorization flow invalidate in-flight completion',async t=>{
 const f=fixture(t);let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);f.setHook(async(url)=>{if(url.endsWith('/token')){await gate;return Response.json({access_token:'stale',token_type:'Bearer',expires_in:3600});}});
 const first=new URL((await f.manager.start(f.id,f.sessionId)).authorization_url).searchParams.get('state')!;const pending=f.manager.finish(f.id,first,'code',f.sessionId,f.config.issuer);await new Promise(resolve=>setImmediate(resolve));
 await f.manager.start(f.id,f.sessionId);release();await assert.rejects(pending);assert.equal((f.hub.db.prepare('SELECT status FROM connection WHERE id=?').get(f.id) as any).status,'pending_consent');
 f.setHook(undefined);const latest=new URL((await f.manager.start(f.id,f.sessionId)).authorization_url).searchParams.get('state')!;f.hub.db.prepare('DELETE FROM session WHERE id=?').run(f.sessionId);await assert.rejects(f.manager.finish(f.id,latest,'code',f.sessionId,f.config.issuer));
});

test('refresh serializes, binds resource, and immediate revoke beats pending refresh',async t=>{
 const f=fixture(t);const state=new URL((await f.manager.start(f.id,f.sessionId)).authorization_url).searchParams.get('state')!;await f.manager.finish(f.id,state,'code',f.sessionId,f.config.issuer);
 const row=f.hub.db.prepare('SELECT credential FROM connection WHERE id=?').get(f.id) as any;const credential=JSON.parse(f.hub.open(row.credential,'connection:'+f.id));credential.expires_at=1;f.hub.db.prepare('UPDATE connection SET credential=? WHERE id=?').run(f.hub.seal(JSON.stringify(credential),'connection:'+f.id),f.id);
 let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);let refreshes=0;f.setHook(async(url,init)=>{if(url.endsWith('/token')){refreshes++;const body=new URLSearchParams(String(init.body));assert.equal(body.get('resource'),f.config.resource);assert.equal(body.get('grant_type'),'refresh_token');await gate;return Response.json({access_token:'fresh',token_type:'Bearer',expires_in:3600});}});
 const first=f.manager.resolve(f.id),second=f.manager.resolve(f.id);await new Promise(resolve=>setImmediate(resolve));assert.equal(refreshes,1);const revoked=f.manager.revoke(f.id);assert.equal((f.hub.db.prepare('SELECT status FROM connection WHERE id=?').get(f.id) as any).status,'revoked');release();await assert.rejects(first);await assert.rejects(second);await revoked;assert.equal((f.hub.db.prepare('SELECT credential FROM connection WHERE id=?').get(f.id) as any).credential,null);
});

test('signed access tokens require exact issuer and resource audience',async t=>{
 const f=fixture(t);const {privateKey,publicKey}=await generateKeyPair('RS256');f.metadata.jwks_uri='https://auth.example/keys';f.setHook(async url=>url.endsWith('/keys')?Response.json({keys:[{...await exportJWK(publicKey),kid:'key'}]}):undefined);
 const jwt=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'key'}).setIssuer(f.config.issuer).setAudience('https://other-resource.example').setExpirationTime('1h').sign(privateKey);f.setToken({access_token:jwt,token_type:'Bearer',expires_in:3600});
 const state=new URL((await f.manager.start(f.id,f.sessionId)).authorization_url).searchParams.get('state')!;await assert.rejects(f.manager.finish(f.id,state,'code',f.sessionId,f.config.issuer));assert.notEqual((f.hub.db.prepare('SELECT status FROM connection WHERE id=?').get(f.id) as any).status,'connected');
});

test('an owner logout during token exchange blocks the final credential commit',async t=>{
 const f=fixture(t);let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);f.setHook(async url=>{if(url.endsWith('/token')){await gate;return Response.json({access_token:'after-logout',token_type:'Bearer',expires_in:3600});}});
 const state=new URL((await f.manager.start(f.id,f.sessionId)).authorization_url).searchParams.get('state')!;const pending=f.manager.finish(f.id,state,'code',f.sessionId,f.config.issuer);await new Promise(resolve=>setImmediate(resolve));f.hub.db.prepare('DELETE FROM session WHERE id=?').run(f.sessionId);release();await assert.rejects(pending);
 assert.ok(!f.hub.open((f.hub.db.prepare('SELECT credential FROM connection WHERE id=?').get(f.id) as any).credential,'connection:'+f.id).includes('after-logout'));
});

test('valid signed access token commits, while resource configuration drift invalidates it',async t=>{
 const f=fixture(t);const {privateKey,publicKey}=await generateKeyPair('RS256');f.metadata.jwks_uri='https://auth.example/keys';f.setHook(async url=>url.endsWith('/keys')?Response.json({keys:[{...await exportJWK(publicKey),kid:'key'}]}):undefined);
 const token=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'key'}).setIssuer(f.config.issuer).setAudience(f.config.resource).setExpirationTime('1h').sign(privateKey);f.setToken({access_token:token,token_type:'Bearer',expires_in:3600});
 const state=new URL((await f.manager.start(f.id,f.sessionId)).authorization_url).searchParams.get('state')!;await f.manager.finish(f.id,state,'code',f.sessionId,f.config.issuer);assert.equal((await f.manager.resolve(f.id)).access_token,token);
 f.hub.db.prepare('UPDATE connection SET config=? WHERE id=?').run(JSON.stringify({...f.config,resource:'https://mcp.example/other'}),f.id);await assert.rejects(f.manager.resolve(f.id));
});

test('local revocation succeeds even when encrypted credentials cannot be decoded',async t=>{
 const f=fixture(t);f.hub.db.prepare("UPDATE connection SET status='connected',credential='corrupt-ciphertext' WHERE id=?").run(f.id);await f.manager.revoke(f.id);const row=f.hub.db.prepare('SELECT status,credential FROM connection WHERE id=?').get(f.id) as any;assert.equal(row.status,'revoked');assert.equal(row.credential,null);
});
