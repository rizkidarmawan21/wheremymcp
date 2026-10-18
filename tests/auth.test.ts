import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hub, hashToken } from '../src/core.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { passwordHash } from '../src/auth.js';

test('owner claim is single-use, cookie admin cannot be replaced with a client token, mutations need CSRF', async () => {
  const dir=mkdtempSync(join(tmpdir(),'hub-auth-')); const key=randomBytes(32);
  const config=loadConfig({HUB_DATA_DIR:dir}); writeFileSync(config.bootstrapTokenFile,'setup-test-token',{mode:0o600}); writeFileSync(config.masterKeyFile,key,{mode:0o600});
  const hub=new Hub(':memory:',key,config); const app=await createApp(hub);
  const post=(url:string,payload:any,headers:any={})=>app.inject({method:'POST',url,payload,headers:{host:'127.0.0.1:8080',...headers}});
  try {
    assert.equal((await post('/setup/claim',{setup_token:'bad',password:'Correct-horse.battery/staple-2026'})).statusCode,401);
    const claimed=await post('/setup/claim',{setup_token:'setup-test-token',password:'Correct-horse.battery/staple-2026'});
    assert.equal(claimed.statusCode,201); assert.equal(claimed.json().recovery_codes.length,10);
    assert.equal((await post('/setup/claim',{setup_token:'setup-test-token',password:'Correct-horse.battery/staple-2026'})).statusCode,404);
    const login=await post('/auth/session',{password:'Correct-horse.battery/staple-2026'}); assert.equal(login.statusCode,200);
    const cookie=String(login.headers['set-cookie']).split(';')[0]!; const csrf=login.json().csrf_token;
    const list=await app.inject({url:'/api/v1/profiles',headers:{cookie,host:'127.0.0.1:8080'}}); assert.equal(list.statusCode,200);
    assert.equal((await post('/api/v1/profiles',{name:'Work'},{cookie})).statusCode,403);
    assert.equal((await post('/api/v1/profiles',{name:'Work'},{cookie,'x-csrf-token':csrf})).statusCode,201);
    const client=await post('/api/v1/clients',{name:'Codex',kind:'codex',profile_id:list.json().profiles[0].id},{cookie,'x-csrf-token':csrf}); assert.equal(client.statusCode,201);
    const token=client.json().token; assert.ok(token);
    assert.equal((await app.inject({url:'/api/v1/profiles',headers:{authorization:`Bearer ${token}`,host:'127.0.0.1:8080'}})).statusCode,403);
    assert.equal(JSON.stringify(hub.db.prepare('SELECT * FROM client').all()).includes(token),false);
    assert.equal((await post('/auth/logout',{}, {cookie,'x-csrf-token':csrf})).statusCode,200);
    assert.equal((await app.inject({url:'/api/v1/profiles',headers:{cookie,host:'127.0.0.1:8080'}})).statusCode,403);
  } finally { await app.close(); hub.close(); rmSync(dir,{recursive:true,force:true}); }
});

test('host, Origin, proxy spoofing and public mode fail closed', async()=>{
  const dir=mkdtempSync(join(tmpdir(),'hub-http-')); const hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));const app=await createApp(hub);
  try {
    assert.equal((await app.inject({url:'/api/v1/setup',headers:{host:'evil.example'}})).statusCode,403);
    assert.equal((await app.inject({url:'/api/v1/setup',headers:{host:'127.0.0.1:8080',origin:'https://evil.example'}})).statusCode,403);
    assert.equal((await app.inject({url:'/api/v1/setup',headers:{host:'127.0.0.1:8080','x-forwarded-host':'evil.example'}})).statusCode,403);
    const insecure=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir,HUB_PUBLIC_MODE:'true',HUB_ORIGIN:'https://hub.example',HUB_TRUSTED_PROXIES:'127.0.0.1'}));
    await assert.rejects(createApp(insecure),/MFA/i); insecure.close();
  }finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('expired owner sessions and revoked clients cannot authorize requests',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-expiry-')); const hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir})); const app=await createApp(hub);
 try{const p=(hub.db.prepare('SELECT id FROM profile').get() as any).id;const id=randomUUID();hub.db.prepare('INSERT INTO client(id,name,kind,profile_id,token_hash,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)').run(id,'x','codex',p,hashToken('dead'),'revoked',Date.now(),null);
 assert.throws(()=>hub.requireClient({headers:{authorization:'Bearer dead'}} as any),/invalid|expired/);
 }finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('login cannot mint a session when the owner password changes during verification',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-race-'));const hub=new Hub(':memory:',randomBytes(32),loadConfig({HUB_DATA_DIR:dir}));
 hub.db.prepare('INSERT INTO owner(id,password_hash,created_at) VALUES(1,?,?)').run(await passwordHash('old password long enough'),Date.now());const app=await createApp(hub);
 try{const pending=app.inject({method:'POST',url:'/auth/session',headers:{host:'127.0.0.1:8080'},payload:{password:'old password long enough'}});await new Promise(r=>setTimeout(r,20));hub.db.prepare('UPDATE owner SET password_hash=? WHERE id=1').run('changed-security-state');const response=await pending;assert.equal(response.statusCode,401);assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM session').get() as any).n,0);}
 finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('MFA login: second factors denied while disabled, TOTP steps single-use, recovery codes one-shot',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'hub-mfa-'));const key=randomBytes(32);
  const config=loadConfig({HUB_DATA_DIR:dir});writeFileSync(config.bootstrapTokenFile,'setup-test-token',{mode:0o600});writeFileSync(config.masterKeyFile,key,{mode:0o600});
  const hub=new Hub(':memory:',key,config);const app=await createApp(hub);
  const {TOTP,Secret}=await import('otpauth');
  let ipSeq=0;
  const post=(url:string,payload:any,headers:any={})=>app.inject({method:'POST',url,payload,remoteAddress:`10.1.${++ipSeq&255}.${++ipSeq%255}`,headers:{host:'127.0.0.1:8080',...headers}});
  const login=async(payload:any)=>post('/auth/session',{password:'Correct-horse.battery/staple-2026',...payload});
  const failure=(response:any)=>{const body=response.json() as any;return response.statusCode===401&&body.mfa_required===true;};
  try{
    const claim=await post('/setup/claim',{setup_token:'setup-test-token',password:'Correct-horse.battery/staple-2026'});
    const codes=(claim.json() as any).recovery_codes as string[];
    // MFA disabled: password alone works; stray second factors are refused, not silently ignored
    assert.equal((await login({})).statusCode,200,'plain password login still works while MFA is off');
    assert.ok(failure(await login({recovery_code:codes[0]!})),'recovery codes must not apply while MFA is disabled');
    assert.ok(failure(await login({totp:'000000'})),'totp must not apply while MFA is disabled');
    // enable MFA exactly as the dashboard would leave it after /auth/mfa/enable
    const secret32='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
    hub.db.prepare('UPDATE owner SET mfa_enabled=1, totp_secret=? WHERE id=1').run(hub.seal(secret32,'owner:totp'));
    const totp=new TOTP({issuer:'UnifyMCP',label:'Owner',algorithm:'SHA1',digits:6,period:30,secret:Secret.fromBase32(secret32)});
    const code=totp.generate() as unknown as string;
    assert.ok(failure(await login({totp:code.slice(0,5)})),'malformed totp must deny login');
    assert.ok(failure(await login({totp:'000000'===code?'111111':'000000'})),'wrong totp must deny');
    const ok=await login({totp:code});
    assert.ok(ok.statusCode===200,`totp login expected 200 got ${ok.statusCode}`);
    assert.ok(failure(await login({totp:code})),'the same TOTP step must not mint a second session');
    assert.ok(failure(await login({recovery_code:'not-a-real-code'})),'unknown recovery code must deny');
    const recovered=await login({recovery_code:codes[0]!});
    assert.ok(recovered.statusCode===200,`recovery login expected 200 got ${recovered.statusCode}`);
    assert.ok(failure(await login({recovery_code:codes[0]!})),'recovery codes are one-shot');
  }finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('MFA setup hands the owner a QR code next to the secret',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'hub-qr-'));const key=randomBytes(32);
  const config=loadConfig({HUB_DATA_DIR:dir});writeFileSync(config.bootstrapTokenFile,'setup-test-token',{mode:0o600});writeFileSync(config.masterKeyFile,key,{mode:0o600});
  const hub=new Hub(':memory:',key,config);const app=await createApp(hub);
  try{
    const claim=await app.inject({method:'POST',url:'/setup/claim',headers:{host:'127.0.0.1:8080'},payload:{setup_token:'setup-test-token',password:'Correct-horse.battery/staple-2026'}});
    assert.equal(claim.statusCode,201);
    const login=await app.inject({method:'POST',url:'/auth/session',headers:{host:'127.0.0.1:8080'},payload:{password:'Correct-horse.battery/staple-2026'}});assert.equal(login.statusCode,200);
    const cookie=String(login.headers['set-cookie']).split(';')[0]!;const csrf=login.json().csrf_token;
    const setup=await app.inject({method:'POST',url:'/auth/mfa/setup',headers:{cookie,host:'127.0.0.1:8080','x-csrf-token':csrf}});
    assert.equal(setup.statusCode,200);
    const body=setup.json() as any;
    assert.equal(typeof body.secret,'string');assert.equal(typeof body.uri,'string');
    assert.match(body.qr_svg,/^<svg/,'QR SVG must be returned for authenticator scanning');
  }finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});

test('owner claim rejects symlink and expired bootstrap files before accepting a fresh token',async()=>{
  const {symlink,unlink,writeFile,utimes}=await import('node:fs/promises');
  const dir=mkdtempSync(join(tmpdir(),'hub-bootstrap-file-'));const key=randomBytes(32);
  const config=loadConfig({HUB_DATA_DIR:dir,HUB_BOOTSTRAP_TTL_MS:'60000'});
  const outside=join(dir,'external-token');await writeFile(outside,'bootstrap-file-token');await symlink(outside,config.bootstrapTokenFile);
  const hub=new Hub(':memory:',key,config),app=await createApp(hub);
  const claim=()=>app.inject({method:'POST',url:'/setup/claim',headers:{host:'127.0.0.1:8080'},payload:{setup_token:'bootstrap-file-token',password:'Correct-horse.battery/staple-2026'}});
  try{
    assert.equal((await claim()).statusCode,401,'A symlink must not supply the bootstrap secret');
    assert.equal(hub.db.prepare('SELECT id FROM owner').get(),undefined);
    await unlink(config.bootstrapTokenFile);await writeFile(config.bootstrapTokenFile,'bootstrap-file-token',{mode:0o600});
    const expired=new Date(Date.now()-120000);await utimes(config.bootstrapTokenFile,expired,expired);
    assert.equal((await claim()).statusCode,401,'Expired bootstrap files must remain rejected');
    await utimes(config.bootstrapTokenFile,new Date(),new Date());
    assert.equal((await claim()).statusCode,201,'A fresh regular bootstrap file still permits setup');
  }finally{await app.close();hub.close();rmSync(dir,{recursive:true,force:true});}
});
