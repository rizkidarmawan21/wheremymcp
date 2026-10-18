import { randomBytes, randomUUID } from 'node:crypto';
import { open, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { hash, argon2id } from 'argon2';
import { Secret, TOTP } from 'otpauth';
import QRCode from 'qrcode';
import { z } from 'zod';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Hub, hashToken, equalSecret, httpError, type OwnerGuard } from './core.js';

export interface OwnerSession { id: string; csrf_token: string; expires_at: number; last_used: number; }
declare module 'fastify' { interface FastifyRequest { ownerSession?: OwnerSession; } }
const passwordSchema = z.string().min(8).max(256).refine(p => /[a-z]/.test(p) && /[A-Z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p), 'Password needs lowercase, uppercase, a digit and a symbol');
export async function passwordHash(password: string): Promise<string> { return hash(password,{type:argon2id,memoryCost:65536,timeCost:3,parallelism:1}); }
const limited = {rateLimit:{max:8,timeWindow:'1 minute'}};

export function ownerGuard(hub: Hub): OwnerGuard {
  return async (request, reply) => {
    const session = findSession(hub, request);
    if (!session) throw httpError(403,'Owner session required');
    if (!['GET','HEAD','OPTIONS'].includes(request.method)) {
      const supplied = request.headers['x-csrf-token'];
      if (typeof supplied !== 'string' || !equalSecret(hashToken(supplied), session.csrf_hash)) throw httpError(403,'CSRF token required');
      const origin = request.headers.origin;
      if (origin && origin !== hub.config.origin) throw httpError(403,'Origin is not allowed');
    }
    request.ownerSession = session;
    hub.db.prepare('UPDATE session SET last_used=? WHERE id=?').run(Date.now(),session.id);
  };
}

function findSession(hub: Hub, request: FastifyRequest): (OwnerSession & {csrf_hash:string}) | undefined {
  const token=request.cookies.hub_session;
  if (!token || token.length>512) return;
  const session=hub.db.prepare('SELECT * FROM session WHERE token_hash=?').get(hashToken(token)) as any;
  if (!session || session.expires_at<=Date.now() || session.last_used<Date.now()-hub.config.sessionIdleMs) return;
  return session;
}

function clearSessions(hub:Hub) { hub.db.prepare('DELETE FROM session').run();hub.db.prepare('DELETE FROM oauth_state').run(); }
function cookieOptions(hub:Hub) {return {httpOnly:true,secure:hub.config.publicMode,sameSite:'lax' as const,path:'/',maxAge:Math.floor(hub.config.sessionTtlMs/1000)};}

export async function registerAuth(app:FastifyInstance,hub:Hub,requireOwner:OwnerGuard):Promise<void> {
  app.get('/api/v1/setup',async()=>({claimed:!!hub.db.prepare('SELECT id FROM owner').get(),public_mode:hub.config.publicMode,csrf_required:true}));
  let hashing=false;
  app.post('/setup/claim',{config:limited},async(request,reply)=>{
    if(hub.db.prepare('SELECT id FROM owner').get() || hub.config.publicMode) throw httpError(404,'Setup is closed');
    if(hashing) throw httpError(429,'Setup is busy');
    const body=z.object({setup_token:z.string().max(256),password:passwordSchema}).strict().parse(request.body);
    let expected:string;
    try {
      const file=await open(hub.config.bootstrapTokenFile,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
      try{const metadata=await file.stat();if(!metadata.isFile()||metadata.size>256||Date.now()-metadata.mtimeMs>hub.config.bootstrapTtlMs)throw new Error();expected=(await file.readFile('utf8')).trim();}
      finally{await file.close();}
    }
    catch{throw httpError(401,'Setup token is missing or expired; generate a new token locally');}
    if(!expected || !equalSecret(expected,body.setup_token)) {hub.audit({action:'setup.claim',outcome:'deny',detail:'invalid_token'});throw httpError(401,'Setup token is invalid');}
    hashing=true;
    try {
      const credential=await passwordHash(body.password);const codes=Array.from({length:10},()=>randomBytes(16).toString('hex'));
      hub.db.transaction(()=>{if(hub.db.prepare('SELECT id FROM owner').get())throw httpError(404,'Setup is closed');
        hub.db.prepare('INSERT INTO owner(id,password_hash,created_at) VALUES(1,?,?)').run(credential,Date.now());
        for(const code of codes)hub.db.prepare('INSERT INTO recovery_code VALUES(?)').run(hashToken(code));
      })();
      await unlink(hub.config.bootstrapTokenFile).catch(()=>{});hub.audit({action:'setup.claim',principal:'owner'});
      return reply.code(201).send({recovery_codes:codes});
    } finally{hashing=false;}
  });

  app.post('/auth/session',{config:limited},async(request,reply)=>{
    const body=z.object({password:z.string().max(1024),totp:z.string().max(10).optional(),recovery_code:z.string().max(128).optional()}).strict().parse(request.body);
    const original=hub.db.prepare('SELECT * FROM owner WHERE id=1').get() as any;
    const validPassword=original && await verifyPassword(hub,body.password);
    const owner=hub.db.prepare('SELECT * FROM owner WHERE id=1').get() as any;
    if(!validPassword || !owner || owner.password_hash!==original.password_hash) {hub.audit({action:'auth.login',outcome:'deny',detail:'invalid_credentials'});throw httpError(401,'Authentication failed');}
    if(!owner.mfa_enabled && (body.totp || body.recovery_code)) {hub.audit({action:'auth.login',outcome:'deny',detail:'mfa_off_with_factor'});return reply.code(401).send({error:'mfa_required',message:'MFA is disabled on this owner; remove the code fields and retry',mfa_required:true});}
    if(owner.mfa_enabled) {
      let valid=false;
      if(body.recovery_code) valid=hub.db.prepare('DELETE FROM recovery_code WHERE hash=?').run(hashToken(body.recovery_code)).changes===1;
      else valid=hub.consumeTotp(body.totp);
      if(!valid){hub.audit({action:'auth.login',outcome:'deny',detail:'mfa_required'});return reply.code(401).send({error:'mfa_required',message:'A valid MFA or recovery code is required',mfa_required:true});}
    }
    const token=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url'),id=randomUUID(),now=Date.now();
    hub.prune();
    // Sessions are bounded to prevent indefinite accumulation on repeated logins.
    hub.db.prepare('DELETE FROM session WHERE id IN (SELECT id FROM session ORDER BY created_at DESC LIMIT -1 OFFSET 19)').run();
    hub.db.prepare('INSERT INTO session VALUES(?,?,?,?,?,?,?)').run(id,hashToken(token),hashToken(csrf),hub.seal(csrf,`csrf:${id}`),now,now,now+hub.config.sessionTtlMs);
    reply.setCookie('hub_session',token,cookieOptions(hub));hub.audit({action:'auth.login',principal:'owner'});
    return {csrf_token:csrf,mfa_enabled:!!owner.mfa_enabled};
  });
  app.get('/auth/session',async(request)=>{
    const session=findSession(hub,request); const owner=hub.db.prepare('SELECT mfa_enabled FROM owner').get() as any;
    if(!session)return {authenticated:false,mfa_enabled:!!owner?.mfa_enabled};
    hub.db.prepare('UPDATE session SET last_used=? WHERE id=?').run(Date.now(),session.id);
    return {authenticated:true,csrf_token:hub.open(session.csrf_token,`csrf:${session.id}`),mfa_enabled:!!owner?.mfa_enabled};
  });
  app.post('/auth/logout',{preHandler:requireOwner},async(request,reply)=>{hub.db.prepare('DELETE FROM session WHERE id=?').run(request.ownerSession!.id);reply.clearCookie('hub_session',{path:'/'});hub.audit({action:'auth.logout',principal:'owner'});return {ok:true};});
  app.post('/auth/mfa/setup',{preHandler:requireOwner},async()=>{
    const owner=hub.db.prepare('SELECT mfa_enabled FROM owner WHERE id=1').get() as any;
    if(owner.mfa_enabled)throw httpError(409,'MFA is already enabled');
    const secret=new Secret({size:20});hub.db.prepare('UPDATE owner SET totp_secret=?,last_totp_step=NULL WHERE id=1').run(hub.seal(secret.base32,'owner:totp'));
    const totp=new TOTP({issuer:'WhereMyMCP',label:new URL(hub.config.origin).hostname,algorithm:'SHA1',digits:6,period:30,secret});
    const uri=totp.toString();
    return {secret:secret.base32,uri,qr_svg:await QRCode.toString(uri,{type:'svg',margin:1,width:240,errorCorrectionLevel:'M'})};
  });
  app.post('/auth/mfa/enable',{preHandler:requireOwner,config:limited},async(request)=>{
    const body=z.object({totp:z.string().regex(/^\d{6}$/)}).strict().parse(request.body);
    if(!hub.consumeTotp(body.totp))throw httpError(401,'Invalid or reused MFA code');
    hub.db.prepare('UPDATE owner SET mfa_enabled=1 WHERE id=1').run();
    hub.db.prepare('DELETE FROM session WHERE id<>?').run(request.ownerSession!.id);hub.audit({action:'auth.mfa.enable',principal:'owner'});return {ok:true};
  });
  app.post('/auth/mfa/disable',{preHandler:requireOwner,config:limited},async(request)=>{
    if(hub.config.publicMode)throw httpError(403,'MFA cannot be disabled in public mode');
    const body=z.object({password:z.string().max(1024),totp:z.string().max(10)}).strict().parse(request.body);
    if(!(await hub.verifyStepUp(body.password,body.totp)))throw httpError(401,'Step-up authentication failed');
    hub.db.prepare('UPDATE owner SET mfa_enabled=0,totp_secret=NULL,last_totp_step=NULL WHERE id=1').run();
    clearSessions(hub);hub.audit({action:'auth.mfa.disable',principal:'owner'});return {ok:true,reauthenticate:true};
  });
  app.post('/auth/password',{preHandler:requireOwner,config:limited},async(request)=>{
    const body=z.object({password:z.string().max(1024),new_password:passwordSchema,totp:z.string().max(10).optional()}).strict().parse(request.body);
    if(!(await hub.verifyStepUp(body.password,body.totp)))throw httpError(401,'Step-up authentication failed');
    hub.db.prepare('UPDATE owner SET password_hash=? WHERE id=1').run(await passwordHash(body.new_password));clearSessions(hub);hub.audit({action:'auth.password.change',principal:'owner'});return {ok:true,reauthenticate:true};
  });
  app.post('/auth/recovery-codes',{preHandler:requireOwner,config:limited},async(request)=>{
    const body=z.object({password:z.string().max(1024),totp:z.string().max(10).optional()}).strict().parse(request.body);
    if(!(await hub.verifyStepUp(body.password,body.totp)))throw httpError(401,'Step-up authentication failed');
    const codes=Array.from({length:10},()=>randomBytes(16).toString('hex'));
    hub.db.transaction(()=>{hub.db.prepare('DELETE FROM recovery_code').run();for(const code of codes)hub.db.prepare('INSERT INTO recovery_code VALUES(?)').run(hashToken(code));})();
    hub.audit({action:'auth.recovery.rotate',principal:'owner'});return {recovery_codes:codes};
  });
}

let loginInFlight=0;
async function verifyPassword(hub:Hub,password:string):Promise<boolean> {
  if(loginInFlight>=2)throw httpError(429,'Authentication is busy');
  loginInFlight++;
  try {const {verify}=await import('argon2');const row=hub.db.prepare('SELECT password_hash FROM owner').get() as any;return !!row && await verify(row.password_hash,password);}
  finally{loginInFlight--;}
}
