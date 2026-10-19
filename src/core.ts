import Database from 'better-sqlite3';
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, closeSync, constants, copyFileSync, fsyncSync, openSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import type { FastifyRequest, preHandlerHookHandler } from 'fastify';
import { verify } from 'argon2';
import { TOTP, Secret } from 'otpauth';
import type { HubConfig } from './config.js';
import { AsyncLocalStorage } from 'node:async_hooks';

export type OwnerGuard = preHandlerHookHandler;
export interface AuditInput { principal?: string; action: string; resource?: string; outcome?: string; detail?: string; latency_ms?: number; }
export interface ClientRow { id: string; name: string; kind: string; profile_id: string; status: string; expires_at: number | null; last_used: number | null; }
export function hashToken(value: string): string { return createHash('sha256').update(value).digest('hex'); }
export function httpError(statusCode: number, message: string): Error & {statusCode:number} { return Object.assign(new Error(message), { statusCode }); }
export function equalSecret(a: string, b: string): boolean { return timingSafeEqual(Buffer.from(hashToken(a)), Buffer.from(hashToken(b))); }
export const SCHEMA_VERSION = 3;

const schema = `
CREATE TABLE owner(id INTEGER PRIMARY KEY CHECK(id=1),password_hash TEXT NOT NULL,totp_secret TEXT,mfa_enabled INTEGER NOT NULL DEFAULT 0,last_totp_step INTEGER,created_at INTEGER NOT NULL);
CREATE TABLE session(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,csrf_hash TEXT NOT NULL,csrf_token TEXT NOT NULL,created_at INTEGER NOT NULL,last_used INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE recovery_code(hash TEXT PRIMARY KEY);
CREATE TABLE profile(id TEXT PRIMARY KEY,name TEXT NOT NULL,slug TEXT NOT NULL UNIQUE,is_default INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
CREATE UNIQUE INDEX one_default ON profile(is_default) WHERE is_default=1;
CREATE TABLE client(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,profile_id TEXT NOT NULL REFERENCES profile(id),token_hash TEXT NOT NULL UNIQUE,status TEXT NOT NULL DEFAULT 'active',expires_at INTEGER,created_at INTEGER NOT NULL,last_used INTEGER);
CREATE TABLE connection(id TEXT PRIMARY KEY,provider TEXT NOT NULL,alias TEXT NOT NULL UNIQUE,status TEXT NOT NULL,identity TEXT NOT NULL DEFAULT '',scopes TEXT NOT NULL DEFAULT '[]',credential TEXT,config TEXT NOT NULL DEFAULT '{}',expires_at INTEGER,created_at INTEGER NOT NULL);
CREATE TABLE oauth_state(id TEXT PRIMARY KEY,connection_id TEXT NOT NULL REFERENCES connection(id) ON DELETE CASCADE,verifier TEXT NOT NULL,session_id TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE upstream(id TEXT PRIMARY KEY,name TEXT NOT NULL,url TEXT NOT NULL,connection_id TEXT REFERENCES connection(id),status TEXT NOT NULL DEFAULT 'registered',allowed_private_ips TEXT NOT NULL DEFAULT '[]',timeout_ms INTEGER NOT NULL DEFAULT 15000,created_at INTEGER NOT NULL);
CREATE TABLE tool(id TEXT PRIMARY KEY,upstream_id TEXT NOT NULL REFERENCES upstream(id) ON DELETE CASCADE,name TEXT NOT NULL,gateway_name TEXT NOT NULL UNIQUE,description TEXT NOT NULL DEFAULT '',input_schema TEXT NOT NULL,annotations TEXT NOT NULL DEFAULT '{}',fingerprint TEXT NOT NULL,approved_fingerprint TEXT,previous_metadata TEXT,risk TEXT NOT NULL DEFAULT 'write',enabled INTEGER NOT NULL DEFAULT 0,UNIQUE(upstream_id,name));
CREATE TABLE profile_grant(profile_id TEXT NOT NULL REFERENCES profile(id) ON DELETE CASCADE,tool_id TEXT NOT NULL REFERENCES tool(id) ON DELETE CASCADE,connection_id TEXT,action_class TEXT NOT NULL CHECK(action_class IN ('read','write','delete')),PRIMARY KEY(profile_id,tool_id));
CREATE TABLE approval(id TEXT PRIMARY KEY,client_id TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,tool_id TEXT NOT NULL REFERENCES tool(id) ON DELETE CASCADE,arguments_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER);
CREATE TABLE audit_event(id TEXT PRIMARY KEY,ts INTEGER NOT NULL,principal TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,outcome TEXT NOT NULL,detail TEXT NOT NULL,latency_ms INTEGER);
CREATE INDEX audit_ts ON audit_event(ts);
CREATE INDEX audit_principal ON audit_event(principal,ts);
CREATE TABLE skill(id TEXT PRIMARY KEY,name TEXT NOT NULL,source TEXT NOT NULL,digest TEXT NOT NULL,content TEXT NOT NULL,approved INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
`;

type Migration = { version: number; up: (db: Database.Database) => void };
const migrations: Migration[] = [
  { version: 1, up: db => {
    db.exec(schema);
    db.prepare('INSERT INTO profile VALUES(?,?,?,?,?)').run(randomUUID(), 'Default', 'default', 1, Date.now());
  }},
  { version: 2, up: db => {
    db.exec(`
      ALTER TABLE audit_event ADD COLUMN profile_id TEXT;
      ALTER TABLE audit_event ADD COLUMN account_id TEXT;
      ALTER TABLE audit_event ADD COLUMN account_alias TEXT;
      UPDATE audit_event SET
        profile_id=CASE WHEN json_valid(detail) THEN json_extract(detail,'$.profile_id') END,
        account_id=CASE WHEN json_valid(detail) THEN json_extract(detail,'$.account_id') END,
        account_alias=CASE WHEN json_valid(detail) THEN json_extract(detail,'$.account_alias') END;
      DROP INDEX audit_ts;
      DROP INDEX audit_principal;
      CREATE INDEX audit_order ON audit_event(ts DESC,id DESC);
      CREATE INDEX audit_principal_order ON audit_event(principal,ts DESC,id DESC);
      CREATE INDEX audit_profile_order ON audit_event(profile_id,ts DESC,id DESC);
      CREATE INDEX audit_account_order ON audit_event(account_id,ts DESC,id DESC);
      CREATE INDEX audit_alias_order ON audit_event(account_alias,ts DESC,id DESC);
      CREATE TABLE profile_grant_v2(
        profile_id TEXT NOT NULL REFERENCES profile(id) ON DELETE CASCADE,
        tool_id TEXT NOT NULL REFERENCES tool(id) ON DELETE CASCADE,
        connection_id TEXT REFERENCES connection(id) ON DELETE RESTRICT,
        action_class TEXT NOT NULL CHECK(action_class IN ('read','write','delete')),
        PRIMARY KEY(profile_id,tool_id)
      );
      INSERT INTO profile_grant_v2(profile_id,tool_id,connection_id,action_class)
        SELECT profile_id,tool_id,connection_id,action_class FROM profile_grant
        WHERE connection_id IS NULL OR EXISTS(SELECT 1 FROM connection WHERE connection.id=profile_grant.connection_id);
      DROP TABLE profile_grant;
      ALTER TABLE profile_grant_v2 RENAME TO profile_grant;
      CREATE INDEX profile_grant_connection ON profile_grant(connection_id);
    `);
  }},
  { version: 3, up: db => {
    db.exec(`CREATE TABLE management_client(id TEXT PRIMARY KEY,name TEXT NOT NULL,scopes TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,status TEXT NOT NULL DEFAULT 'active',expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,last_used INTEGER);`);
  }},
];

function backupBeforeMigration(db: Database.Database, dbPath: string, version: number): void {
  if (dbPath === ':memory:' || !statSync(dbPath).isFile()) return;
  const result = db.pragma('wal_checkpoint(TRUNCATE)') as { busy: number }[];
  if (result[0]?.busy) throw new Error('Cannot checkpoint database before migration');
  const backupPath = `${dbPath}.pre-migration-v${version}-${Date.now()}-${randomUUID()}.sqlite`;
  copyFileSync(dbPath, backupPath, constants.COPYFILE_EXCL);
  chmodSync(backupPath, 0o600);
  const fd = openSync(backupPath, 'r+');
  try { fsyncSync(fd); } finally { closeSync(fd); }
  const dir = openSync(dirname(backupPath), 'r');
  try { fsyncSync(dir); } finally { closeSync(dir); }
}

export class Hub {
  readonly db: Database.Database;
  readonly key: Buffer;
  readonly config: HubConfig;
  readonly dbPath: string;
  resolveConnectionCredential?: (id:string)=>Promise<{secret?:string;access_token?:string}>;
  nativeTools?: (connectionId:string)=>Promise<Array<{name:string;description:string;inputSchema:Record<string,unknown>;annotations?:Record<string,unknown>}>>;
  nativeCall?: (connectionId:string,name:string,args:Record<string,unknown>,signal?:AbortSignal)=>Promise<{content:Array<{type:'text';text:string}>}>;
  private authInFlight = 0;
  private readonly auditPrincipal = new AsyncLocalStorage<string>();

  constructor(dbPath: string, key: Buffer, config: HubConfig) {
    if (key.length !== 32) throw new Error('Master key must contain exactly 32 raw bytes');
    this.key = Buffer.from(key); this.config = config; this.dbPath = dbPath;
    this.db = new Database(dbPath);
    try {
      this.db.pragma('foreign_keys = ON'); this.db.pragma('busy_timeout = 5000');
      this.db.pragma('journal_mode = WAL'); this.db.pragma('synchronous = FULL');
      const hasLedger = !!this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migration'").get();
      const freshDatabase = !hasLedger;
      let version = 0;
      if (!hasLedger) {
        const initialMigration = migrations[0]!;
        this.db.transaction(() => {
          this.db.exec('CREATE TABLE schema_migration(version INTEGER PRIMARY KEY,applied_at INTEGER NOT NULL)');
          initialMigration.up(this.db);
          this.db.prepare('INSERT INTO schema_migration VALUES(?,?)').run(initialMigration.version, Date.now());
        })();
        version = initialMigration.version;
      } else {
        version = (this.db.prepare('SELECT COALESCE(MAX(version),0) AS version FROM schema_migration').get() as {version:number}).version;
        if (version > SCHEMA_VERSION) throw new Error('Database schema is newer than this release; upgrade the application or restore a compatible backup');
      }
      for (const migration of migrations.filter(item => item.version > version)) {
        if (!freshDatabase) backupBeforeMigration(this.db, dbPath, migration.version);
        this.db.transaction(() => {
          migration.up(this.db);
          this.db.prepare('INSERT INTO schema_migration VALUES(?,?)').run(migration.version, Date.now());
        })();
        version = migration.version;
      }
      if (version !== SCHEMA_VERSION) throw new Error('Database migration ledger is incomplete; restore a compatible backup');
      const check = this.db.pragma('quick_check', { simple: true });
      if (check !== 'ok') throw new Error('Database integrity check failed');
      if (dbPath !== ':memory:') chmodSync(dbPath, 0o600);
      const checkKey = this.setting('key_check');
      if (checkKey) { if (this.open(checkKey, 'system:key-check') !== 'unifymcp') throw new Error('Master key verification failed'); }
      else this.setSetting('key_check', this.seal('unifymcp', 'system:key-check'));
    } catch (err) { this.db.close(); throw err; }
  }

  seal(plaintext: string, context: string): string {
    const wrappingKey = Buffer.from(hkdfSync('sha256', this.key, Buffer.from('unifymcp-v2'), Buffer.from(`wrap:${context}`), 32));
    const dataKey = randomBytes(32);
    try {
      const nonce=randomBytes(12),wrapNonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',dataKey,nonce);
      cipher.setAAD(Buffer.from(context));const data=Buffer.concat([cipher.update(plaintext,'utf8'),cipher.final()]);
      const wrap=createCipheriv('aes-256-gcm',wrappingKey,wrapNonce);wrap.setAAD(Buffer.from(`wrap:${context}`));
      const wrappedKey=Buffer.concat([wrap.update(dataKey),wrap.final()]);
      return JSON.stringify({v:2,kid:hashToken(this.key.toString('hex')).slice(0,16),nonce:nonce.toString('base64'),tag:cipher.getAuthTag().toString('base64'),data:data.toString('base64'),wrapped_key:wrappedKey.toString('base64'),wrap_nonce:wrapNonce.toString('base64'),wrap_tag:wrap.getAuthTag().toString('base64')});
    }finally{wrappingKey.fill(0);dataKey.fill(0);}
  }

  open(ciphertext: string, context: string): string {
    try {
      const payload = JSON.parse(ciphertext);
      if (![1,2].includes(payload.v) || typeof payload.data !== 'string' || payload.kid !== hashToken(this.key.toString('hex')).slice(0,16)) throw new Error();
      let key:Buffer;
      if(payload.v===2){
        const wrappingKey=Buffer.from(hkdfSync('sha256',this.key,Buffer.from('unifymcp-v2'),Buffer.from(`wrap:${context}`),32));
        try{const unwrap=createDecipheriv('aes-256-gcm',wrappingKey,Buffer.from(payload.wrap_nonce,'base64'));unwrap.setAAD(Buffer.from(`wrap:${context}`));unwrap.setAuthTag(Buffer.from(payload.wrap_tag,'base64'));key=Buffer.concat([unwrap.update(Buffer.from(payload.wrapped_key,'base64')),unwrap.final()]);if(key.length!==32)throw new Error();}
        finally{wrappingKey.fill(0);}
      }else key=Buffer.from(hkdfSync('sha256',this.key,Buffer.from('unifymcp-v1'),Buffer.from(context),32));
      try {
        const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(payload.nonce, 'base64'));
        cipher.setAAD(Buffer.from(context)); cipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
        return Buffer.concat([cipher.update(Buffer.from(payload.data, 'base64')), cipher.final()]).toString('utf8');
      } finally { key.fill(0); }
    } catch { throw httpError(503, 'Credential decryption failed'); }
  }

  setting(key: string): string | undefined { return (this.db.prepare('SELECT value FROM settings WHERE key=?').get(key) as {value:string} | undefined)?.value; }
  setSetting(key: string, value: string): void { this.db.prepare('INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, value); }

  audit(event: AuditInput): void {
    event={...event,principal:this.auditPrincipal.getStore()??event.principal};
    const code = (s: string | undefined, fallback: string) => (s || fallback).slice(0,160).replace(/[^a-zA-Z0-9_.:@/-]/g,'_');
    const profile=(this.db.prepare('SELECT profile_id FROM client WHERE id=?').get(event.principal||'') as {profile_id:string}|undefined)?.profile_id;
    const account=this.db.prepare('SELECT c.id,c.alias FROM connection c LEFT JOIN upstream u ON u.connection_id=c.id LEFT JOIN tool t ON t.upstream_id=u.id WHERE t.id=? OR c.id=? LIMIT 1').get(event.resource||'',event.resource||'') as {id:string;alias:string}|undefined;
    const detail=JSON.stringify({code:code(event.detail,''),...(profile?{profile_id:profile}:{}),...(account?{account_id:account.id,account_alias:account.alias}:{})});
    this.db.prepare('INSERT INTO audit_event(id,ts,principal,action,resource,outcome,detail,latency_ms,profile_id,account_id,account_alias) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(randomUUID(),Date.now(),code(event.principal,'system'),code(event.action,'unknown'),code(event.resource,''),code(event.outcome,'ok'),detail,event.latency_ms ?? null,profile??null,account?.id??null,account?.alias??null);
  }

  withAuditPrincipal<T>(principal:string,work:()=>T):T { return this.auditPrincipal.run(principal,work); }

  requireClient(request: FastifyRequest): ClientRow {
    if (this.setting('emergency_stop') === 'true') throw httpError(503, 'Emergency stop is active');
    const bearer = request.headers.authorization;
    if (!bearer?.startsWith('Bearer ') || bearer.length > 512) throw httpError(401, 'Client bearer token required');
    const row = this.db.prepare('SELECT id,name,kind,profile_id,status,expires_at,last_used FROM client WHERE token_hash=?').get(hashToken(bearer.slice(7))) as ClientRow | undefined;
    if (!row || row.status !== 'active' || (row.expires_at !== null && row.expires_at <= Date.now())) throw httpError(401, 'Client credential is invalid or expired');
    this.db.prepare('UPDATE client SET last_used=? WHERE id=?').run(Date.now(),row.id);
    return row;
  }

  async verifyStepUp(password: string, token?: string): Promise<boolean> {
    if (this.authInFlight >= 2) throw httpError(429, 'Authentication is busy');
    const owner = this.db.prepare('SELECT * FROM owner WHERE id=1').get() as any;
    if (!owner || typeof password !== 'string' || password.length > 1024) return false;
    this.authInFlight++;
    try {
      if (!(await verify(owner.password_hash, password))) return false;
      const current = this.db.prepare('SELECT * FROM owner WHERE id=1').get() as any;
      if (!current || current.password_hash !== owner.password_hash) return false;
      if (current.mfa_enabled && !this.consumeTotp(token)) return false;
      return true;
    } finally { this.authInFlight--; }
  }

  consumeTotp(token?: string): boolean {
    const owner = this.db.prepare('SELECT * FROM owner WHERE id=1').get() as any;
    if (!owner?.totp_secret || !token || !/^\d{6}$/.test(token)) return false;
    const totp = new TOTP({ issuer:'WhereMyMCP',label:'Owner',algorithm:'SHA1',digits:6,period:30,secret:Secret.fromBase32(this.open(owner.totp_secret,'owner:totp')) });
    const delta = totp.validate({ token, window:1 });
    if (delta === null) return false;
    const step = Math.floor(Date.now()/30_000)+delta;
    if (owner.last_totp_step !== null && step <= owner.last_totp_step) return false;
    return this.db.prepare('UPDATE owner SET last_totp_step=? WHERE id=1 AND (last_totp_step IS NULL OR last_totp_step<?)').run(step,step).changes === 1;
  }

  prune(): void {
    const now = Date.now();
    this.db.transaction(() => {
      this.db.prepare('DELETE FROM session WHERE expires_at<? OR last_used<?').run(now,now-this.config.sessionIdleMs);
      this.db.prepare('DELETE FROM oauth_state WHERE expires_at<?').run(now);
      this.db.prepare('DELETE FROM approval WHERE expires_at<?').run(now);
      this.db.prepare('DELETE FROM audit_event WHERE ts<?').run(now-Number(this.setting('audit_retention_days')||this.config.auditRetentionDays)*86400_000);
      this.db.prepare('DELETE FROM audit_event WHERE id IN (SELECT id FROM audit_event ORDER BY ts DESC LIMIT -1 OFFSET 100000)').run();
    })();
  }

  close(): void { if (this.db.open) this.db.close(); this.key.fill(0); }
}
