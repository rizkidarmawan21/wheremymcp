import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, readdirSync, statSync } from 'node:fs';
import Database from 'better-sqlite3';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hub, hashToken, SCHEMA_VERSION } from '../src/core.js';
import { loadConfig } from '../src/config.js';

test('vault binds ciphertext to a record and rejects tampering or the wrong key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hub-core-'));
  const config = loadConfig({ HUB_DATA_DIR: dir });
  const hub = new Hub(':memory:', randomBytes(32), config);
  try {
    const ciphertext = hub.seal('credential-canary', 'connection:a');
    assert.equal(JSON.parse(ciphertext).v, 2);
    assert.ok(JSON.parse(ciphertext).wrapped_key);
    assert.equal(hub.open(ciphertext, 'connection:a'), 'credential-canary');
    assert.throws(() => hub.open(ciphertext, 'connection:b'));
    const pieces = JSON.parse(ciphertext); pieces.tag = randomBytes(16).toString('base64');
    assert.throws(() => hub.open(JSON.stringify(pieces), 'connection:a'));
    const other = new Hub(':memory:', randomBytes(32), config);
    assert.throws(() => other.open(ciphertext, 'connection:a')); other.close();
    assert.equal(ciphertext.includes('credential-canary'), false);
  } finally { hub.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('schema is versioned, singleton owner enforced, empty default profile has no grants', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hub-core-'));
  const hub = new Hub(':memory:', randomBytes(32), loadConfig({ HUB_DATA_DIR: dir }));
  try {
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM schema_migration').get() as any).n, SCHEMA_VERSION);
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM profile WHERE is_default=1').get() as any).n, 1);
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM profile_grant').get() as any).n, 0);
    assert.throws(() => hub.db.prepare('INSERT INTO owner(id,password_hash,created_at) VALUES (2,?,?)').run('hash', Date.now()));
    assert.equal(hashToken('test').length, 64);
  } finally { hub.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('configuration refuses accidental public bind and insecure public origin', () => {
  assert.throws(() => loadConfig({ HUB_HOST: '0.0.0.0' }), /loopback|container/i);
  assert.throws(() => loadConfig({ HUB_PUBLIC_MODE: 'true', HUB_ORIGIN: 'http://hub.example', HUB_TRUSTED_PROXIES: '127.0.0.1' }), /https/i);
  assert.throws(() => loadConfig({ HUB_PUBLIC_MODE: 'true', HUB_ORIGIN: 'https://hub.example' }), /prox/i);
  assert.equal(loadConfig({}).host, '127.0.0.1');
});

test('v3 upgrade preserves existing client credentials and never grants management implicitly',()=>{
 const dir=mkdtempSync(join(tmpdir(),'hub-v3-upgrade-')),key=randomBytes(32),config=loadConfig({HUB_DATA_DIR:dir}),path=join(dir,'hub.sqlite');
 let hub:Hub|undefined;
 try{
  hub=new Hub(path,key,config);const profile=hub.db.prepare('SELECT id FROM profile').pluck().get();
  hub.db.prepare('INSERT INTO client(id,name,kind,profile_id,token_hash,created_at) VALUES(?,?,?,?,?,?)').run('existing','Existing','codex',profile,hashToken('existing-token'),0);
  hub.db.prepare('INSERT INTO management_client(id,name,scopes,token_hash,expires_at,created_at) VALUES(?,?,?,?,?,?)').run('legacy','Legacy','["read"]',hashToken('legacy-token'),9999999999999,0);
  hub.db.exec('ALTER TABLE client DROP COLUMN management_scopes; DELETE FROM schema_migration WHERE version=4');
  const before=hub.db.prepare('SELECT * FROM client').get() as any,legacy=hub.db.prepare('SELECT * FROM management_client').get();hub.close();hub=undefined;
  hub=new Hub(path,key,config);
  const {management_scopes,...after}=hub.db.prepare('SELECT * FROM client').get() as any;
  assert.equal(management_scopes,'[]');assert.deepEqual(after,before);assert.deepEqual(hub.db.prepare('SELECT * FROM management_client').get(),legacy);
  assert.equal(hub.db.prepare('SELECT max(version) FROM schema_migration').pluck().get(),4);
  const snapshot=readdirSync(dir).find(name=>name.includes('.pre-migration-v4-'));assert.ok(snapshot);assert.equal(statSync(join(dir,snapshot)).mode&0o777,0o600);
 }finally{hub?.close();rmSync(dir,{recursive:true,force:true});}
});

test('v1 upgrade snapshots existing data, preserves valid grants and indexes historical audit filters', () => {
  const dir=mkdtempSync(join(tmpdir(),'hub-migration-'));
  const dbPath=join(dir,'hub.sqlite'),key=randomBytes(32),config=loadConfig({HUB_DATA_DIR:dir});
  let hub:Hub|undefined;
  try {
    hub=new Hub(dbPath,key,config);
    const profile=(hub.db.prepare('SELECT id FROM profile').get() as any).id;
    const credential=hub.seal('migration-credential','connection:account');
    hub.db.prepare('INSERT INTO connection(id,provider,alias,status,credential,created_at) VALUES(?,?,?,?,?,?)').run('account','bearer','legacy-alias','active',credential,0);
    hub.db.prepare('INSERT INTO upstream(id,name,url,created_at) VALUES(?,?,?,?)').run('upstream','legacy','https://example.test/mcp',0);
    for(const name of ['valid','orphan'])hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,input_schema,fingerprint) VALUES(?,?,?,?,?,?)').run(name,'upstream',name,name,'{}','fp');
    hub.close();hub=undefined;
    const legacy=new Database(dbPath);
    try {
      legacy.exec(`
        DROP INDEX audit_order; DROP INDEX audit_principal_order; DROP INDEX audit_profile_order; DROP INDEX audit_account_order; DROP INDEX audit_alias_order;
        ALTER TABLE audit_event DROP COLUMN profile_id; ALTER TABLE audit_event DROP COLUMN account_id; ALTER TABLE audit_event DROP COLUMN account_alias;
        CREATE INDEX audit_ts ON audit_event(ts); CREATE INDEX audit_principal ON audit_event(principal,ts);
        DROP TABLE profile_grant;
        CREATE TABLE profile_grant(profile_id TEXT NOT NULL REFERENCES profile(id) ON DELETE CASCADE,tool_id TEXT NOT NULL REFERENCES tool(id) ON DELETE CASCADE,connection_id TEXT,action_class TEXT NOT NULL CHECK(action_class IN ('read','write','delete')),PRIMARY KEY(profile_id,tool_id));
        DELETE FROM schema_migration WHERE version>=2;
        DROP TABLE management_client;
        ALTER TABLE client DROP COLUMN management_scopes;
      `);
      legacy.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run(profile,'valid','account','read');
      legacy.prepare('INSERT INTO profile_grant VALUES(?,?,?,?)').run(profile,'orphan','missing-account','read');
      legacy.prepare('INSERT INTO audit_event VALUES(?,?,?,?,?,?,?,?)').run('event',123,'client','tool.call','valid','success',JSON.stringify({profile_id:profile,account_id:'account',account_alias:'legacy-alias'}),1);
    } finally {legacy.close();}
    hub=new Hub(dbPath,key,config);
    assert.equal(hub.open((hub.db.prepare('SELECT credential FROM connection WHERE id=?').get('account') as any).credential,'connection:account'),'migration-credential');
    assert.deepEqual(hub.db.prepare('SELECT tool_id,connection_id FROM profile_grant').all(),[{tool_id:'valid',connection_id:'account'}]);
    assert.deepEqual(hub.db.prepare('SELECT profile_id,account_id,account_alias FROM audit_event WHERE id=?').get('event'),{profile_id:profile,account_id:'account',account_alias:'legacy-alias'});
    assert.deepEqual(hub.db.pragma('foreign_key_check'),[]);
    assert.throws(()=>hub!.db.prepare('DELETE FROM connection WHERE id=?').run('account'),/FOREIGN KEY/);
    const queryPlan=hub.db.prepare('EXPLAIN QUERY PLAN SELECT * FROM audit_event WHERE profile_id=? ORDER BY ts DESC,id DESC LIMIT ?').all(profile,50) as {detail:string}[];
    assert(queryPlan.some(row=>row.detail.includes('audit_profile_order')));
    assert(!queryPlan.some(row=>row.detail.includes('TEMP B-TREE')));
    const snapshots=readdirSync(dir).filter(name=>name.includes('.pre-migration-v2-'));
    assert.equal(snapshots.length,1);
    const snapshotPath=join(dir,snapshots[0]!);
    assert.equal(statSync(snapshotPath).mode&0o777,0o600);
    const snapshot=new Database(snapshotPath,{readonly:true});
    try {
      assert.equal(snapshot.prepare('SELECT MAX(version) FROM schema_migration').pluck().get(),1);
      assert.equal(snapshot.prepare('SELECT COUNT(*) FROM profile_grant').pluck().get(),2);
    } finally {snapshot.close();}
  } finally {hub?.close();rmSync(dir,{recursive:true,force:true});}
});
