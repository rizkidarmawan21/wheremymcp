import {createHash, randomBytes} from 'node:crypto';
import {createLocalJWKSet, jwtVerify} from 'jose';
import {Hub, httpError} from '../core.js';
import {safeFetch, type FetchPolicy} from './network.js';

type Fetcher = (input: string | URL | Request, init?: RequestInit, policy?: FetchPolicy) => Promise<Response>;
interface Connection {
  id: string; provider: string; status: string; credential: string | null;
  config: string; scopes: string; expires_at: number | null;
}
interface Binding {client_id: string; issuer: string; resource: string; allowed_origin: string}
interface Credential {
  client_secret?: string; secret?: string; access_token?: string; refresh_token?: string;
  expires_at?: number; binding?: Binding;
}
interface Metadata {
  issuer: string; authorization_endpoint: string; token_endpoint: string;
  jwks_uri?: string; revocation_endpoint?: string;
  token_endpoint_auth_methods_supported: string[];
  revocation_endpoint_auth_methods_supported?: string[];
  authorization_response_iss_parameter_supported: boolean;
}
interface Snapshot {
  binding: Binding; metadata: Metadata; verifier: string; generation: string;
  config_hash: string; credential_hash: string; scopes: string[];
}
const digest = (value: string | null) => createHash('sha256').update(value ?? '').digest('hex');
const flowKey = (id: string) => 'remote_oauth_flow:' + id;
const failure = (message: string, status = 400): never => {throw httpError(status, message);};

function secureUrl(value: unknown): URL {
  if (typeof value !== 'string' || value.length > 2048) return failure('Invalid remote OAuth URL');
  let url: URL;
  try {url = new URL(value);} catch {return failure('Invalid remote OAuth URL');}
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return failure('Remote OAuth URLs require HTTPS without credentials, query or fragment');
  return url;
}
function binding(row: Connection): Binding {
  let config: Binding;
  try {config = JSON.parse(row.config);} catch {return failure('Invalid remote OAuth configuration');}
  if (!config || typeof config.client_id !== 'string' || !config.client_id || config.client_id.length > 512) return failure('Remote OAuth client ID is required');
  const issuer = secureUrl(config.issuer), resource = secureUrl(config.resource), origin = secureUrl(config.allowed_origin);
  if (origin.origin !== config.allowed_origin || resource.origin !== config.allowed_origin) return failure('Remote OAuth resource must match its allowed origin');
  if (issuer.href !== config.issuer && issuer.origin !== config.issuer) return failure('Remote OAuth issuer must use a canonical URL');
  return {client_id: config.client_id, issuer: config.issuer, resource: config.resource, allowed_origin: config.allowed_origin};
}
function sameBinding(left: Binding | undefined, right: Binding): boolean {
  return !!left && left.client_id === right.client_id && left.issuer === right.issuer && left.resource === right.resource && left.allowed_origin === right.allowed_origin;
}
function requestedScopes(row: Connection): string[] {
  let scopes: unknown;
  try {scopes = JSON.parse(row.scopes);} catch {return failure('Invalid remote OAuth scopes');}
  if (!Array.isArray(scopes) || scopes.length > 100 || scopes.some(scope => typeof scope !== 'string' || !scope || scope.length > 200 || /\s/.test(scope))) return failure('Invalid remote OAuth scopes');
  return scopes;
}

export class RemoteOAuthManager {
  private readonly refreshes = new Map<string, Promise<Credential>>();
  constructor(readonly hub: Hub, readonly fetcher: Fetcher = safeFetch) {}

  private connection(id: string): Connection {
    const row = this.hub.db.prepare('SELECT * FROM connection WHERE id=?').get(id) as Connection | undefined;
    if (!row || row.provider !== 'remote_oauth') return failure('Remote OAuth connection not found', 404);
    return row;
  }
  private credential(row: Connection): Credential {
    return row.credential ? JSON.parse(this.hub.open(row.credential, 'connection:' + row.id)) : {};
  }
  private session(sessionId: string): void {
    const row = this.hub.db.prepare('SELECT expires_at,last_used FROM session WHERE id=?').get(sessionId) as {expires_at: number; last_used: number} | undefined;
    if (!row || row.expires_at <= Date.now() || row.last_used <= Date.now() - this.hub.config.sessionIdleMs) return failure('Owner session expired or revoked', 403);
  }
  private async json(response: Response): Promise<Record<string, unknown>> {
    const text = await response.text();
    if (Buffer.byteLength(text) > 1_048_576) return failure('Remote OAuth response exceeded its limit', 502);
    let data: unknown;
    try {data = JSON.parse(text);} catch {return failure('Remote OAuth response was invalid', 502);}
    if (!data || typeof data !== 'object' || Array.isArray(data)) return failure('Remote OAuth response was invalid', 502);
    return data as Record<string, unknown>;
  }
  private async discover(config: Binding): Promise<Metadata> {
    const issuer = secureUrl(config.issuer);
    const wellKnown = new URL('/.well-known/oauth-authorization-server' + (issuer.pathname === '/' ? '' : issuer.pathname.replace(/\/$/, '')), issuer.origin);
    const response = await this.fetcher(wellKnown, {}, {allowedOrigin: issuer.origin, timeoutMs: 10000, maxResponseBytes: 1_048_576});
    if (!response.ok) return failure('Remote OAuth discovery failed', 502);
    const data = await this.json(response);
    if (data.issuer !== config.issuer) return failure('Remote OAuth metadata issuer mismatch');
    const endpoint = (value: unknown, required: boolean): string | undefined => {
      if (value === undefined && !required) return undefined;
      const url = secureUrl(value);
      if (url.origin !== issuer.origin) return failure('Remote OAuth metadata endpoints must use the issuer origin');
      return url.href;
    };
    if (!Array.isArray(data.code_challenge_methods_supported) || !data.code_challenge_methods_supported.includes('S256')) return failure('Remote OAuth server must support S256 PKCE');
    const methods = data.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
    if (!Array.isArray(methods) || methods.some(method => typeof method !== 'string')) return failure('Remote OAuth authentication metadata is invalid');
    const revokeMethods = data.revocation_endpoint_auth_methods_supported;
    if (revokeMethods !== undefined && (!Array.isArray(revokeMethods) || revokeMethods.some(method => typeof method !== 'string'))) return failure('Remote OAuth revocation metadata is invalid');
    return {
      issuer: config.issuer,
      authorization_endpoint: endpoint(data.authorization_endpoint, true)!,
      token_endpoint: endpoint(data.token_endpoint, true)!,
      jwks_uri: endpoint(data.jwks_uri, false),
      revocation_endpoint: endpoint(data.revocation_endpoint, false),
      token_endpoint_auth_methods_supported: methods,
      revocation_endpoint_auth_methods_supported: revokeMethods as string[] | undefined,
      authorization_response_iss_parameter_supported: data.authorization_response_iss_parameter_supported === true,
    };
  }
  private authenticate(form: URLSearchParams, config: Binding, credential: Credential, methods: string[]): Headers {
    const headers = new Headers({'content-type': 'application/x-www-form-urlencoded', accept: 'application/json'});
    const secret = credential.client_secret;
    if (secret && methods.includes('client_secret_basic')) {
      const encode = (value: string) => new URLSearchParams({v: value}).toString().slice(2);
      headers.set('authorization', 'Basic ' + Buffer.from(encode(config.client_id) + ':' + encode(secret)).toString('base64'));
    } else if (secret && methods.includes('client_secret_post')) {
      form.set('client_id', config.client_id); form.set('client_secret', secret);
    } else if (!secret && methods.includes('none')) form.set('client_id', config.client_id);
    else return failure('Remote OAuth client authentication method is unsupported');
    return headers;
  }
  private async token(endpoint: string, form: URLSearchParams, config: Binding, credential: Credential, metadata: Metadata, scopes: string[]): Promise<Credential> {
    form.set('resource', config.resource);
    const headers = this.authenticate(form, config, credential, metadata.token_endpoint_auth_methods_supported);
    const response = await this.fetcher(endpoint, {method: 'POST', headers, body: form.toString()}, {allowedOrigin: new URL(config.issuer).origin, timeoutMs: 15000, maxResponseBytes: 1_048_576});
    const data = await this.json(response);
    if (!response.ok || data.error || typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 16384 || /[\r\n]/.test(data.access_token)) return failure('Remote OAuth token exchange failed', 403);
    if (typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer') return failure('Remote OAuth token type must be Bearer');
    if (data.resource !== undefined && data.resource !== config.resource) return failure('Remote OAuth token resource mismatch');
    if (data.refresh_token !== undefined && (typeof data.refresh_token !== 'string' || !data.refresh_token || data.refresh_token.length > 16384)) return failure('Remote OAuth refresh token is invalid');
    if (data.scope !== undefined && (typeof data.scope !== 'string' || data.scope.split(/\s+/).filter(Boolean).some(scope => !scopes.includes(scope)))) return failure('Remote OAuth granted scopes exceed the requested scopes');
    let expiresAt: number | undefined;
    if (data.expires_in !== undefined) {
      if (typeof data.expires_in !== 'number' || !Number.isFinite(data.expires_in) || data.expires_in <= 0 || data.expires_in > 31_536_000) return failure('Remote OAuth token lifetime is invalid');
      expiresAt = Date.now() + data.expires_in * 1000;
    }
    if (data.access_token.split('.').length === 3) {
      if (!metadata.jwks_uri) return failure('Signed remote OAuth access tokens require issuer JWKS');
      const keysResponse = await this.fetcher(metadata.jwks_uri, {}, {allowedOrigin: new URL(config.issuer).origin, timeoutMs: 10000, maxResponseBytes: 1_048_576});
      if (!keysResponse.ok) return failure('Remote OAuth signing keys unavailable', 502);
      const keys = await this.json(keysResponse);
      if (!Array.isArray(keys.keys) || keys.keys.length > 64) return failure('Remote OAuth signing keys are invalid');
      try {
        const result = await jwtVerify(data.access_token, createLocalJWKSet(keys as never), {issuer: config.issuer, audience: config.resource, algorithms: ['RS256', 'PS256', 'ES256', 'EdDSA']});
        if (typeof result.payload.exp !== 'number') return failure('Remote OAuth JWT access token requires expiry');
        const jwtExpiry = result.payload.exp * 1000;
        expiresAt = expiresAt === undefined ? jwtExpiry : Math.min(expiresAt, jwtExpiry);
      } catch {return failure('Remote OAuth access token issuer, signature or audience is invalid', 403);}
    }
    return {...credential, secret: data.access_token, access_token: data.access_token, refresh_token: data.refresh_token as string | undefined ?? credential.refresh_token, expires_at: expiresAt, binding: config};
  }

  async start(connectionId: string, sessionId: string): Promise<{authorization_url: string}> {
    this.session(sessionId);
    const row = this.connection(connectionId), config = binding(row), scopes = requestedScopes(row);
    const metadata = await this.discover(config);
    this.session(sessionId);
    const current = this.connection(connectionId);
    if (current.config !== row.config || current.credential !== row.credential || current.status !== row.status) return failure('Remote OAuth connection changed during discovery', 409);
    const state = randomBytes(32).toString('base64url'), verifier = randomBytes(48).toString('base64url');
    const snapshot: Snapshot = {binding: config, metadata, verifier, generation: state, config_hash: digest(row.config), credential_hash: digest(row.credential), scopes};
    this.hub.db.transaction(() => {
      this.hub.db.prepare('DELETE FROM oauth_state WHERE connection_id=? OR expires_at<?').run(connectionId, Date.now());
      this.hub.db.prepare('INSERT INTO oauth_state VALUES(?,?,?,?,?)').run(state, connectionId, this.hub.seal(JSON.stringify(snapshot), 'oauth:' + state), sessionId, Date.now() + 600000);
      this.hub.setSetting(flowKey(connectionId), state);
      this.hub.db.prepare("UPDATE connection SET status='pending_consent' WHERE id=?").run(connectionId);
    })();
    const url = new URL(metadata.authorization_endpoint);
    const params = {response_type: 'code', client_id: config.client_id, redirect_uri: this.hub.config.origin + '/oauth/callback/remote_oauth', scope: scopes.join(' '), state, resource: config.resource, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256'};
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    this.hub.audit({principal: 'owner', action: 'remote_oauth.start', resource: connectionId});
    return {authorization_url: url.toString()};
  }
  async finish(connectionId: string, state: string, code: string, sessionId: string, iss?: string): Promise<{connection_id: string}> {
    this.session(sessionId);
    if (!state || state.length > 128 || !code || code.length > 4096) return failure('Remote OAuth callback is invalid');
    const saved = this.hub.db.prepare('SELECT * FROM oauth_state WHERE id=? AND connection_id=?').get(state, connectionId) as {verifier: string; session_id: string; expires_at: number} | undefined;
    if (!saved || saved.session_id !== sessionId || saved.expires_at <= Date.now()) return failure('Remote OAuth state is invalid or expired');
    const snapshot = JSON.parse(this.hub.open(saved.verifier, 'oauth:' + state)) as Snapshot;
    if ((snapshot.metadata.authorization_response_iss_parameter_supported && !iss) || (iss !== undefined && iss !== snapshot.binding.issuer)) return failure('Remote OAuth authorization issuer mismatch');
    const row = this.connection(connectionId);
    this.assertFlow(row, snapshot, sessionId);
    if (!this.hub.db.prepare('DELETE FROM oauth_state WHERE id=?').run(state).changes) return failure('Remote OAuth state has already been used');
    try {
      const form = new URLSearchParams({grant_type: 'authorization_code', code, code_verifier: snapshot.verifier, redirect_uri: this.hub.config.origin + '/oauth/callback/remote_oauth'});
      const next = await this.token(snapshot.metadata.token_endpoint, form, snapshot.binding, this.credential(row), snapshot.metadata, snapshot.scopes);
      if (saved.expires_at <= Date.now()) return failure('Remote OAuth authorization expired', 403);
      this.assertFlow(this.connection(connectionId), snapshot, sessionId);
      this.hub.db.prepare("UPDATE connection SET credential=?,status='connected',expires_at=NULL WHERE id=?").run(this.hub.seal(JSON.stringify(next), 'connection:' + connectionId), connectionId);
      this.hub.setSetting(flowKey(connectionId), 'completed:' + state);
      this.hub.audit({principal: 'owner', action: 'remote_oauth.connected', resource: connectionId});
      return {connection_id: connectionId};
    } catch {
      this.hub.db.prepare("UPDATE connection SET status='reauth_required' WHERE id=? AND status='pending_consent' AND credential IS ? AND config=? AND EXISTS(SELECT 1 FROM settings WHERE key=? AND value=?)").run(connectionId, row.credential, row.config, flowKey(connectionId), snapshot.generation);
      this.hub.audit({principal: 'owner', action: 'remote_oauth.callback', resource: connectionId, outcome: 'deny', detail: 'exchange_or_binding_failed'});
      return failure('Remote OAuth authorization failed', 403);
    }
  }
  private assertFlow(row: Connection, snapshot: Snapshot, sessionId: string): void {
    this.session(sessionId);
    if (row.status !== 'pending_consent' || this.hub.setting(flowKey(row.id)) !== snapshot.generation || digest(row.config) !== snapshot.config_hash || digest(row.credential) !== snapshot.credential_hash || !sameBinding(binding(row), snapshot.binding)) return failure('Remote OAuth flow was superseded, revoked or changed', 409);
  }
  async resolve(connectionId: string): Promise<Credential> {
    const row = this.connection(connectionId), config = binding(row);
    if (row.status !== 'connected' || !row.credential || (row.expires_at !== null && row.expires_at <= Date.now())) return failure('Remote OAuth connection is unavailable', 403);
    const credential = this.credential(row);
    if (!sameBinding(credential.binding, config)) return failure('Remote OAuth token resource binding changed', 403);
    if (!credential.expires_at || credential.expires_at > Date.now() + 60000) return credential;
    const pending = this.refreshes.get(connectionId);
    if (pending) return pending;
    const promise = this.refresh(row, config, credential);
    this.refreshes.set(connectionId, promise);
    try {return await promise;} finally {this.refreshes.delete(connectionId);}
  }
  private async refresh(row: Connection, config: Binding, credential: Credential): Promise<Credential> {
    try {
      if (!credential.refresh_token) return failure('Remote OAuth requires reauthorization', 403);
      const metadata = await this.discover(config);
      const beforeExchange = this.connection(row.id);
      if (beforeExchange.status !== 'connected' || beforeExchange.credential !== row.credential || beforeExchange.config !== row.config) return failure('Remote OAuth connection changed before refresh', 409);
      const next = await this.token(metadata.token_endpoint, new URLSearchParams({grant_type: 'refresh_token', refresh_token: credential.refresh_token}), config, credential, metadata, requestedScopes(row));
      const current = this.connection(row.id);
      if (current.status !== 'connected' || current.credential !== row.credential || current.config !== row.config) return failure('Remote OAuth connection was revoked or changed during refresh', 409);
      this.hub.db.prepare('UPDATE connection SET credential=? WHERE id=?').run(this.hub.seal(JSON.stringify(next), 'connection:' + row.id), row.id);
      this.hub.audit({action: 'remote_oauth.refresh', resource: row.id});
      return next;
    } catch {
      this.hub.db.prepare("UPDATE connection SET status='reauth_required' WHERE id=? AND status='connected' AND credential IS ? AND config=?").run(row.id, row.credential, row.config);
      return failure('Remote OAuth refresh failed or connection changed', 403);
    }
  }
  async revoke(connectionId: string): Promise<{provider_revocation: string}> {
    const row = this.connection(connectionId);
    let credential: Credential = {}; let readable = true;
    try {credential = this.credential(row);} catch {readable = false;}
    this.hub.db.transaction(() => {
      this.hub.db.prepare("UPDATE connection SET status='revoked',credential=NULL WHERE id=?").run(connectionId);
      this.hub.db.prepare('DELETE FROM oauth_state WHERE connection_id=?').run(connectionId);
      this.hub.db.prepare('DELETE FROM approval WHERE tool_id IN (SELECT tool.id FROM tool JOIN upstream ON upstream.id=tool.upstream_id WHERE upstream.connection_id=?)').run(connectionId);
      this.hub.setSetting(flowKey(connectionId), 'revoked:' + randomBytes(16).toString('hex'));
    })();
    this.hub.audit({principal: 'owner', action: 'remote_oauth.revoke', resource: connectionId});
    let result = 'not_supported';
    try {
      if (!readable) throw new Error('credential_unavailable');
      const config = binding(row), metadata = await this.discover(config), token = credential.refresh_token || credential.secret || credential.access_token;
      if (metadata.revocation_endpoint && token) {
        const form = new URLSearchParams({token, token_type_hint: credential.refresh_token ? 'refresh_token' : 'access_token'});
        const headers = this.authenticate(form, config, credential, metadata.revocation_endpoint_auth_methods_supported ?? metadata.token_endpoint_auth_methods_supported);
        const response = await this.fetcher(metadata.revocation_endpoint, {method: 'POST', headers, body: form.toString()}, {allowedOrigin: new URL(config.issuer).origin, timeoutMs: 15000, maxResponseBytes: 1_048_576});
        result = response.ok ? 'succeeded' : 'failed';
      }
    } catch {result = 'failed';}
    this.hub.audit({action: 'remote_oauth.provider_revoke', resource: connectionId, detail: result});
    return {provider_revocation: result};
  }
}
