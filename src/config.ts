import { resolve } from 'node:path';
import { isIP } from 'node:net';

export interface HubConfig {
  dataDir: string; masterKeyFile: string; bootstrapTokenFile: string;
  host: string; port: number; origin: string; publicMode: boolean;
  trustedProxies: string[]; sessionTtlMs: number; sessionIdleMs: number;
  bootstrapTtlMs: number; maxBodyBytes: number; auditRetentionDays: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): HubConfig {
  const dataDir = resolve(env.HUB_DATA_DIR || 'data');
  const port = integer(env.HUB_PORT, 8080, 1, 65535);
  const host = env.HUB_HOST || '127.0.0.1';
  const publicMode = env.HUB_PUBLIC_MODE === 'true';
  const origin = env.HUB_ORIGIN || `http://127.0.0.1:${port}`;
  const url = new URL(origin);
  if (url.origin !== origin || url.username || url.password) throw new Error('HUB_ORIGIN must be an exact origin without a path or credentials');
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('HUB_ORIGIN requires HTTP or HTTPS');
  const trustedProxies = (env.HUB_TRUSTED_PROXIES || '').split(',').map(s => s.trim()).filter(Boolean);
  if (trustedProxies.some(p => !isIP(p))) throw new Error('Trusted proxies must be explicit IP addresses');
  if (!['127.0.0.1', '::1', 'localhost'].includes(host) && env.HUB_CONTAINER_MODE !== 'true' && !publicMode) {
    throw new Error('Direct installs must bind loopback; container binding requires HUB_CONTAINER_MODE=true');
  }
  if (!publicMode && !['localhost','127.0.0.1','[::1]'].includes(url.hostname)) throw new Error('Local mode requires a loopback origin');
  if (publicMode && url.protocol !== 'https:') throw new Error('Public mode requires HTTPS');
  if (publicMode && trustedProxies.length === 0) throw new Error('Public mode requires explicit trusted proxies');
  return {
    dataDir, masterKeyFile: resolve(env.HUB_MASTER_KEY_FILE || `${dataDir}/master.key`),
    bootstrapTokenFile: resolve(env.HUB_BOOTSTRAP_TOKEN_FILE || `${dataDir}/bootstrap.token`),
    host, port, origin, publicMode, trustedProxies,
    sessionTtlMs: integer(env.HUB_SESSION_TTL_MS, 12*3600_000, 60_000, 7*86400_000),
    sessionIdleMs: integer(env.HUB_SESSION_IDLE_MS, 30*60_000, 60_000, 86400_000),
    bootstrapTtlMs: integer(env.HUB_BOOTSTRAP_TTL_MS, 30*60_000, 60_000, 86400_000),
    maxBodyBytes: integer(env.HUB_MAX_BODY_BYTES, 1024*1024, 1024, 8*1024*1024),
    auditRetentionDays: integer(env.HUB_AUDIT_RETENTION_DAYS, 30, 1, 365),
  };
}

function integer(value: string | undefined, fallback: number, min: number, max: number): number {
  const n = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new Error(`Invalid integer configuration, expected ${min}..${max}`);
  return n;
}
