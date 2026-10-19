# API and data contracts

All timestamps are Unix milliseconds. JSON fields use snake_case. Admin responses never include encrypted or plaintext credential fields. Errors use `{error, message, request_id}`.

## Database schema

Database tables are defined in `src/core.ts`. All opaque IDs are UUID strings unless stated otherwise.

- `owner(id INTEGER PRIMARY KEY CHECK(id=1), password_hash, totp_secret, mfa_enabled INTEGER, last_totp_step INTEGER, created_at INTEGER)`; totp_secret is encrypted.
- `session(id TEXT PRIMARY KEY, token_hash TEXT UNIQUE, csrf_hash TEXT, csrf_token TEXT encrypted, created_at INTEGER, last_used INTEGER, expires_at INTEGER)`.
- `recovery_code(hash TEXT PRIMARY KEY)`.
- `profile(id TEXT PRIMARY KEY, name TEXT, slug TEXT UNIQUE, is_default INTEGER, created_at INTEGER)`.
- `client(id TEXT PRIMARY KEY, name TEXT, kind TEXT, profile_id TEXT REFERENCES profile, token_hash TEXT UNIQUE, status TEXT, expires_at INTEGER, created_at INTEGER, last_used INTEGER, management_scopes TEXT JSON array DEFAULT '[]')`; management is opt-in and default-off for existing clients.
- `management_client(id TEXT PRIMARY KEY, name TEXT, scopes TEXT JSON array, token_hash TEXT UNIQUE, status TEXT, expires_at INTEGER NOT NULL, created_at INTEGER, last_used INTEGER)`; separate configuration-administration tokens, never ordinary gateway tokens.
- `connection(id TEXT PRIMARY KEY, provider TEXT, alias TEXT UNIQUE, status TEXT, identity TEXT, scopes TEXT JSON array, credential TEXT encrypted, config TEXT JSON object, expires_at INTEGER, created_at INTEGER)`.
- `oauth_state(id TEXT PRIMARY KEY, connection_id TEXT, verifier TEXT encrypted, session_id TEXT, expires_at INTEGER)`.
- `upstream(id TEXT PRIMARY KEY, name TEXT, url TEXT, connection_id TEXT REFERENCES connection, status TEXT, allowed_private_ips TEXT JSON array, timeout_ms INTEGER, created_at INTEGER)`.
- `tool(id TEXT PRIMARY KEY, upstream_id TEXT REFERENCES upstream ON DELETE CASCADE, name TEXT, gateway_name TEXT UNIQUE, description TEXT, input_schema TEXT JSON, annotations TEXT JSON, fingerprint TEXT, approved_fingerprint TEXT, risk TEXT, enabled INTEGER, UNIQUE(upstream_id,name))`.
- `profile_grant(profile_id TEXT REFERENCES profile ON DELETE CASCADE, tool_id TEXT REFERENCES tool ON DELETE CASCADE, connection_id TEXT REFERENCES connection ON DELETE RESTRICT, action_class TEXT, PRIMARY KEY(profile_id,tool_id))`. Connection IDs must match the tool's upstream connection. Read, write, delete are owner-assigned classifications. Write/delete require explicit grants and a one-use approval record.
- `approval(id TEXT PRIMARY KEY, client_id TEXT, tool_id TEXT, arguments_hash TEXT, expires_at INTEGER, used_at INTEGER)`.
- `audit_event(id TEXT PRIMARY KEY, ts INTEGER, principal TEXT, action TEXT, resource TEXT, outcome TEXT, detail TEXT, latency_ms INTEGER, profile_id TEXT, account_id TEXT, account_alias TEXT)`; detail contains controlled codes only. Profile/account fields support indexed audit filters and historical alias search.
- `skill(id TEXT PRIMARY KEY, name TEXT, source TEXT, digest TEXT, content TEXT JSON file map, approved INTEGER, created_at INTEGER)`.
- `settings(key TEXT PRIMARY KEY, value TEXT)`.
- `schema_migration(version INTEGER PRIMARY KEY, applied_at INTEGER)`; current schema version 4. Every upgrade runs in a transaction after checkpointing and writing a mode-0600 pre-migration SQLite copy.

## Core types

`HubConfig`: `dataDir`, `masterKeyFile`, `bootstrapTokenFile`, `host`, `port`, `origin`, `publicMode`, `trustedProxies: string[]`, `sessionTtlMs`, `sessionIdleMs`, `bootstrapTtlMs`, `maxBodyBytes`, `auditRetentionDays`.

`AuditInput`: `{principal?: string, action: string, resource?: string, outcome?: string, detail?: string, latency_ms?: number}`. Omit arbitrary user text from events.

`Hub(dbPath: string, key: Buffer, config: HubConfig)`. `requireClient(request)` returns `{id,name,kind,profile_id,status,expires_at,last_used}` or throws an HTTP error.

`registerGateway(app: FastifyInstance, hub: Hub, requireOwner: OwnerGuard): Promise<void>` owns `/mcp`, `/api/v1/upstreams`, `/api/v1/tools`, tool approval/refresh, and `/api/v1/approvals`. Owner routes are guarded. Gateway uses `hub.requireClient(request)`.

`registerOperations(app, hub, requireOwner): Promise<void>` exported from `src/backup.ts` registers backup/config-export and skill endpoints, delegates skill implementation to `src/skills.ts`. CLI imports Hub and config loading from root.

## Root HTTP routes

- `GET /api/v1/setup` returns `{claimed, public_mode, csrf_required:true}`.
- `POST /setup/claim` body `{setup_token,password}`; returns `{recovery_codes}`. No session auto-login.
- `POST /auth/session` body `{password,totp?,recovery_code?}`; returns `{csrf_token,mfa_required?}` and session cookie on success.
- `GET /auth/session` returns `{authenticated,csrf_token?,mfa_enabled}`. CSRF token is encrypted in its session row.
- `POST /auth/logout`, `POST /auth/mfa/setup` returns `{secret,uri,qr_svg}`, `POST /auth/mfa/enable` body `{totp}`, `POST /auth/mfa/disable` body `{password,totp}`.
- `GET /api/v1/overview` returns `{counts,emergency_stop,recent_events}`.
- `GET|POST /api/v1/profiles`; POST `{name,slug?}`.
- `GET /api/v1/profiles/:id` returns profile with `grants`; `PUT /api/v1/profiles/:id/grants` body `{grants:[{tool_id,connection_id,action_class}]}`.
- `POST /api/v1/profiles/:id/clone` body `{name,slug?}`.
- `DELETE /api/v1/profiles/:id` accepts optional `{replacement_profile_id}`. Built-in default deletion is refused. Bound clients require an explicit different existing replacement; reassignment, pending-approval removal, profile/grant deletion and audit are atomic. Client tokens and revoked status are preserved; replacement grants are not changed.
- `GET|POST /api/v1/clients`; POST `{name,kind,profile_id,ttl_days?,management_scopes?,password?,totp?}` returns `{client,token}` once. Nonempty management scopes require authenticated owner step-up before insertion. Public client metadata returns parsed management scopes, never token hashes.
- `POST /api/v1/clients/:id/revoke`, `POST /api/v1/clients/:id/rotate` returns `{token}` once. Rotation of management-enabled clients requires owner step-up `{password,totp?}` and cannot be delegated through management tools. Issuance/rotation are limited to 8 requests/minute.
- `GET /api/v1/clients/:id/config?kind=codex|claude|cursor|gemini` returns `{snippet,instructions}` with environment-variable token reference, never a stored secret.
- `GET|POST /api/v1/connections`; POST `{provider,alias,secret?,identity?,scopes?,config?}`. Generic header credentials use provider `api_key` or `bearer`; config contains `header_name` only for API key, plus optional `allowed_origin`.
- `PATCH /api/v1/connections/:id` body alias/secret update; `POST /api/v1/connections/:id/revoke`.
- `POST /api/v1/connections/:id/oauth/start` returns `{authorization_url}`; callback `GET /oauth/callback/:provider`.
- `GET /api/v1/audit?limit=&before=&action=&outcome=` returns `{events,next_before}`.
- `POST /api/v1/emergency-stop` body `{enabled:true|false}`.
- `GET /api/v1/system/diagnostics` reports schema version, migration state, TLS deployment expectation and trusted-proxy count; `GET|PATCH /api/v1/settings`.

## Gateway dashboard contracts

- `GET /api/v1/upstreams` returns `{upstreams}`.
- `POST /api/v1/upstreams` body `{name,url,connection_id?,allowed_private_ips?:[],timeout_ms?}` returns `{upstream}`.
- `POST /api/v1/upstreams/:id/refresh`; `POST /api/v1/upstreams/:id/approve`; `POST /api/v1/upstreams/:id/disable`.
- `GET /api/v1/tools` returns `{tools}` including parsed input_schema/annotations.
- `POST /api/v1/tools/:id/approve` body `{risk:'read'|'write'|'delete',enabled:true|false}`.
- `POST /api/v1/approvals` body `{client_id,tool_id,arguments,ttl_seconds?}` returns one-use `{approval_id}`. Client supplies it via `_meta.wheremymcp_approval_id` on tool call; fingerprint binds the argument object.

## Operations dashboard contracts

- `GET /api/v1/backups` returns `{backups:[{name,created_at,size}]}`.
- `POST /api/v1/backup/create` body `{password,totp?}` returns `{name,created_at,size}` after owner step-up.
- `GET /api/v1/config/export` returns a versioned configuration with no credential ciphertexts, tokens, sessions, or MFA secrets.
- `GET /api/v1/skills` returns `{skills}`; `POST /api/v1/skills` body `{name,source,files:{'SKILL.md':'...'}}`.
- `POST /api/v1/skills/:id/approve`; `DELETE /api/v1/skills/:id`.
- CLI: `init`, `backup`, `restore`, `rotate-key`, `skills plan`, `skills sync`. No restore over a running process or nonempty destination. Skill sync requires an explicit target root, dry-run preview and explicit apply; never execute content.

## Bulk server tool approval

`POST /api/v1/upstreams/:id/auto-approve-tools` requires the owner session, CSRF protection and body `{trust_server:true}`. It performs live discovery, approves only currently advertised tools, and activates that server. Explicit destructive hints map to Delete, explicit read-only hints to Read, and missing/unclear hints to Write. Destructive wins if both hints are set. Existing classifications for current tools are replaced only by this explicit owner action.

Approval, fingerprint pinning, pending-approval invalidation, server activation and audit records are committed in one transaction per server. Changed server configuration during discovery aborts approval. No profile grant is created or changed. Removed tools stay disabled. Later discovery still quarantines changed metadata; no permanent automatic trust mode is stored.

The dashboard processes selected servers with four concurrent requests and reports partial failures. Only an explicit HTTP 429 rejection can trigger one retry after `Retry-After`; upstream tool calls are never retried by this flow. The registry limit is 128 servers, discovery is bounded to 256 tools per server, and each profile accepts at most 5000 exact grants.

MCP tool listing joins current client, profile, grants, tools, servers and account state in one query per page. Refresh-required flags are cached only within that request, once per upstream; later requests recheck current policy. Tool-call authorization remains checked for each invocation.

## Management MCP contracts

`POST /mcp` serves both profile-granted provider tools and optional `wheremymcp_manage_*` management tools using one client token. Read, Write and Delete management scopes are independent from profile grants; each request/call rechecks current token status, expiry and permissions. Combined discovery uses the existing 64-tool pages. Emergency stop blocks provider calls while scoped management remains available. Full catalog and delegation boundaries: [Management MCP](management-mcp.md).

`PUT /api/v1/clients/:id/management` accepts `{management_scopes,password?,totp?}` under the owner session and CSRF guard, limited to 8 requests/minute. Nonempty scopes require owner password/MFA step-up. Clearing all scopes requires the owner session/CSRF. This does not rotate the token or change profile grants. Delegated management tools cannot call this API or grant management scopes during client creation.

Legacy `POST /mcp/manage` retains separate management-token discovery/calls under the original bare tool names. GET/DELETE require a valid management bearer token and return 405; transport is stateless. Existing token APIs below remain for compatibility. The dashboard directs new setup to unified Agent clients.

Owner-session and CSRF protected token APIs:

- `GET /api/v1/management/clients` returns `{endpoint,config,tools_count,clients}` with metadata only. Expired active rows are reported as `expired`.
- `POST /api/v1/management/clients` accepts `{name,scopes,ttl_days?,password,totp?}` and returns `{client,token,endpoint,config}` once; expiry defaults to 30 days, maximum 365.
- `POST /api/v1/management/clients/:id/rotate` accepts `{password,totp?}` and returns `{token,endpoint,config}` once. Revoked/expired clients cannot rotate.
- `POST /api/v1/management/clients/:id/revoke` revokes immediately.

Issuance/rotation require owner step-up and are rate limited to 8 requests/minute. No management MCP tool exposes these owner-token APIs.

`GET /api/v1/tools?limit=25&offset=0&server_id=UUID&search=TEXT&include_metadata=false` selects a bounded database page and returns `{items,total,next_offset}`. Maximum limit 100. Compact rows omit tool schemas and include readable server/name plus a bounded description. `include_metadata=true` returns parsed metadata for that page. Omitting `limit` retains the dashboard's existing `{tools}` response.
