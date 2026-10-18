# Single-instance implementation plan

Status: implementation in progress. Latest audit fixes cover client-token snippet leakage, schema migration v2, indexed audit filters, owner-facing runtime diagnostics and supply-chain pinning. MCP resources/prompts, sandboxed stdio bridge, client-specific skill adapters and restore-drill tracking remain open BRD requirements. Managed hosting infrastructure and billing remain outside this application.

## Architecture and constraints

Use a TypeScript modular monolith, Node.js 22+, Fastify, SQLite WAL, and the official MCP TypeScript SDK v2. Keep one owner and one database per installation. Use stable IDs for account and policy bindings. Never add tenancy, team RBAC, billing, an agent harness, or arbitrary shell execution.

The owner dashboard uses cookie sessions and CSRF protection. Agent clients use separate, hashed bearer tokens bound to a profile. Every invocation rechecks the current client, profile, connection, upstream, tool approval, and emergency-stop state. The vault uses AEAD with an externally supplied master key. Logs contain metadata, never tool arguments or results.

Public mode requires TLS termination, an explicit origin, trusted proxy addresses, and owner MFA. Fresh installations bind locally. Stdio execution remains disabled until a separately reviewed sandbox exists, as required by the BRD. Skills are reviewed files, never executable hooks. No telemetry runs.

The owner selected the MIT License for public source distribution. Package metadata retains `private: true` to prevent accidental npm publication. Official package/image publication and deployment remain separate operator actions.

## Work units and ownership

1. Core (`src/core.ts`, `src/config.ts`, `src/auth.ts`, `src/app.ts`, `src/main.ts`, `src/providers.ts`, `tests/core.test.ts`, `tests/auth.test.ts`, `tests/providers.test.ts`): schema migrations, encrypted vault, owner bootstrap/login/MFA/recovery, scoped client tokens, profiles, provider connections and OAuth, audit, emergency stop, HTTP boundaries, application composition.
2. Gateway (`src/gateway/**`, `tests/gateway.test.ts`, `tests/network.test.ts`): remote registry, bounded SSRF-safe transport, discovery, metadata fingerprints, tool approval, namespace routing, protocol negotiation and policy enforcement. Register routes with `registerGateway(app, hub, requireOwner)`.
3. Dashboard (`public/**`, `DESIGN.md`, `tests/dashboard.test.ts`): functional setup/login, overview, servers/tool review, connections/OAuth, profiles/grants, clients/config, MFA/security, audit, skills and backup operations. Static, dependency-light browser application; no raw upstream HTML rendering.
4. Operations (`src/backup.ts`, `src/skills.ts`, `src/cli.ts`, `tests/operations.test.ts`, `Dockerfile`, `compose.yaml`, `deploy/**`, `.github/**`, installation/security/compatibility docs): encrypted online backup/offline restore, key rotation, reviewed skill import/dry-run/sync, hardened containers, Helm, CI/release assets and runbooks.

Workers own disjoint paths. Root coordinates interfaces, integrates all units, performs full verification and reviews the completed application.

## Shared core interface

`Hub` exposes `db` (better-sqlite3), `config`, `seal(plaintext, context)`, `open(ciphertext, context)`, `audit(event)`, `setting(key)`, `setSetting(key, value)`, and `close()`.

`OwnerGuard` is a Fastify pre-handler. It validates the owner session and checks CSRF on mutations. All admin paths use it. `requireClient(request)` authenticates a bearer token against fresh SQLite state and returns the client row.

SQL schema and HTTP route contracts are recorded in `docs/contracts.md`. Each unit starts with acceptance tests, runs them to establish a failing baseline, implements the feature, then verifies the same tests. Global checks: `npm test`, `npm run typecheck`, `npm run build`, dependency audit, real local HTTP/browser smoke, backup/restore drill, and available container/chart validation.

## Acceptance and release evidence

- [ ] Singleton claim closes permanently; owner password is Argon2id; invalid/expired sessions, CSRF and MFA failures are rejected.
- [ ] A client cannot access admin routes; revoked/expired clients and removed grants fail on the next invocation.
- [ ] Connection secrets remain encrypted and absent from API serialization, audit, config exports, and errors.
- [ ] Two upstreams with colliding names route through separate namespaces and account bindings; drift quarantines changed tools.
- [ ] DNS/IP validation blocks metadata, private addresses and rebinding; explicit local exceptions are narrow and audited; redirects do not leak credentials.
- [ ] MCP modern and legacy protocol paths are exercised using the official SDK. Product-client support is claimed only for tested installed versions.
- [ ] OAuth state/PKCE, fixed redirects, issuer checks, serialized refresh and revoke precedence have negative tests. Live provider consent remains unverified without user credentials.
- [ ] All dashboard controls call working routes; keyboard, empty/error states, mobile and escaped untrusted metadata are checked.
- [ ] Encrypted backup restores on fresh state; wrong key/tampering fail; optional client/session revocation works.
- [ ] Skills cannot escape approved directories or execute hooks; dry-run precedes writes and originals are backed up.
- [ ] Compose/Helm and CI assets enforce stated hardening. Actual external signing, multiarchitecture runtime, cluster isolation, provider approvals, independent review and benchmark targets require external evidence.

Do not report unmet release gates as completed simply because source code or CI configuration exists. Produce a final requirements/evidence report separating implemented behavior, locally verified behavior, and external release gates.
