# Requirements and evidence report — WhereMyMCP 0.1.0 (single-instance Community Edition)

Date: 2026-10-18. Scope: single-instance implementation against the Community Edition BRD v2. This report separates implemented behavior, locally verified behavior, known BRD gaps, and external release gates. Local implementation does not authorize deployment or publication.

## 1. Implemented behavior (source, not yet independently verified behavior)

Core, gateway tools, dashboard and operations are implemented. Known BRD gaps remain listed in section 4; source implementation alone does not make the full BRD complete.

- **Core** (`src/core.ts`, `src/config.ts`, `src/auth.ts`, `src/app.ts`, `src/main.ts`, `src/providers.ts`): SQLite WAL schema with ordered migrations through v2 and pre-migration database copies, AEAD credential vault, owner bootstrap/login, Argon2id, TOTP MFA and recovery codes, cookie sessions with CSRF, scoped client tokens, provider OAuth, metadata-only audit, emergency stop and HTTP boundaries.
- **Gateway** (`src/gateway/`): remote MCP tools registry/calls, SSRF-safe transport with DNS pinning/private-address blocking, metadata fingerprints and drift quarantine, per-invocation policy checks and one-use write approvals. MCP resources/prompts and local stdio bridge are not implemented.
- **Dashboard** (`public/`, `DESIGN.md`): setup, login, overview, servers/tools, connections, profiles/grants, clients, MFA/security, audit, backups, skills. Static dependency-light build; untrusted metadata is escaped at render.
- **Operations** (`src/backup.ts`, `src/skills.ts`, `src/cli.ts`): encrypted online backup, authenticated download, offline fresh-directory restore, key rotation with recovery; reviewed skill import/planning; `init`, `bootstrap-reset`; hardened Compose stack, restricted single-replica Helm templates, CI/dependabot/semgrep workflow source.

## 2. Locally verified behavior (evidence collected 2026-10-18, this machine)

| Check | Command | Result |
| --- | --- | --- |
| Typecheck | `npm run typecheck` | Pass, no output |
| Build | `npm run build` | Pass |
| Source checks after audit fixes | `npm run typecheck && npm run build`; `git diff --check`; `docker compose config --quiet` | Pass |
| Current unit/integration/browser suite | `HUB_CAPTURE_DASHBOARD=true npm test` | 62/62 pass, 0 fail, 0 skipped. Expanded browser flow uses the actual app, SQLite and an authenticated MCP fixture. See `e2e-audit-2026-10-18.md`. |
| Dependency audit | `npm audit --omit=dev` | 0 vulnerabilities |
| Compose config validity | `docker compose -f tests/compose.verify.yaml config` | Valid |
| **Compose smoke drill** (disposable `unifymcp-verify` project, fresh volumes, port 18080) | `npx tsx tests/compose-smoke.ts` | **PASS**: fresh owner claim, encrypted upstream account, DNS-pinned container egress, discovery/review/profile grants, read invocation (SDK call end-to-end in-container), one-use write approval + replay rejection, client revoke takes effect on next call, audit shows >10 metadata events and contains neither the client token nor tool arguments, encrypted backup create, logout. Both transport modes (`2026-07-28`, `2025-11-25`) exercised with the official SDK. |
| Current local instance runtime | Compose project `unifymcp`, `http://127.0.0.1:8080` | Recreated from the verified image; ready and healthy. Served JS/CSS match source bytes. Existing owner data preserved. Authenticated feature mutations were exercised on disposable test instances. |
| Real HTTP smoke of backup path | via compose-smoke `/api/v1/backup/create` | Pass inside container drill |

Drill notes: the smoke script requires stale volumes to be removed and `HUB_PORT=18080 HUB_ORIGIN=http://127.0.0.1:18080` when reusing the project; verify stack was torn down after the run. Offline CLI commands refuse while an instance holds `runtime.lock` (concurrency guard verified by message).

Current follow-up: the Docker drill also runs a browser across all 12 dashboard pages at desktop/mobile widths. The verification fixture uses a dedicated port-8081 healthcheck. Detailed feature coverage and current artifacts are in [the E2E audit](e2e-audit-2026-10-18.md).

## 3. Partially verified

- `tests/compose.verify.yaml` validated structurally (`config`); the full stack build+run path was exercised only through the smoke drill project, not the default project file in claim-to-claim lifecycle.
- Helm templates written but `helm lint` not run — helm CLI not installed locally.
- Dashboard accessibility/keyboard/mobile behaviors covered by automated dashboard tests and static screenshot review; no OS screen-reader, real-device keyboard or full manual browser audit.
- Client interop claimed only for the SDK versions exercised (`@modelcontextprotocol/client` 2.3.1).

## 4. Known BRD gaps and external release gates

Known feature gaps, not claimed complete:

- MCP resources/prompts discovery, authorization and calls (BRD MCP-004/MCP-019).
- Sandboxed local stdio bridge and pairing lifecycle (BRD MCP-020/SKL-007); deliberately disabled until a reviewed sandbox exists.
- Skill registry publisher/trust metadata and client-specific adapters; dashboard sync remains CLI-only (BRD SKL-001/SKL-004).
- Dashboard does not record a successful restore drill; backup existence is not recoverability proof (BRD UX-008).
- Real-client compatibility, live OAuth consent and cluster-level enforcement remain unverified.

External release gates requiring evidence not available locally:

1. Official package/image publication (MIT source license selected; `private: true` still blocks artifact publication).
2. Externally signed releases and multiarchitecture image runtime evidence.
3. Independent security review as required by the plan.
4. Live provider consent flows with real user credentials (state/PKCE negative tests exist locally, consent path unverified).
5. Cluster isolation and `helm lint`/cluster validation.
6. Cluster/production benchmark targets, if any.
7. Product-client support claims beyond the SDK tested.
8. Dashboard operating-system-level review for public mode (TLS termination, MFA in public mode requires an exposed origin — not exercised).

## 5. Statement

No unmet release gate is claimed complete. Sections 2 and 3 reflect only evidence collected locally on 2026-10-18; section 4 remains open until external review and owner decisions.

Rename follow-up: current artifacts were refreshed after the WhereMyMCP rename. The existing local Compose project retains its old name to preserve volumes. See [rename compatibility](rename-compatibility.md) for retained formats and [runtime branding evidence](evidence/local-branding.json) for the browser check on port 8080.
