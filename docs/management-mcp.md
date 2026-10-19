# Management MCP

Use one Streamable HTTP MCP connection at `/mcp` and one token per client. It serves profile-granted provider tools and optional management tools together.

| Endpoint | Purpose | Credential |
| --- | --- | --- |
| `/mcp` | Provider tools plus owner-enabled management tools | One client token |
| `/mcp/manage` | Compatibility for earlier separate management clients | Existing legacy management token |

Management tools are built in. Do not register WhereMyMCP as an upstream or add these tools to profile grants. The client profile governs provider tools; the client's separate permission field governs management authority using the same credential.

## Setup

1. Sign in to the owner dashboard and open **Agent clients**.
2. For an existing client, choose **Edit management access**. For a new client, choose **Issue client token** and select the usual profile and client application.
3. Set **Manage WhereMyMCP** to Read, Read + Write, or Read + Write + Delete. It starts off. Owner password and authenticator fields appear when permission is selected; MFA is required when enabled for the owner.
4. Save. Existing clients keep their token, endpoint and profile grants. New client tokens appear once. Reload the MCP client to refresh its tool list.
5. Use **Client config** for Codex, Claude, Cursor or Gemini output, or Hermes/other transport guidance. Every format references the same `/mcp` endpoint and `WHEREMYMCP_TOKEN`.

```toml
[mcp_servers.wheremymcp]
url = "http://127.0.0.1:8080/mcp"
bearer_token_env_var = "WHEREMYMCP_TOKEN"
```

The environment variable must reach the process running the client; exporting it in another terminal does not change an already running desktop app. Keep tokens out of committed configuration files. Native interoperability outside the tested Codex version still needs separate verification.

One expiry, rotation and revocation controls both provider and management access. Rotation of a management-enabled token requires owner password/MFA and immediately invalidates the old token. Revocation and management-permission changes apply on the next request, including for an already connected client. Clearing management access keeps provider access and the token intact. The dashboard never retrieves an existing token.

## Earlier installations

Schema v4 preserves all existing client token hashes, grants and legacy management clients. Existing agent clients gain an empty management scope list; no client becomes an administrator automatically. Existing `/mcp/manage` connections continue to work with their `wmm_` token and original tool names. Their rotate/revoke controls remain visible in **Management MCP**. To consolidate, enable management on the agent client, verify its shared `/mcp` connection, then revoke the old separate management token.

## Tools and scopes

A token sees management tools permitted by its scopes, alongside provider tools permitted by its profile. Each call rechecks current token status, expiry and scope. Scopes are independent in the API; the dashboard offers common permission combinations.

The table lists base operation names. On `/mcp`, names carry the `wheremymcp_manage_` prefix, for example `wheremymcp_manage_servers_list`. Imported provider tool names remain valid; a collision gives the built-in tool an available `_builtin_N` alias. Discovery returns the exact current names without duplicates.

| Scope | Tools |
| --- | --- |
| Read | `overview_get`, `diagnostics_get`, `connections_list`, `servers_list`, `tools_list`, `profiles_list`, `profile_get`, `clients_list`, `client_config`, `audit_list` |
| Write | `server_create`, `server_update`, `server_refresh`, `server_auto_approve`, `server_disable`, `tool_approve`, `profile_create`, `profile_clone`, `profile_set_access`, `client_create`, `client_rotate` |
| Delete | `server_delete`, `profile_delete`, `client_revoke` |

Write grants configuration-administrator authority over servers, profile access and ordinary agent credentials. A management agent can issue an ordinary client with a broad profile. This is intentional delegation; give Read to agents that should only inspect the instance. Management calls themselves do not use the ordinary gateway's one-use approvals. Ordinary agent write/delete calls still require those approvals.

`client_create` can issue only ordinary clients, and `client_rotate` can rotate only clients without management authority. They return the new ordinary token once, so the MCP client, conversation and tool-result logs can receive that secret. Only the owner can grant management access or rotate a management-enabled client. Connection reads never return provider credentials; client lists never return token hashes.

## Example workflow

Ask the connected agent:

> Register this HTTP MCP endpoint using the existing connection named Personal. Trust its current tools, then give Default access to this server. Show the resulting tool count.

The agent can list existing connection/server/profile IDs, call `server_create`, explicitly call `server_auto_approve` with `trust_server: true`, and replace the chosen profile's access using `profile_set_access`. The server retains normal endpoint validation, private-IP restrictions, metadata quarantine and account binding checks.

`profile_set_access` replaces the entire profile selection; use `confirm_replace: true` and exactly one selector: `server_ids`, `tool_ids`, or `all_available: true`. An empty `tool_ids` clears access. To retain existing grants, include their server/tool selection as well. Unavailable exact tool IDs fail before any grant changes. The built-in Default profile cannot be deleted; deleting a bound custom profile requires an explicit replacement profile.

Delete/revoke tools require `confirm: true`. Enabling server tools requires `trust_server: true`. These arguments make intent explicit but are not a second authentication factor.

## Bounds and security

- Tools are a fixed catalog mapped to existing validated application handlers. There is no generic HTTP, SQL, shell or file-execution tool.
- Unified clients keep the existing random `umcp_` token format. Only SHA-256 hashes are stored. Granting management permissions and rotating privileged tokens require an authenticated owner session, CSRF protection, rate limiting and password/MFA step-up.
- Provider-only tokens have no management authority. No client bearer token authenticates directly to owner REST. Legacy management tokens remain specific to `/mcp/manage`.
- Provider credential editing/consent, owner password/MFA/recovery, management-permission grants, backup/restore and key rotation are not exposed through this catalog.
- An internal one-use dispatch capability binds each reused handler request to the authenticated client, credential source, scope, method and URL. HTTP clients cannot supply this capability themselves.
- Domain changes and accepted/denied management calls identify `management:<client-id>` in audit events. Arguments, results and secret tokens are not written to audit events.
- `tools_list` uses database pagination: default 25, maximum 100 results, optional server/search filters and optional full metadata. Compact results omit schemas and bound descriptions to 240 characters. `profile_get` paginates grants; `audit_list` defaults to 25 and permits at most 100 events. Tool responses over 1 MiB return a controlled error requesting a smaller page.
- Existing registry bounds remain: 128 servers, 256 discovered tools per server, 5000 exact grants per profile. Large registries need multiple profiles.
- Restore with `--invalidate-clients` revokes unified clients and any legacy management tokens. Without invalidation, existing permissions are retained. Older supported backups migrate forward without granting management implicitly.

The gateway emergency stop blocks ordinary provider calls. Management access remains available to inspect and repair configuration; use dashboard token revocation to stop a management client.

## Verification

`tests/management.test.ts` exercises real HTTP SDK discovery/calls, server setup, bulk approval/grants, provider and management tools using one token, continued provider write approval, scope changes, owner-only permission grants/privileged rotation, imported name collisions, merged pagination, emergency-stop behavior, MFA, expiry/revocation and audit attribution. The browser suite issues a unified token, edits management permissions, generates Claude configuration, invokes management through `/mcp`, rotates the token while preserving the secret dialog and revokes it. Migration tests verify v3 credential preservation/default-off permissions; backup tests verify token preservation/invalidation.

Screenshots use a disposable test owner: [desktop](evidence/management-1280.png), [mobile](evidence/management-390.png). Live provider OAuth consent and other clients' native configuration formats are outside these fixture checks.

The earlier separate-endpoint implementation passed 76 tests and native Codex CLI 0.163.0 discovery before consolidation. The unified implementation has additional scope, migration, name-collision, lifecycle and browser coverage described above. These fixture checks do not establish live provider consent or native compatibility with every generated client format.

Unified verification on 2026-10-19 passed **81/81 tests**, typecheck/build, dependency audit and static security rules. The local initialized Docker instance migrated from schema v3 to v4 after an encrypted backup; existing credentials, profiles, grants and provider rows were preserved, and existing clients retained empty management scopes. Served dashboard JavaScript and compiled application files matched the verified build. A temporary Read-enabled client exposed **148 tools on one `/mcp` connection** through both the HTTP SDK and native Codex CLI 0.163.0: 138 provider tools and 10 management tools, with no native tool-list error. Write and direct owner-REST access were denied. The temporary client was deleted; persistent user permissions and global Codex configuration were not changed.
