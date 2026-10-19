# Management MCP

WhereMyMCP exposes two separate Streamable HTTP MCP endpoints:

| Endpoint | Purpose | Credential |
| --- | --- | --- |
| `/mcp` | Call approved provider tools through profile grants | Agent client token |
| `/mcp/manage` | Manage this WhereMyMCP instance | Management token with Read, Write and/or Delete scopes |

The management endpoint is built in. Do not register it in MCP servers or grant it through a profile. Using the management endpoint does not require importing another server.

## Setup

1. Sign in to the owner dashboard and open **Management MCP**.
2. Choose **Issue management token**, enter a client name and select scopes. Read is selected initially. Add Write only when the agent should change configuration; add Delete when it should remove objects or revoke clients.
3. Select an expiry from 1 to 365 days; the default is 30 days. Confirm the owner password and authenticator code when MFA is enabled.
4. Save the token shown once. Set `WHEREMYMCP_MANAGEMENT_TOKEN` in the environment used to launch Codex. Paste the generated configuration into the client's configuration file and reload its MCP connection.

```toml
[mcp_servers.wheremymcp_management]
url = "http://127.0.0.1:8080/mcp/manage"
bearer_token_env_var = "WHEREMYMCP_MANAGEMENT_TOKEN"
```

The environment variable must reach the process running Codex; exporting it in another terminal does not change an already running desktop app. Keep tokens out of committed configuration files. Other MCP clients can use the same endpoint with `Authorization: Bearer <management-token>`; their native configuration syntax needs separate verification.

Rotation requires owner password/MFA and immediately invalidates the old token. Revocation takes effect on the next request, including for an already connected client. Expired or revoked management clients require a new issuance. The dashboard never retrieves an existing token.

## Tools and scopes

A token sees only tools permitted by its scopes. Each call also rechecks current token status, expiry and scope. Scopes are independent: a Write-only token cannot list registry state.

| Scope | Tools |
| --- | --- |
| Read | `overview_get`, `diagnostics_get`, `connections_list`, `servers_list`, `tools_list`, `profiles_list`, `profile_get`, `clients_list`, `client_config`, `audit_list` |
| Write | `server_create`, `server_update`, `server_refresh`, `server_auto_approve`, `server_disable`, `tool_approve`, `profile_create`, `profile_clone`, `profile_set_access`, `client_create`, `client_rotate` |
| Delete | `server_delete`, `profile_delete`, `client_revoke` |

Write grants configuration-administrator authority over servers, profile access and ordinary agent credentials. A management agent can issue an ordinary client with a broad profile. This is intentional delegation; give Read to agents that should only inspect the instance. Management calls themselves do not use the ordinary gateway's one-use approvals. Ordinary agent write/delete calls still require those approvals.

`client_create` and `client_rotate` return a new ordinary agent token once. The MCP client, conversation and tool-result logs can therefore receive that secret. Keep that conversation private. Connection reads never return provider credentials, and client lists never return token hashes.

## Example workflow

Ask the connected agent:

> Register this HTTP MCP endpoint using the existing connection named Personal. Trust its current tools, then give Default access to this server. Show the resulting tool count.

The agent can list existing connection/server/profile IDs, call `server_create`, explicitly call `server_auto_approve` with `trust_server: true`, and replace the chosen profile's access using `profile_set_access`. The server retains normal endpoint validation, private-IP restrictions, metadata quarantine and account binding checks.

`profile_set_access` replaces the entire profile selection; use `confirm_replace: true` and exactly one selector: `server_ids`, `tool_ids`, or `all_available: true`. An empty `tool_ids` clears access. To retain existing grants, include their server/tool selection as well. Unavailable exact tool IDs fail before any grant changes. The built-in Default profile cannot be deleted; deleting a bound custom profile requires an explicit replacement profile.

Delete/revoke tools require `confirm: true`. Enabling server tools requires `trust_server: true`. These arguments make intent explicit but are not a second authentication factor.

## Bounds and security

- Tools are a fixed catalog mapped to existing validated application handlers. There is no generic HTTP, SQL, shell or file-execution tool.
- Management tokens are random `wmm_` credentials. Only SHA-256 hashes are stored. Issuance/rotation require an authenticated owner session, CSRF protection, rate limiting and password/MFA step-up.
- Ordinary gateway tokens cannot authenticate to `/mcp/manage`. Management tokens cannot authenticate to `/mcp` or directly to owner REST endpoints.
- Provider credential editing/consent, owner password/MFA/recovery, management-token issuance, backup/restore and key rotation are not exposed through this catalog.
- An internal one-use dispatch capability binds each reused handler request to the authenticated manager, scope, method and URL. HTTP clients cannot supply this capability themselves.
- Domain changes and accepted/denied management calls identify `management:<client-id>` in audit events. Arguments, results and secret tokens are not written to audit events.
- `tools_list` uses database pagination: default 25, maximum 100 results, optional server/search filters and optional full metadata. Compact results omit schemas and bound descriptions to 240 characters. `profile_get` paginates grants; `audit_list` defaults to 25 and permits at most 100 events. Tool responses over 1 MiB return a controlled error requesting a smaller page.
- Existing registry bounds remain: 128 servers, 256 discovered tools per server, 5000 exact grants per profile. Large registries need multiple profiles.
- Restore with `--invalidate-clients` revokes both ordinary and management tokens in schema-v3 backups. Restore retains management tokens when client invalidation is not requested. Version-1/2 backups remain supported.

The gateway emergency stop blocks ordinary provider calls. Management access remains available to inspect and repair configuration; use dashboard token revocation to stop a management client.

## Verification

`tests/management.test.ts` exercises real HTTP SDK discovery/calls, server setup, bulk approval/grants, a working ordinary client, continued gateway write approval, scope denial, forged dispatch rejection, owner REST isolation, MFA step-up, token rotation/revocation/expiry and audit attribution. The browser suite issues, rotates and revokes management tokens through the actual UI and invokes a management tool with the SDK. Backup tests verify management-token preservation and invalidation.

Screenshots use a disposable test owner: [desktop](evidence/management-1280.png), [mobile](evidence/management-390.png). Live provider OAuth consent and other clients' native configuration formats are outside these fixture checks.

Local verification on 2026-10-19: full suite **76/76**, typecheck/build and dependency audit passed. The initialized Docker instance upgraded from schema v2 to v3; hashes of existing owner, profile, client, connection, server, tool and grant rows were unchanged. Served dashboard JavaScript matched source. A temporary Read token exercised five management SDK operations and scope denial on the running instance. Native Codex CLI 0.163.0 discovered all 10 Read tools through an isolated process configuration with no tool-list error; the existing ordinary gateway still exposed 138 tools. The temporary verification token was removed. No persistent management token or global Codex configuration was installed by this verification.
