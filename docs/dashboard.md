# Owner dashboard

The dashboard is a same-origin HTML/CSS/ES-module application served by the Fastify app. It has no frontend framework, bundler, external fonts, analytics or runtime asset requests.

## Implemented workspaces

| Workspace | Owner operations |
| --- | --- |
| First run and owner login | Claim with local bootstrap token; save one-time recovery codes; password login with TOTP or recovery code; recover session CSRF after reload; logout. Owner-selected policy requires at least 8 characters with lowercase, uppercase, number and symbol. |
| Gateway overview | Real inventory counts and recent audit decisions; emergency-stop state; stop/resume confirmation. A global Stop gateway button is available from every authenticated view. |
| MCP servers | Register endpoint and account binding; exact local-IP exception array; bounded timeout; refresh discovery; approve server; disable routing. |
| Tool review | Show escaped description, input schema, annotations and fingerprint; compare approved and current metadata side by side after drift; review risk and enable the exact metadata. |
| Connections | Account alias and identity; API key, bearer, GitHub, Google, Slack or remote MCP OAuth connection; secret replacement; scope disclosure; BYO OAuth client configuration and provider authorization handoff; revoke. |
| Profiles and grants | Create or clone a profile; select an entire MCP server, all available tools, or individual tools. Search names/accounts, uncheck access or clear the selection, then save. Review-required tools remain unavailable. Delete custom profiles; explicitly choose replacement access for their clients before deletion. The built-in default remains, with editable tool access. |
| Agent clients | Separate profile-bound token per application; optional expiry; token shown once; rotate and revoke; generate and copy environment-variable config for Codex, Claude, Cursor, Gemini, Hermes or generic clients. Hermes/generic output is explicitly transport guidance. |
| Management MCP | Shared `/mcp` endpoint and token; overview of management-enabled agent clients with Edit management access. Agent clients issues tokens, chooses optional management access with conditional owner password/MFA, edits access, and generates all existing client config formats. Legacy separate clients retain rotate/revoke controls. See [management setup](management-mcp.md). |
| One-use approvals | Select client and reviewed write/delete tool; inspect exact JSON argument object and lifetime; return the one-use approval ID for `_meta.wheremymcp_approval_id`. |
| Reviewed skills | Enter file map or source reference; preview every imported file; import unapproved; inspect stored files; approve or delete. CLI sync remains an explicit dry-run/apply operation. |
| Security | Authenticator setup URI and secret; confirm code; disable MFA with step-up; rotate recovery codes; change password and reauthenticate; emergency stop/resume. |
| Audit | Action, outcome, principal/client ID, resource/tool ID, historical profile/account IDs, recorded account alias and local date/time range filters; cursor pagination preserves same-timestamp events; server events remain free of tool arguments/results. |
| Backups and export | Step-up encrypted backup creation and binary download; credential-free JSON export; file/paste import preview followed by step-up import confirmation; restore/key-retention and reapproval instructions. |
| Settings and diagnostics | Inspect TLS/proxy and schema migration status; edit audit-retention days; show immutable runtime settings separately. |

Unsupported providers are not offered. OAuth consent remains an external provider flow, with the provider hostname and requested scopes visible before leaving the instance. Broad Google Drive scopes require the backend's explicit acknowledgment and provider verification controls. Connection aliases match the server's letters/digits/dot/underscore/hyphen format.

Native GitHub/Google/Slack connections expose native provider tools. A remote MCP OAuth connection instead requires `config.client_id`, `config.issuer`, `config.resource` and `config.allowed_origin`; the URL fields must be the exact HTTPS values expected by the remote service. BYO client secret is optional for a public OAuth client. After provider consent, register the remote MCP URL separately and select the stable remote OAuth connection. No remote server is registered automatically.

## Request and rendering boundaries

- Fetch uses same-origin cookies. Mutations send `x-csrf-token` and a JSON body, including `{}` for payload-free Fastify actions. CSRF stays in memory and is recovered from `GET /auth/session` after reload.
- Tool metadata, imported files, errors, schemas, identities and generated snippets enter the document through DOM text nodes. No HTML injection sink is used.
- Passwords, TOTP setup secrets, recovery codes, tokens and approval IDs are not stored in local storage. Only the selected theme is persisted. Secret dialogs clear their content when closed or canceled.
- Config import has a read-only preview before the mutation. The server independently validates the supplied export and step-up credentials. Imported connections need reauthentication, tools need reapproval, and client credentials are not imported.
- Encrypted backup download uses an owner-authenticated POST with CSRF and password/TOTP step-up. The browser receives the encrypted `.umcp` blob; the external master key remains separate.
- Pending forms and action buttons prevent duplicate submissions. Failed forms keep their values and show a readable error. Failed data views expose a retry action. Empty views identify the next useful owner action.

## Accessibility

Native labeled forms, buttons, links, details and dialog elements provide keyboard behavior and focus containment. Escape closes dialogs and the phone directory. Visible focus rings are provided in both themes; a skip link moves to the main workspace. All data views announce loading and errors; state labels carry meaning in text. Buttons, fields, navigation destinations and summary controls have at least 44px targets. Checkbox labels provide the full target area. JSON and machine identifiers wrap without causing page overflow.

## Profiles and tool access

A profile is an allowlist shared by the agent clients assigned to it. A grant allows one tool through its specific server account and reviewed risk classification. A profile with no grants exposes no tools. Write and delete tools still require a one-use approval for each call.

Use **Edit tool access**, check the tools a client needs, and choose **Save access**. Uncheck a tool to remove its grant. **Clear selection** removes every check; changes apply only after saving. Internal gateway identifiers remain available in Tool review details, while permission controls use the original tool names and descriptions.

A custom profile can be deleted. If clients use it, the confirmation requires a replacement profile and explains the immediate permission change. Client tokens remain valid and use the replacement profile; revoked clients remain revoked. Pending approvals are cleared, and the removed profile's grants are deleted without being copied into the replacement. The built-in Default profile cannot be deleted; clearing its access blocks all tools for its clients.

## Setup without per-tool review

1. Register the MCP URLs and select account connections where needed.
2. In **MCP servers**, select multiple servers or **Select all servers**, then **Auto approve selected servers**. Confirm that you trust those servers to describe their current tools. Discovery and approval run as one batch with progress and per-server failure results.
3. In **Profiles & grants**, use **Default → Edit tool access**. Select whole server groups or **Select all available**, then **Save access**. Groups start collapsed for multiple servers, so a large registry does not present thousands of open rows.
4. In **Agent clients**, issue a token using Default and copy the client configuration.

Manual review remains available for a classification override. Its behavior choices describe view/search/list, create/edit/send/run, and deletion. **Enable tool** both saves the classification and enables profile selection; no separate enable checkbox is required. Manual review filters by server and search, rendering 50 tools at a time.

Getting started uses enabled, fingerprint-matched tools and valid grants, rather than treating discovery or the existence of a client as completed permission setup. Account connections are optional when the MCP server needs no credentials.

## Long tool descriptions

Tool review shows a first-sentence preview capped at 240 characters. The full provider description remains available through a keyboard-accessible disclosure. Recognized `<examples>` and `<hints>` blocks appear as separate examples and usage notes; all content is rendered as text, never provider HTML. Profiles use the compact preview while search still covers the full description. Stored tool metadata is unchanged.

## MCP discovery errors

Missing, expired or rejected account authentication returns the controlled `upstream_auth_required` code with instructions to authorize or update the account in Connections. HTTP 401/403 from a remote MCP server receives the same safe classification. Other discovery failures explain endpoint, availability and schema checks without disclosing upstream exception text. Unexpected server errors remain generic.

A completely failed approval batch displays **Tool approval needs attention**, its per-server cause and request ID, and **Review connections**. It does not suggest granting tools that were never enabled.
