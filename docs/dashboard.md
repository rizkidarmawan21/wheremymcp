# Owner dashboard

The dashboard is a same-origin HTML/CSS/ES-module application served by the Fastify app. It has no frontend framework, bundler, external fonts, analytics or runtime asset requests. Design direction and the reasons for palette, typography, surfaces and responsive composition are in [DESIGN.md](../DESIGN.md).

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

## Browser evidence

Run `npx playwright install chromium` once, then `npx tsx --test tests/dashboard.test.ts`. CI must install Chromium with its system dependencies. `HUB_CAPTURE_DASHBOARD=true npx tsx --test tests/dashboard.test.ts` additionally writes these screenshots:

- [Desktop, light theme](evidence/dashboard-desktop.png), actual isolated Fastify app and SQLite with an issued test client, after its token dialog has closed.
- [Phone, dark theme](evidence/dashboard-mobile.png), the same real backend with the shipped theme control and collapsed mobile directory.

The fixtures are explicitly browser-test records. Screenshots contain no password, session cookie, API/client token, TOTP secret or recovery code. The user's Docker Compose database is not used or claimed by these tests.

The actual backend browser test verifies claim and ten recovery-code records, login and reload, credential encryption, exact-IP upstream registration, server and tool approval, account-bound grants and profile clone, hashed client issuance, an exact-call approval record, retention persistence, encrypted backup creation/download, secret-free config download, config preview without writes followed by a persisted import, emergency stop, recovery-code replacement, password change and reauthentication, real TOTP enable/disable, and logout. Tool discovery uses an authenticated local HTTP MCP fixture. The actual browser-created approval is exercised through an SDK tool call, including missing-approval and replay rejection.

The contract-browser test additionally covers unavailable-server retry, escaped malicious upstream metadata, approved/current drift review, client token rotation, clipboard copy, generated-config copy, invalid allowlist input, upstream refresh/approval/disable, connection rename/secret replacement and revoke, OAuth handoff URL/scope disclosure, skill file preview/import/approval/delete, audit filtering and equal-timestamp cursor pagination, and the mobile menu. Each navigation destination and every refresh action is clicked. Both browser tests assert no uncaught page errors.

Click-through record:

| Control | Observed behavior |
| --- | --- |
| Claim, login, reload, logout | Creates one owner; displays recovery codes once; authenticated views survive reload using recovered CSRF; logout returns to login. |
| Refresh, retry, menu and navigation | Registry data reloads; controlled error retries successfully; all twelve navigation destinations open; phone Menu opens the directory and selecting a destination closes it. |
| Server and tool controls | Register honors exact local addresses; invalid CIDRs show validation; refresh calls discovery endpoint; approve/disable change policy; tool review submits risk and enable state; schema text remains escaped. |
| Account and profile controls | Secret is encrypted and absent from rendered registry; rename/replacement/revoke call their routes; grants retain stable connection ID; clone copies existing grants. |
| Client controls | Create/rotate displays a replacement only in a closable secret dialog; copy uses Clipboard API; generated config references an environment variable; revoke requires confirmation and cancel leaves it unchanged. |
| Approval and skill controls | Exact call approval persists; skill preview precedes import; stored file text can be inspected; approval and deletion require confirmation. |
| Owner security controls | Setup secret and URI open; real TOTP enables MFA; disable requires password plus another valid code; password change ends the session; recovery rotation reveals replacement codes. |
| Audit controls | Filters reload results; older-page request uses the opaque cursor, preserving events sharing a timestamp. |
| Backup and config controls | Step-up creates/downloads encrypted file; export downloads JSON without credential canary; reading a JSON file fills the preview; preview does not write; confirmed import creates the expected profile. |
| Theme and viewport controls | Real theme button changes both theme and label; 360, 768 and 1365px layouts hold in both themes for all twelve workspaces; 200% text size holds at 360px; keyboard Escape closes dialogs. |

## Accessibility and layout

Native labeled forms, buttons, links, details and dialog elements provide keyboard behavior and focus containment. Escape closes dialogs and the phone directory. Visible focus rings are provided in both themes; a skip link moves to the main workspace. All data views announce loading and errors; state labels carry meaning in text. Buttons, fields, navigation destinations and summary controls have at least 44px targets. Checkbox labels provide the full target area. JSON and machine identifiers wrap without causing page overflow.

The automated browser sweep checks all twelve workspaces at three widths and two themes (72 combinations), plus 200% text resizing at phone width. Screenshots were opened for visual inspection. Text pairing checks used the antislop contrast checker: normal/muted/danger/accent text passes 4.5:1 in both themes; field boundaries pass 3:1 (light weakest pairing 3.05:1, dark 3.56:1); focus colors exceed 3:1. Main text is 15.30:1 in light and 13.36:1 in dark. Text and button sizing use rem and fluid scales where appropriate.

A real mobile software keyboard, screen-reader session and installed agent applications were not exercised. External OAuth consent and provider credentials were not supplied. Those checks remain separate from local dashboard verification. Restore verification is explicitly not tracked by the dashboard; listed backup creation alone is never described as a tested restore. Audit account aliases are event-time snapshots; later account renames do not rewrite historical events. Profile/account IDs remain visible for exact filtering even when current records have changed.

## Antislop delivery gate

Direction is the authorized utility workspace in DESIGN.md, ENERGY 2 / RHYTHM 2 / MOTION 1. The gate below covers the local implementation and the recorded browser evidence; it does not claim external provider or client compatibility verification.

- R-02 PASS: authored UI copy has no em dash.
- R-03 PASS: 72 width/theme/workspace combinations and phone text resizing show no page overflow; screenshots visually inspected.
- R-17 PASS: inventory and records come from APIs; screenshots use explicitly identified isolated browser fixtures.
- R-18 PASS: no testimonials, invented people or profile photos.
- R-23 PASS: authorized text-only product identity; no generated assets.
- R-24 PASS: every navigation destination is implemented and clicked.
- R-25 PASS: computed text contrast exceeds AA and field/focus boundaries meet 3:1 in both themes.
- R-26 PASS: controls have actual routes, state changes or native disclosure behavior; click-through evidence above.
- R-27 PASS: empty descriptions, loading announcements, request errors and retry behavior exist; controlled failure exercised.
- R-28 PASS: no FAQ filler.
- R-32 PASS: native controls, skip link, visible focus, native modal focus and Escape dismissal; keyboard Escape exercised.
- R-33 PASS: theme and responsive behavior are authored directly in source, without CSS-rewriting runtime helpers.
- R-34 PASS: actual theme toggle, both-theme browser sweeps and contrast checks.
- R-35 PASS: actual backend and contract-browser suites run; click-through record, screenshots and uncaught-error checks retained.
- R-36 PASS: no compliance, performance or customer claims.
- R-37 PASS: design direction and dials recorded before UI source creation.
- R-38 PASS: no realistic-looking filler records in shipped source; actual API state or explanatory empty state.
- R-01 PASS: restrained amber/ink palette serves primary owner actions; no default gradients or glow.
- R-04 PASS: text labels provide meaning without a decorative icon library.
- R-06 PASS: local readable sans typography and machine-only monospace have written purposes.
- R-07 PASS: no decorative grid or patterned background.
- R-08 PASS: no decorative button arrows.
- R-09 PASS: rectangular labels convey real policy state; no marketing capsules.
- R-10 PASS: no glass surfaces.
- R-12 PASS: shadows mark the blocking dialog and transient feedback, not every registry row.
- R-13 PASS: no glow.
- R-14 PASS: workspaces use content-specific registry rows, policy forms, schema comparisons and audit lists.
- R-19 PASS: only interaction feedback; no loops or entrance choreography, with reduced-motion support.
- R-22 PASS: no unrelated illustrations.
- Liveliness PASS: balanced heading contrast, structural spacing, amber primary action and repeated namespace/fingerprint motif match the declared dials.
- C-1/C-2/C-3/C-4/C-5 PASS: written purposes, working routes, task-driven content, state/theme/viewport resilience and sourced records.
- R-05/R-11/R-15/R-16/R-20/R-21/R-29/R-30/R-31 PASS: purposeful utility composition, consistent small radii, concrete action labels, no marketing filler, working theme choice, constrained palette and documented major decisions.

## Profiles and tool access

A profile is an allowlist shared by the agent clients assigned to it. A grant allows one tool through its specific server account and reviewed risk classification. A profile with no grants exposes no tools. Write and delete tools still require a one-use approval for each call.

Use **Edit tool access**, check the tools a client needs, and choose **Save access**. Uncheck a tool to remove its grant. **Clear selection** removes every check; changes apply only after saving. Internal gateway identifiers remain available in Tool review details, while permission controls use the original tool names and descriptions.

A custom profile can be deleted. If clients use it, the confirmation requires a replacement profile and explains the immediate permission change. Client tokens remain valid and use the replacement profile; revoked clients remain revoked. Pending approvals are cleared, and the removed profile's grants are deleted without being copied into the replacement. The built-in Default profile cannot be deleted; clearing its access blocks all tools for its clients.

The browser regression uses 30 tools, including a long name and an unreviewed tool. It verifies modal boundaries and visible save controls at 1280px and 390px in both themes, search, grant removal, clearing all access, deleting unused profiles, and explicit client reassignment before deleting a bound profile.

## Setup without per-tool review

1. Register the MCP URLs and select account connections where needed.
2. In **MCP servers**, select multiple servers or **Select all servers**, then **Auto approve selected servers**. Confirm that you trust those servers to describe their current tools. Discovery and approval run as one batch with progress and per-server failure results.
3. In **Profiles & grants**, use **Default → Edit tool access**. Select whole server groups or **Select all available**, then **Save access**. Groups start collapsed for multiple servers, so a large registry does not present thousands of open rows.
4. In **Agent clients**, issue a token using Default and copy the client configuration.

Manual review remains available for a classification override. Its behavior choices describe view/search/list, create/edit/send/run, and deletion. **Enable tool** both saves the classification and enables profile selection; no separate enable checkbox is required. Manual review filters by server and search, rendering 50 tools at a time.

Getting started uses enabled, fingerprint-matched tools and valid grants, rather than treating discovery or the existence of a client as completed permission setup. Account connections are optional when the MCP server needs no credentials.

The scale browser test registers **50 MCP entries against one authenticated local MCP fixture**, discovers **50 tools each**, auto approves the **2500 tools** in one selected-server batch, saves 50 grants through one server checkbox and 2500 grants through Select all available, and lists 2500 tools through an actual SDK client. It also exercises rate-limit recovery during a burst of earlier owner operations. Evidence: [scale result](evidence/bulk-setup-scale.json), [desktop](evidence/bulk-access-1280.png), [mobile](evidence/bulk-access-390.png).
