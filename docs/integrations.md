# Provider and remote-server connections

The dashboard stores multiple accounts under stable connection IDs and unique aliases. Renaming an alias does not change profile bindings. Owner sessions and agent tokens are independent from provider credentials. Every new server and tool requires review before any profile can expose it.

## Generic remote MCP

Register an HTTPS Streamable HTTP endpoint under MCP Servers. Choose an independent bearer-token or API-key connection when required. An API-key connection needs an explicit header name; reserved HTTP, cookie, proxy, and MCP headers are refused. The gateway never forwards its inbound agent token. Credential `allowed_origin` can further restrict the destination origin.

Private endpoints require an owner-approved list of exact IP addresses. Public DNS names are resolved and validated again for each outgoing request; the socket uses the validated address. Redirects are rejected. Cloud metadata addresses remain blocked even when a private exception is supplied. HTTP is permitted only for explicitly approved private/local destinations. Do not broadly allow private networks to work around a failed connection.

The gateway bounds request/response size, schema complexity, connection count, tool count, invocation time, stream events, and audit retention. These are resource protections, not license limits. Current limits and supported MCP revisions are recorded in [gateway compatibility](compatibility/gateway.md). Tool output is untrusted data; it cannot modify policies or execute hub code.

## GitHub

Create a connection with provider `github`. For browser authorization, configure a BYO OAuth or GitHub App client ID in `config.client_id` and supply its client secret through the secret field. Register the exact callback `http://127.0.0.1:8080/oauth/callback/github` for the default local deployment, or the configured HTTPS origin for public mode. Start OAuth from the connection row. The flow uses S256 PKCE and a one-use, session-bound state. An app still controls its own repository permissions and installation grants.

For a manually issued fine-grained token, omit `config.client_id` and supply the token as the connection secret. Select only the repositories and permissions needed. A manually supplied token is not evidence that its external identity has been verified through OAuth.

The native server provides repository listing, issue listing, file reads, issue creation and issue comments. Writes require an explicit profile grant plus a one-use approval bound to the client, tool, and exact arguments. Repository permissions remain enforced by GitHub. The authorization flow follows [GitHub's OAuth documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps); PKCE is supported for [OAuth and GitHub Apps](https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/).

## Google Calendar and Drive

Use provider `google`, configure a BYO OAuth client ID/secret, and register the exact `/oauth/callback/google` URI. Select the required Calendar/Drive scopes before consent. The hub adds `openid` for authenticated identity binding. It verifies the ID-token signature, issuer, audience, nonce, and subject against UserInfo, following [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).

The native server provides calendar listing, event listing/creation, Drive metadata listing/reads, and Google Workspace document text export. Start with the narrowest scopes that support the task. `drive.file` does not mean access to all files. Broad Drive scopes require an explicit informed acknowledgment in the connection config; this does not waive [Google's restricted-scope requirements](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification). The hub does not claim verified broad-scope approval.

Refresh tokens stay encrypted. Parallel refreshes share one operation per connection. Revocation or credential replacement during a refresh wins; a stale network response cannot reinstall old credentials. A provider denial requires reauthorization rather than fallback to another account.

## Slack

Use provider `slack`, configure the BYO app ID/secret and `/oauth/callback/slack`, and enable PKCE in the Slack app. Configure only the channel/history/posting scopes needed. The native server lists conversations, reads selected channel history and posts approved messages. Each workspace grant has a separate connection and alias; the hub does not silently switch workspaces.

Slack PKCE requires the app setting described in [Using PKCE](https://docs.slack.dev/authentication/using-pkce/). The flow uses [OAuth v2](https://docs.slack.dev/authentication/installing-with-oauth/). A provider token can still lack access to a channel, and provider rate limits still apply.

## Review and reauthorization

OAuth creates a registered native upstream. Refresh its catalog, inspect each tool's schema and risk, approve the server/tools, then add exact account-bound profile grants. Upstream `readOnlyHint` is advisory; only the owner's stored risk classification controls authorization. Changed tool descriptions, schemas, annotations or server version quarantine the changed tools until review.

Public mode requires local owner setup and MFA enrollment before startup with HTTPS/trusted-proxy configuration. Local HTTP owner cookies use HttpOnly and SameSite=Lax so a top-level OAuth callback can retain the session; public mode adds Secure. All browser mutations still require the session-bound CSRF header. Callback state is bound to the current owner session and current flow, so logout, password changes, a newer flow, and local revocation invalidate pending exchanges.

Provider consent, app verification, actual live scopes, vendor quotas and external token revocation need provider-specific tests with an owner's configured app. Local contract tests use deterministic provider fakes and do not establish production provider approval.
