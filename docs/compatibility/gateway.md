# Gateway compatibility and verification

Verified locally on 18 October 2026 with Node.js 22.18.0, official `@modelcontextprotocol/server` and `@modelcontextprotocol/client` 2.3.1, Fastify 5.12.7 and Undici 7.30.1.

## Protocol evidence

| Interface | Implementation | Local evidence |
| --- | --- | --- |
| Modern Streamable HTTP | Official `createMcpHandler`, client negotiation `auto` | Real HTTP SDK client negotiates `2026-07-28`, modern era; tool listing and calls pass |
| Legacy Streamable HTTP | Official stateless legacy fallback | Real HTTP SDK client negotiates `2025-11-25`, legacy era; policy-filtered listing passes |
| Remote upstream transport | Official SDK `Client` + `StreamableHTTPClientTransport`, modern probe then SDK legacy fallback | Real local fake remote server discovery and calls pass |
| Native provider adapter | Root-owned `nativeTools(connectionId)` and `nativeCall(connectionId,name,args,signal)` | Fake native GitHub adapter passes the same gateway policy and approval flow |
| Product clients | Codex, Claude, Cursor, Gemini configurations are produced by root | Installed product-client sessions have not been exercised; no product-version compatibility claim |

The gateway is stateless. Clients must relist after catalog or policy changes. List results use private cache hints with zero TTL; every call checks current authorization independently. Tools are paginated in batches of 64. GET/DELETE sessions, resumable streams, subscriptions, server-initiated sampling/elicitation, legacy HTTP+SSE transport, prompts and resources are not exposed. Prompts/resources require their own explicit permissions before support can be enabled. Stdio execution remains disabled.

## Owner lifecycle and enforcement

New remote upstreams start in `pending_review`. Discovery caches metadata; upstream approval and separate owner tool classification/enabling are required. `readOnlyHint` never grants authority. Root may create `native://` records internally, but manual URL registration accepts HTTP(S) only.

Gateway names combine the immutable upstream UUID with the SHA-256 digest of the original tool name. Identically named tools from separate servers remain distinct. Fingerprints include all discovered tool metadata and upstream implementation version. Any fingerprint change disables the tool. Previously approved description, input schema, annotations and fingerprint remain available as `previous_metadata` for review. Removed tools are disabled and lose their approved fingerprint.

Both listing and invocation enforce the current client, profile, exact tool/account/action grant, connection status/lifetime, upstream status, tool approval, metadata fingerprint and emergency stop. An invocation also retains its original tool fingerprint/risk so an owner policy change during connection setup cannot substitute a different tool classification. In-flight policy checks run every 50 ms, and output is checked again before delivery.

Writes and deletes require an owner-created approval bound to client ID, tool ID and canonical argument hash. The approval expires within 300 seconds, is atomically consumed immediately before dispatch and cannot be reused. A timed-out or cancelled call can already have changed the remote provider. The gateway never retries calls; uncertain writes quarantine the upstream for owner review. Three failed read calls open the circuit. Owner refresh and approval restore an errored upstream.

## Limits and outbound network policy

- At most 32 registered upstreams, 8 concurrent discovery/call operations globally and 1 per upstream. Excess calls fail immediately instead of entering an unbounded queue.
- Discovery accepts at most 8 pages and 256 tools per upstream. Metadata is bounded, names are validated and unsafe schema regex patterns or `patternProperties` are rejected. Input schemas use AJV with no remote schema loading.
- Agent arguments are bounded to 64 KiB and depth 24. Responses are bounded to 1 MiB. Upstream deadlines range from 100 ms to 60 seconds; DNS resolution is bounded to 5 seconds. Streams are buffered within the byte/deadline limit, with a 2,048-event cap.
- DNS answers are validated before connecting. Any forbidden answer rejects the destination; Undici socket DNS lookup is pinned to a validated address, preventing a second hostname resolution from rebinding the connection. HTTPS certificates still validate against the original hostname.
- Public destinations require HTTPS. Private, loopback, link-local, multicast, reserved IPv4 and non-global IPv6 destinations are denied by default, including IPv4-mapped IPv6 representations. An owner may allow at most 16 exact private IPs; CIDRs and broad network flags are rejected. AWS/Google IPv6 metadata addresses, Alibaba metadata IPv4 and all IPv4 link-local addresses remain forbidden despite overrides.
- URL credentials, fragments and target query strings are forbidden. Provider adapters may explicitly set `safeFetch(..., {allowQuery:true})` in the third policy argument for fixed provider API URLs. Manual remote MCP URLs remain query-free.
- Redirects are rejected without following them. Cookies, proxy authorization and caller-supplied Host are removed. Gateway bearer tokens are never copied into outbound requests. Remote credentials are decrypted by connection UUID; optional root credential resolution supports OAuth refresh. Credential origin bindings are enforced.
- MCP errors and audit events use controlled codes. Audit stores identifiers/outcomes/timing without arguments, outputs or upstream exception text. Known upstream and incoming client secrets are redacted from returned text. Arbitrary provider content remains untrusted; this is not general-purpose semantic DLP.

## Acceptance evidence

`npx tsx --test tests/gateway.test.ts tests/network.test.ts` passes 10 tests:

1. Real modern and legacy negotiation, colliding tool names, deny-default listing, schema validation, live grant removal and metadata drift quarantine.
2. One-use argument-bound write approval and strict upstream credential separation.
3. Concurrent overload, in-flight emergency cancellation and no repeated write dispatch.
4. Output bounds, credential redaction, owner/Origin guards and unsafe schema rejection.
5. Native provider adapters under the same account, approval and revocation policy.
6. Private/metadata/mapped-IPv6 address denial and exact local exceptions.
7. Real local HTTP, redirect refusal, body limits, deadlines and explicit provider query opt-in.
8. Repeated socket lookups remain pinned to the validated address even when the requested hostname changes.
9. Imported upstreams remain blocked from approval, listing and calls until successful live rediscovery clears the import marker.
10. Production Hub schema, encrypted vault, real client-token authentication and persisted audit events through an actual SDK gateway call. This regression initially reproduced the core audit SQL placeholder mismatch; the core fix is now verified.

The initial tests failed with missing gateway/network modules before implementation. Tests use a real local SDK upstream with an explicit `127.0.0.1` exception; no external service credentials or mutations are involved.

These tests do not establish a malicious authoritative-DNS deployment drill, production egress firewall enforcement, external provider consent, installed product-client interoperability, load/SLO compliance or an independent security review. Those remain release gates.


## Generic OAuth-protected remote MCP

`RemoteOAuthManager` supports owner-configured `remote_oauth` connections with a BYO client ID and optional encrypted client secret. Public config contains fixed HTTPS `issuer`, `resource`, and exact `allowed_origin`; the resource origin must match that origin. Callback URI is `<hub-origin>/oauth/callback/remote_oauth`. Dynamic client registration is disabled.

RFC 8414 discovery is bounded and requires exact issuer equality and S256 PKCE. Authorization, token, JWKS and optional revocation endpoints must share the configured issuer origin, with HTTPS and no URL credentials, query or fragment. This conservative restriction intentionally excludes authorization servers distributing endpoints across different origins. Supported token endpoint client authentication is `client_secret_basic`, `client_secret_post`, or `none` for a registered public client advertising it.

Authorization and token/refresh requests carry the exact resource indicator. State is single-use, encrypted and bound to the connection, owner session, client ID, resource, issuer, config/ciphertext snapshot and per-flow generation. Completion rechecks live owner-session validity, state lifetime and the current flow/connection before storing tokens. Logout, secret rotation, revoke and newer authorization flows prevent stale completion.

Signed compact JWT access tokens require issuer JWKS and are cryptographically verified for signature, exact issuer, resource audience and expiration; no unverified claims authorize a connection. A three-part token without usable JWKS fails closed. Opaque tokens retain an encrypted issuer/resource/client binding and rely on resource-bound authorization-server issuance plus the remote MCP server's token enforcement; the hub does not invent claims or introspection results. JWE access tokens are treated as opaque. A token response explicitly naming a different resource is rejected.

Refresh is serialized per connection, includes the resource indicator, rechecks connection/config/ciphertext before exchange and commit, and cannot overwrite local revocation. Local revoke clears credentials, state and pending approvals before any provider network call; decryption/network failures do not block that local action. Provider revocation returns a separate `succeeded`, `failed` or `not_supported` outcome.

`npx tsx --test tests/remote-oauth.test.ts` passes 8 fake-fetch contract tests covering PKCE/resource binding, issuer/endpoints/S256 rejection, session/state replay, superseded flows, logout during exchange, serialized refresh versus revoke, signed JWT audience rejection and valid signature acceptance, configuration drift, and local revoke despite unreadable credentials. External authorization-server consent remains unverified.
