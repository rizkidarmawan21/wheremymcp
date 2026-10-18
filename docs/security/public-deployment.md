# Public deployment boundary

Local Compose publishes only `127.0.0.1:8080`. Keep that default until owner setup, recovery-code storage, MFA enrollment and a backup/restore drill are complete.

Public mode requires `HUB_PUBLIC_MODE=true`, one exact HTTPS `HUB_ORIGIN`, and explicit comma-separated IP addresses in `HUB_TRUSTED_PROXIES`. The application validates public access and requires owner MFA. Enroll MFA through the dashboard before switching an existing local instance to public mode. Startup refuses public mode for an unclaimed owner or an owner without enabled MFA. Bootstrap and enroll locally first, then stop the app and switch configuration.

Terminate TLS at a maintained reverse proxy; `deploy/Caddyfile.example` shows the routing shape and uses an intentionally invalid hostname. Preserve the actual Host, set forwarded protocol to HTTPS, and overwrite client-supplied forwarding headers. Trust the proxy's observed source IP, not arbitrary Internet headers. Do not set trusted proxy addresses to every client or an entire cluster as a convenience. Origin checks and MFA do not replace firewall rules or TLS.

For same-host Caddy, retain loopback publishing. With a containerized proxy, explicitly control the shared network and verify the proxy IP seen by the app; a broad interface bind must not become a public cleartext bypass. Kubernetes ingress requires TLS, a matching origin and exact controller IPs. NetworkPolicy must restrict ingress to the controller namespace and egress to DNS plus approved upstream/proxy destinations. Verify packet drops with your actual CNI; rendering YAML is not proof of isolation.

Compose limits CPU, memory, PIDs, open files and log rotation. Its bridge network allows outbound traffic, subject to application SSRF checks. For a public deployment, add an enforcing host/container firewall or controlled egress proxy. Application URL validation does not provide host-level network isolation.

Keep state and secrets off shared untrusted mounts, protect container/host administration, avoid the Docker socket, and monitor disk capacity, backup age, readiness and authentication failures. No remote administration agent or telemetry service is installed. Container separation does not provide VM-grade isolation.

Before an Internet-facing release: independent focused security review, live TLS/proxy/MFA tests, provider consent review, client-version interop, signed release verification, container scanning and a fresh restore drill remain required external gates. A local green test suite is not public-production approval.
