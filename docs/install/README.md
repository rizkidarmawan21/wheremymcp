# Installation and updates

Run one process, one owner and one SQLite database per installation. Use a local filesystem that supports SQLite locking; network filesystems and multiple replicas are unsupported. No managed hosting or billing service is included.

## Docker Compose

From the app checkout:

```sh
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:8080/health/ready
```

The `init` service exits after preparing `state` and `secrets` named volumes. The app runs as UID/GID 1000 with its secret volume read-only. Port 8080 binds to `127.0.0.1`; remote access needs an explicit reverse proxy or SSH tunnel.

Read the setup token without copying the master key:

```sh
docker compose exec hub node -e "process.stdout.write(require('fs').readFileSync('/secrets/bootstrap.token','utf8'))"
```

Open the exact origin `http://127.0.0.1:8080`, claim the owner within 30 minutes, save recovery codes, and log in. `localhost` is a different origin. Default `HUB_ORIGIN` deliberately uses `127.0.0.1`.

Expired setup token, before owner claim:

```sh
docker compose stop hub
docker compose run --rm --entrypoint node init dist/cli.js bootstrap-reset
docker compose up -d hub
```

Then read the new token using the command above. A claimed installation rejects bootstrap reset. `docker compose down` preserves named volumes; `down -v` destroys them and must not be part of an update.

The init service refuses a running instance. Before rebuilding or recreating an existing stack, stop `hub` first. This protects offline maintenance from a competing process.

## Source install

Use Node.js 22.19.0+, npm, and a native-build toolchain when needed. Keep key files outside the state directory:

```sh
npm ci
npm run build
export HUB_DATA_DIR="$PWD/.local/state"
export HUB_MASTER_KEY_FILE="$PWD/.local/secrets/master.key"
export HUB_BOOTSTRAP_TOKEN_FILE="$PWD/.local/secrets/bootstrap.token"
npm run cli -- init
cat "$HUB_BOOTSTRAP_TOKEN_FILE"
npm start
```

Initialization creates a raw 32-byte key and a random token using exclusive mode-0600 file creation. Existing keys are preserved. Keep `.local/` outside version control; never include secret files in bug reports. For production, use a protected service environment and dedicated persistent directories rather than a checkout.

Default bind is loopback. Relevant environment variables are `HUB_HOST`, `HUB_PORT`, `HUB_ORIGIN`, `HUB_DATA_DIR`, `HUB_MASTER_KEY_FILE`, `HUB_BOOTSTRAP_TOKEN_FILE`, `HUB_PUBLIC_MODE` and comma-separated IPs in `HUB_TRUSTED_PROXIES`. `HUB_CONTAINER_MODE=true` permits container binding but does not enable public access or skip origin checks.

## Kubernetes

The chart at `deploy/helm/wheremymcp` enforces one replica with `Recreate`, a retained ReadWriteOnce PVC, nonroot security context, read-only rootfs, no service-account token and explicit secret injection. It does not create or publish a release image.

Create a raw key and setup token outside source control, then inject them into the target namespace:

```sh
umask 077
mkdir -p /secure/wheremymcp
node -e "require('fs').writeFileSync('/secure/wheremymcp/master.key',require('crypto').randomBytes(32),{mode:384,flag:'wx'})"
node -e "require('fs').writeFileSync('/secure/wheremymcp/bootstrap.token',require('crypto').randomBytes(32).toString('base64url')+'\n',{mode:384,flag:'wx'})"
kubectl create secret generic wheremymcp-secrets --from-file=/secure/wheremymcp/master.key --from-file=/secure/wheremymcp/bootstrap.token
helm lint deploy/helm/wheremymcp --set existingSecret=wheremymcp-secrets
helm upgrade --install wheremymcp deploy/helm/wheremymcp --set existingSecret=wheremymcp-secrets --set image.repository=YOUR_REGISTRY/wheremymcp --set image.digest=sha256:YOUR_VERIFIED_DIGEST
```

The Secret must be accessible to group 1000 through the pod's `fsGroup`; verify this with your CSI driver. The storage class must honor ownership and SQLite locks. No privileged init container repairs incompatible PVC permissions. Create the token immediately before first installation because its TTL is based on the mounted file timestamp.

By default NetworkPolicy permits DNS only, plus ingress from the `ingress-nginx` namespace. Configure the actual namespace/pod selectors, explicit upstream or egress-proxy CIDRs, and required ports. CIDRs use destination IPs, so changing SaaS IP ranges need operator updates; prefer a controlled egress proxy when appropriate. NodeLocal DNS and nonstandard DNS labels require adjusted selectors. A CNI that ignores NetworkPolicy leaves traffic unrestricted. Cluster install, packet isolation and storage behavior remain external verification gates.

Without ingress, use `kubectl port-forward service/wheremymcp 8080:8080` for the default local origin. Complete owner claim and MFA through the local port-forward before enabling public mode. Public startup refuses unclaimed or MFA-disabled state. Public ingress requires `publicMode=true`, an HTTPS origin, exact trusted proxy IPs, host and TLS Secret. Controller IP changes require explicit configuration changes; do not trust broad CIDRs to avoid maintaining them.

## Upgrade and rollback

1. Record current source revision/image digest, schema version and config. Create an encrypted backup and test a fresh restore with the separately retained key.
2. Stop the app. Keep both named volumes/PVC and external keys. Review migration and release notes.
3. Build or load the reviewed candidate, run checks, then recreate one app process. Confirm readiness, owner login, approved MCP call and revoked-client denial.
4. If rollback is needed, stop the candidate and restore the pre-upgrade backup into a fresh data directory with the matching old key and application version. Change the volume mapping only after the restore drill passes.

Downgrades over a newer database are unsupported. Current schema version is 2. Startup applies ordered migrations transactionally and stores a mode-0600 pre-migration SQLite copy beside the database before changing an existing database. Restore accepts supported older backup schemas; startup migrates them. Health alone does not prove auth, upstream connectivity or data continuity.

For air-gapped operation, preload an image built for the target architecture and copy dependencies/build artifacts through your approved process. OAuth and remote upstreams need reachable providers; no offline provider capability is implied.
