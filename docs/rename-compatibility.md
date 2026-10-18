# WhereMyMCP rename compatibility

The product and repository are now WhereMyMCP and `wheremymcp`. The previous product name was UnifyMCP. This changes presentation and deployment defaults while retaining existing stored data and client authentication.

## Existing Docker installations

Compose project names determine the default named-volume names. An installation originally created as `unifymcp` uses `unifymcp_state` and `unifymcp_secrets`. Starting it under a different project name would select different volumes.

Keep the original project name in a local, uncommitted `.env` file:

```dotenv
COMPOSE_PROJECT_NAME=unifymcp
```

If the installation used a custom project name, keep that name instead. The current local installation retains its existing project and volumes through this setting. New installations default to `wheremymcp`.

For an initialized installation, build the new image and replace only the application:

```sh
docker compose build init
docker compose up -d --no-deps --wait --wait-timeout 30 hub
```

The application image is now `wheremymcp:local`. The Helm chart lives at `deploy/helm/wheremymcp`. Existing Kubernetes releases and PVCs require their normal upgrade review; no cluster migration is claimed here.

## Preserved formats

- Existing client bearer tokens keep working. The opaque `umcp_` prefix remains supported and issuance retains the same format.
- Vault key derivation, key verification markers and encrypted backup key derivation retain their original identifiers. Existing ciphertext does not need to be rewritten.
- Encrypted backup files retain the `.umcp` extension and existing file format.
- Skill sync retains `.unifymcp-backups` and recovery file naming for compatibility with existing plans and files.
- Existing TOTP secrets and recovery codes retain their values. New authenticator enrollments display WhereMyMCP; issuer display text does not change the TOTP algorithm.
- The dashboard reads the previous `unifymcp-theme` preference as a fallback and writes future selections to `wheremymcp-theme`.

## Agent configuration

New generated configurations use the server label `wheremymcp` and environment variable `WHEREMYMCP_TOKEN`. Existing client configurations with another server label or token environment variable continue to work because the gateway authenticates the token value, not the client's local variable name.

New write/delete approvals use `_meta.wheremymcp_approval_id`. The gateway also accepts `_meta.unifymcp_approval_id` for existing integrations. Both names use the same argument-bound, one-use approval check.

## Verification

Compatibility checks open a database and restore an encrypted backup created before the rename, decrypt a test connection and authenticate an existing client token. Browser tests exercise new configuration names; existing gateway tests continue to exercise the legacy approval metadata key. A disposable Compose project checks the new image and fresh-install defaults separately from the owner's retained volumes.
