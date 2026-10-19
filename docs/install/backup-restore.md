# Backup, restore and key rotation

Backups use SQLite's online backup API, then encrypt the entire snapshot with AES-256-GCM. HKDF derives a backup-specific key with random salt from the external 32-byte master key. A versioned manifest binds schema version, creation timestamp and plaintext SHA-256 as authenticated data. Credentials, sessions and metadata are inside the encrypted payload; the key is not bundled. Current database schema is v2. Restore accepts supported v1 backups; startup applies the v2 migration after restore.

The live SQLite database is not whole-database encrypted: vault fields are encrypted, while registry/audit metadata remains visible to filesystem readers. Protect the state volume and host backups. Use encrypted disks where the threat model requires it.

## Create and retain

Use Dashboard → Backups, re-enter the owner password and, when enabled, a fresh TOTP code. The API refuses missing or invalid step-up. For a local operator:

```sh
npm run cli -- backup
# Container equivalent:
docker compose exec hub node dist/cli.js backup
```

Backup files are `data/backups/backup-*.umcp` or `/data/backups/` in the container. Copy the resulting encrypted file to separately protected storage. Copying a live `hub.sqlite` file directly is not a substitute because committed records may reside in WAL.

Keep the matching master key in a separate protected password manager, hardware-backed store or encrypted offline recovery medium. Retain the previous key for every retained old backup after rotation. Do not put keys in Git, support bundles or the backup directory. No scheduler, remote backup upload or automatic retention deletion is included. Schedule the CLI using an operator-controlled job and verify its exit status; choose retention based on your recovery requirements.

Suggested pilot operating target: daily encrypted backups and a monthly fresh restore drill. These are operator targets, not measured RPO/RTO guarantees. Record backup age, restore duration, schema version, login and MCP-call results. Backup existence does not prove recoverability.

## Restore into fresh state

Stop any process that might use the destination. Keep the original state for investigation. Restore into an empty directory using the application version that created the backup:

```sh
npm run cli -- restore --file /safe/backup.umcp --target /new/state --key-file /secure/master.key --invalidate-clients
```

Wrong keys, tampered manifests/ciphertext, unsupported schemas, corrupt SQLite, active runtime leases, symlink targets and nonempty destinations fail. Restore takes the same exclusive operation lock used at application startup. It validates SQLite integrity before atomic installation of the database file.

Owner sessions and in-flight OAuth states are invalidated by default. `--invalidate-clients` also revokes all existing ordinary agent and management tokens; issue new tokens after recovery. `--keep-sessions` explicitly preserves sessions and OAuth state and is discouraged for incident recovery. An installation with a claimed owner stays claimed; restore never creates a new bootstrap path.

Point `HUB_DATA_DIR` at the restored directory and `HUB_MASTER_KEY_FILE` at its matching key. Start one process, log in using the existing owner, verify a connection and approved tool call, and confirm invalidated clients fail. Never restore over a running process or overwrite an existing state directory.

For Compose recovery, run a maintenance container from the same locally built image with a new empty volume at `/restore` and the original secret volume read-only. Keep the production `hub` stopped. Mount the encrypted archive read-only, then invoke `node dist/cli.js restore --file /archive/backup.umcp --target /restore --key-file /secrets/master.key --invalidate-clients`. The maintenance container must run as the volume owner (UID 1000) and have an empty writable destination. After validation, update the Compose state-volume mapping to the new volume and start the app. Retain the original volume until the drill is accepted.

## Rotate the external key offline

Stop the application first. Generate a distinct raw 32-byte new key in protected storage. For a source installation with writable external key files:

```sh
umask 077
node -e "require('fs').writeFileSync('/secure/new-master.key',require('crypto').randomBytes(32),{mode:384,flag:'wx'})"
npm run cli -- rotate-key --new-key-file /secure/new-master.key
```

Rotation re-encrypts connection credentials, owner TOTP, OAuth PKCE verifiers, session CSRF values and the vault key-check sentinel using their original AAD bindings. It stages and checks a new database before replacing the database and external key with individual atomic renames. A durable `rotation.pending.json` journal makes startup fail closed during an interrupted two-file transition. The filesystem cannot atomically replace two files on separate mounts.

The command retains an old encrypted DB under the data directory and old/new keys in a mode-0700 sibling recovery directory outside state. Preserve these until a new-key backup/restore drill passes, then retire them according to your secure deletion/storage policy. Returned paths contain no key values. Old backups still require the old key.

If interrupted:

```sh
# Keep the app stopped. This rolls both resources back to the retained old pair.
npm run cli -- rotate-key --recover
```

Recovery restores the original DB and key, synchronizes the directories, and removes the journal. Runtime and maintenance exclusion use kernel-backed SQLite leases on the same local filesystem. Leases release on process crash, including when containers reuse PID 1; `runtime.lock` is diagnostic only. Do not delete or replace the lease files while any process may be active. Unsupported/network filesystems require a separate locking validation.

A mounted Kubernetes Secret is read-only and cannot be replaced by this command. Rotate in an offline writable staging environment, validate the result, then replace both the PVC state and Secret while the deployment is scaled to zero. This cluster procedure requires a separate rehearsal and is not automated by the chart. Compose also mounts secrets read-only in the running app; use an offline maintenance mount with write access to secrets, not `exec hub rotate-key`.

## Download an encrypted backup from the dashboard

Each listed backup has a download action. Re-enter the owner password and a fresh TOTP when enabled; the browser POSTs to `/api/v1/backups/<name>/download` with its session and CSRF header. The response streams an `application/octet-stream` attachment. It remains encrypted and does not include the master key. Downloading is a separate step-up action, so an already used TOTP may require waiting for a new code. The API accepts only generated backup basenames and opens without following symlinks.

## Move configuration without moving credentials

Dashboard export uses config format **2**, containing profiles, public provider configuration/scopes, upstream registry, full tool metadata, grants and skill file maps/digests. It excludes owner authentication, sessions, bearer tokens and vault credential ciphertext. Client tokens must be created afresh on the target. Exported metadata and skill files can still be private; handle the JSON accordingly.

Preview the file in the target dashboard, then explicitly import with password/MFA step-up. The API is `POST /api/v1/config/import` with `{password,totp?,config}`. Import is a single SQLite transaction: invalid references, unsafe targets, mismatched account/risk grants, duplicate IDs or existing alias/slug/tool-name collisions roll back every change. Existing owner, sessions and client tokens are untouched.

Stable imported IDs are retained. An imported default profile becomes a new nondefault profile with deterministic slug `imported-default-<UUID>`; the target's default profile and its grants remain unchanged. Re-importing the same IDs is rejected rather than silently merging or updating them. Edit deliberate conflicts in a reviewed copy or import into a different instance.

Imported connections have no credentials and status `not_configured`. Upstreams become registered with rediscovery required; tools are disabled with no approved fingerprint, and skills require fresh approval. Reauthorize connections, refresh discovery, inspect the new metadata and approve the upstream/tools before issuing clients or enabling access. Native provider URLs must bind exactly to their matching provider and connection. Remote URLs are checked statically without DNS or provider calls during import; normal discovery/call validation resolves and pins destinations before network access.

Format 1 from earlier development snapshots is not importable; regenerate an export from this candidate. Current import limits are 900 KiB, 100 profiles/connections/upstreams/skills, 256 tools and 2,000 grants, with bounded depth, text lengths and skill file maps. These resource limits are not licensing limits. Full encrypted backup/restore is the path for moving a complete instance with its original credentials and separately retained key.
