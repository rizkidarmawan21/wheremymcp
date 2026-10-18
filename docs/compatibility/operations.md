# Operations compatibility and evidence

| Surface | Implemented behavior | Evidence / limitation |
| --- | --- | --- |
| Node | Node.js 22.19.0+ TypeScript app and CLI | Local Node 22 tests; other runtimes require a fresh run |
| SQLite | Single writer, WAL, online backup, schema 2 | Backup/restore negative tests; network filesystems unsupported |
| Backup format | `.umcp` JSON envelope version 1, AES-256-GCM | Whole-file canary absence, wrong key and tampered-manifest rejection |
| Restore | Empty directory only; sessions revoked by default; optional client revocation | Local fresh-directory drill; operator must retain matching key |
| Config portability | Format 2; owner step-up; atomic metadata import; no credentials/client tokens | Roundtrip, collision rollback, unsafe URL/native binding/account-risk tests; reauthorization and fresh review required |
| Backup download | Owner + password/MFA step-up; encrypted binary stream | File equality and auth/path/symlink negative tests |
| Key rotation | Offline credential/TOTP/PKCE/CSRF re-encryption; journal rollback | Local old/new key/context checks; no atomic cross-mount pair swap |
| Docker Compose | Local source build; init and nonroot app; separate volumes | Manifest validation; runtime proof must be recorded for the exact build |
| Helm | One replica, retained PVC, Secret, probes, restricted security context, NetworkPolicy, optional TLS ingress | Helm lint/template configured in CI; local Helm and live cluster validation unverified |
| Generic skill folder | File-map import → reviewed digest → absolute-root preview → explicit apply | Traversal, symlink, stale-preview and backup tests |
| Codex / Claude / Cursor skill discovery | No automatic client-directory adapter | Operator selects an existing absolute skill directory and checks that client's documented layout/version |
| Hooks / package install / stdio | Not executed | Files are copied as text only; no shell execution, dependencies or permission inheritance |
| Release | Checksums, SBOM, Sigstore/provenance workflow source | MIT source license; no existing signed image/release claimed; `private: true` blocks artifact publication |
| OAuth providers | Connection data backed up and rotated | Actual provider consent/refresh/revoke and vendor policy need live tests |

Skill import is manual; no automatic git clone, remote URL fetching, update tracking or publisher verification is included. `source` is owner-supplied provenance, not an attestation. Each approved version is immutable through the API, pinned by a canonical file-map digest and per-file SHA-256. Changed content requires a new import and approval.

CLI example after dashboard import and approval:

```sh
npm run cli -- skills plan --id SKILL_UUID --target /absolute/existing/client/skill-directory --out /safe/review-plan.json
# Read the saved file and review every before/after value first.
npm run cli -- skills sync --plan /safe/review-plan.json --apply
```

The plan contains file content and must be kept private when the imported files contain private material. Apply recomputes approved content and current target files; a changed digest or stale preview fails. Existing originals are copied into `.unifymcp-backups/<unique-id>/` before overwrite. Sync never deletes extra files or follows target symlinks. Each update uses an exclusive temporary file and atomic rename, so existing hardlinks cannot redirect writes to an external inode. Use a trusted target directory without concurrent hostile local writers: filesystem ancestor swaps are outside the protection Node's path-based APIs can guarantee. A failed partial sync may leave some files applied; retain the backups, resolve the cause, regenerate and review a new plan.

Default folder sync copies reviewed text files without choosing a client-specific parent directory. Automatic compatibility across every agent client is not claimed. MCP transport compatibility is tracked separately by the gateway's tested protocol/client matrix.
