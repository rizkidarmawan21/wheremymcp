# Security policy

This checkout is a development candidate. No externally reviewed stable release or support SLA exists yet. Use the newest reviewed candidate, read the known limitations, and validate recovery before public exposure.

## Private vulnerability reports

Use the repository's **Security → Advisories → Report a vulnerability** private reporting feature when the repository owner enables it. Include affected source revision, reproduction steps, expected/actual behavior and redacted logs. Do not include live credentials, client tokens, recovery codes, key files or customer content.

If private reporting is unavailable, do not open a public issue containing an exploit or secrets. Contact the repository owner through an already established private channel and ask for a secure reporting path. No unverified email address or invented disclosure service is provided. Enabling a documented private reporting channel is a public-release prerequisite.

The maintainer should acknowledge privately, reproduce on an identified revision, assess impact, patch and add a regression test, prepare an advisory with affected/fixed versions, and coordinate publication. Response/patch timings are not promised until maintainers establish a support policy. Urgent fixes must use the same checks, signed candidate/release process and restore-safe migration review as ordinary releases; no unattended update bypass exists.

## Security boundaries

One owner and one DB per instance. Separate owner sessions and hashed client bearer tokens. Vault fields use authenticated encryption; encrypted backups require a separately retained master key. Registry and audit metadata in live SQLite are readable to filesystem administrators. Upstream metadata and skill files remain untrusted.

Arbitrary stdio packages, shell hooks, skill execution, remote install scripts, multi-tenant billing and cross-instance operator access are outside the application. Tool-output prompt injection cannot be solved solely by a gateway; agents and owners must review tool descriptions, grants and results.

See [public deployment](docs/security/public-deployment.md), [backup/restore](docs/install/backup-restore.md), and [compatibility](docs/compatibility/operations.md). Application tests, scanners and chart rendering complement an independent review; none establishes complete security by itself.
