# Contributing

WhereMyMCP is licensed under the [MIT License](LICENSE). Contributions are accepted under the same license. Package metadata retains `private: true` to prevent accidental npm publication; official package and image releases remain separate maintainer actions.

Use Node.js 22+, `npm ci`, and the existing TypeScript/Fastify/SQLite architecture. Keep changes proportional, preserve one-owner policy and deny-by-default authorization, and avoid unrelated refactors. New external dependencies need a concrete reason. Do not add arbitrary command execution, telemetry or hidden provider access.

For behavior changes, add a regression/acceptance test, observe the failure, implement the smallest change, then run:

```sh
npm test
npm run typecheck
npm run build
npm audit --audit-level=high
docker compose config --quiet
```

Container and cluster changes also need source-built image smoke, Helm lint/template and an actual deployment check when that runtime is available. Tests must not contact live providers or require real credentials. Keep secrets, database files and private backup artifacts outside commits and build context. Comments, commits, PRs and client documents use plain English.

Optional browser screenshots can be generated with `HUB_CAPTURE_DASHBOARD=true npm test`. They are saved in the ignored `docs/evidence/` directory. Generated screenshots, test logs, internal plans and audit reports stay local; do not commit them as product documentation.

Explain the user-visible trigger/result, validation evidence and remaining limitations in the PR. Security-sensitive reports follow `SECURITY.md`; do not publish an uncoordinated exploit in an issue. Do not claim published signatures, multiarchitecture runtime compatibility, provider approval or client compatibility from workflow/source files alone.
