# Release evidence and verification

The repository contains workflow source, not a published release. `candidate-release` is manually dispatched and checks package version, the supplied immutable Node base-image digest, tests, typecheck, build and dependency audit. It produces a source archive, CycloneDX dependency SBOM, SHA-256 checksums, a Sigstore checksum bundle and GitHub build-provenance attestation. Workflow runs and actual downloadable artifacts must be inspected before claiming any of these exist.

Source code is distributed under the MIT License. OCI publishing additionally requires an explicit workflow input and removal of the package publication safeguard: the current `private: true` deliberately blocks that workflow path. Once maintainers enable artifact publication, the workflow can build linux/amd64 and linux/arm64 images, publish BuildKit SBOM/provenance, sign the immutable digest using keyless Sigstore, and attest the registry subject. A successful cross-build does not demonstrate both architectures run correctly; record an independent smoke on each target.

Before accepting a release:

1. Resolve the source revision, workflow identity, version and immutable image digest through an authenticated release channel.
2. Verify `SHA256SUMS` against the downloaded source archive and SBOM. Verify the Sigstore bundle against the expected repository workflow identity and GitHub Actions OIDC issuer, never a wildcard identity accepted from the artifact itself.
3. Verify GitHub provenance and that the source revision and workflow match the reviewed release.
4. For an OCI image, use `cosign verify` with the immutable `registry/image@sha256:...`, expected certificate identity and `https://token.actions.githubusercontent.com` issuer. Inspect the SBOM and provenance attached to that digest.
5. Run the candidate's source checks, vulnerability/container scans, auth and MCP smoke, and a fresh backup restore. Record remaining findings and owner acceptance; independent security review remains a public-release gate.

CI includes dependency, secret, static and container scans. GitHub Actions use immutable commit references; scanner container tags remain version-tagged and require release-time review. Semgrep rules are a narrow local policy gate; CodeQL is a separate workflow and may require repository security features/permissions on a private repository. Scanner configuration or a workflow file is not a passing scan.

No automatic update or unattended image pull is enabled. Urgent security releases follow private triage, a regression test, candidate validation, verified signatures/advisory and explicit operator update. Keep a tested pre-upgrade backup and matching key for rollback.
