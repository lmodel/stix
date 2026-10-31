---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/knowledge-release
title: Knowledge Release (knowledge-release.yaml)
description: "The Knowledge Release workflow, `.github/workflows/knowledge-release.yaml`: on a published release, once `KNOWLEDGE_RELEASE_ENABLED` is `true`, it attaches the bundle, the Copilot skill and the schema copy `schema-<tag>-stix.yaml`, each with a checksum and an attestation."
genre: reference
resource: .github/workflows/knowledge-release.yaml
sources:
  - id: knowledge-release.yaml
    resource: .github/workflows/knowledge-release.yaml
    title: the header comment, the on key and the jobs
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Knowledge Release (knowledge-release.yaml)

`.github/workflows/knowledge-release.yaml` runs on each published release once `KNOWLEDGE_RELEASE_ENABLED` is `true`, or by hand for a tag. Its `pack` job compares the bundle and the domain schema with the last release that carries them. Its `attach` job, which runs no third-party packages, attaches the bundle zip, the Copilot skill zip and `.lokf/stix.yaml` as `schema-<tag>-stix.yaml`, each with its `.sha256` and a build-provenance attestation.[^knowledge-release.yaml]

[^knowledge-release.yaml]: .github/workflows/knowledge-release.yaml, the header comment, the on key and the jobs
