---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/semantic-release
title: Semantic release (semantic-release.yml)
description: "The Semantic release workflow, `.github/workflows/semantic-release.yml`: on a pull request to main it plans the release, and on a push to main it releases with semantic-release and dispatches the knowledge release."
genre: reference
resource: .github/workflows/semantic-release.yml
sources:
  - id: semantic-release.yml
    resource: .github/workflows/semantic-release.yml
    title: the header comment, the on key and the jobs
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Semantic release (semantic-release.yml)

`.github/workflows/semantic-release.yml` plans the release on each pull request to `main` and releases on each push to `main`. Both jobs install the tools pinned in `.github/release/package-lock.json` with `npm ci --ignore-scripts`, and both refuse to run without a `v*` tag. The release job runs in the `release` Environment, and dispatches the knowledge release once `KNOWLEDGE_RELEASE_ENABLED` is `true`.[^semantic-release.yml]

[^semantic-release.yml]: .github/workflows/semantic-release.yml, the header comment, the on key and the jobs
