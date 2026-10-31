---
type: Playbook
id: https://w3id.org/lmodel/stix/knowledge/playbooks/release
title: Release
description: "How a release is made: entries under `## [Unreleased]` in CHANGELOG.md, a releasing commit type, and the merge to main, after which semantic-release tags the version and the knowledge release attaches `schema-<tag>-stix.yaml` and the bundle."
genre: how-to
resource: .releaserc.json
sources:
  - id: contributing.md
    resource: CONTRIBUTING.md
    title: the Releasing (maintainers) section
  - id: releaserc.json
    resource: .releaserc.json
    title: the plugins and release rules
  - resource: CHANGELOG.md
    title: the baseline note
  - resource: .github/release
    title: the release tools' manifest and lock
  - resource: .github/scripts/changelog-release.mjs
    title: the check, notes and promote commands
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Release

1. Write each behaviour change under `## [Unreleased]` in `CHANGELOG.md` as you go.[^contributing.md]
2. Give the change a releasing type: only `feat:`, `fix:`, `security:` and a breaking `!` start a release, and a squash merge takes the pull request's title.
3. Merge to `main`. `semantic-release.yml` promotes the changelog section, tags `vX.Y.Z` and publishes the GitHub release, with the tools pinned in `.github/release/package-lock.json`.[^releaserc.json]
4. Once `KNOWLEDGE_RELEASE_ENABLED` is `true`, the knowledge release attaches the bundle and `.lokf/stix.yaml` as `schema-<tag>-stix.yaml`, each with its `.sha256` and attestation.

The first release needs the signed `v0.0.0` baseline tag on `main`, so that it is 0.1.0; a breaking change bumps the minor version below 1.0.0.

[^contributing.md]: CONTRIBUTING.md, the Releasing (maintainers) section
[^releaserc.json]: .releaserc.json, the plugins and release rules
