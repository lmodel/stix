---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/knowledge-sync
title: Knowledge sync (knowledge-sync.yaml)
description: "The Knowledge sync workflow, `.github/workflows/knowledge-sync.yaml`: every Monday it checks whether a newer KTL release changes the sidecar's copies or the skills pin, and opens one pull request that moves them together."
genre: reference
resource: .github/workflows/knowledge-sync.yaml
sources:
  - id: knowledge-sync.yaml
    resource: .github/workflows/knowledge-sync.yaml
    title: the header comment, the on key and the jobs
  - resource: .github/PULL_REQUEST_TEMPLATE/knowledge-sync.md
    title: the pull request it opens
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Knowledge sync (knowledge-sync.yaml)

`.github/workflows/knowledge-sync.yaml` runs every Monday at 04:10 UTC and by hand. It compares the sidecar's copies and the librarian's skills pin with the newest release of the Knowledge Trust Ladder (KTL) skills, as the release's sync manifest lists them, and opens one pull request that moves them together. It needs `KNOWLEDGE_SYNC_TOKEN` in the `knowledge-sync` Environment to open the pull request.[^knowledge-sync.yaml]

[^knowledge-sync.yaml]: .github/workflows/knowledge-sync.yaml, the header comment, the on key and the jobs
