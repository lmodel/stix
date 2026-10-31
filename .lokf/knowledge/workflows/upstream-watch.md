---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/upstream-watch
title: Upstream watch (upstream-watch.yaml)
description: "The Upstream watch workflow, `.github/workflows/upstream-watch.yaml`: every Monday it runs `scripts/check_upstream_release.py`, and on a finding opens or updates one issue."
genre: reference
resource: .github/workflows/upstream-watch.yaml
sources:
  - id: upstream-watch.yaml
    resource: .github/workflows/upstream-watch.yaml
    title: the header comment, the on key and the jobs
  - resource: .github/scripts/report-issue.sh
    title: the issue it opens or updates
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Upstream watch (upstream-watch.yaml)

`.github/workflows/upstream-watch.yaml` runs every Monday at 07:00 UTC and by hand. It runs `scripts/check_upstream_release.py`, which compares `upstream/` with OASIS's repository and docs.oasis-open.org. When the check fails, `.github/scripts/report-issue.sh` opens an issue, or comments on the open one with the same title. Its one write scope is `issues: write`.[^upstream-watch.yaml]

[^upstream-watch.yaml]: .github/workflows/upstream-watch.yaml, the header comment, the on key and the jobs
