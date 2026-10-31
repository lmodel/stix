---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/knowledge-librarian
title: Knowledge Librarian (knowledge-librarian.yaml)
description: "The Knowledge Librarian workflow, `.github/workflows/knowledge-librarian.yaml`: every Monday it runs the ktl-librarian skill, pinned to KTL v0.59.0, with no write token, and opens a pull request with what changed; inert until `KNOWLEDGE_LIBRARIAN_ENABLED` is `true`."
genre: reference
resource: .github/workflows/knowledge-librarian.yaml
sources:
  - id: knowledge-librarian.yaml
    resource: .github/workflows/knowledge-librarian.yaml
    title: the header comment, the on key and the jobs
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Knowledge Librarian (knowledge-librarian.yaml)

`.github/workflows/knowledge-librarian.yaml` runs every Monday at 05:00 UTC and by hand, once `KNOWLEDGE_LIBRARIAN_ENABLED` is `true`. It installs the ktl-librarian skill at the pinned release, v0.59.0, and runs an agent in a job with no write token. A separate `publish` job, which runs no agent, applies the agent's patch to the bundle alone and opens a pull request for a person to review.[^knowledge-librarian.yaml]

[^knowledge-librarian.yaml]: .github/workflows/knowledge-librarian.yaml, the header comment, the on key and the jobs
