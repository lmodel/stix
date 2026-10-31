---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/knowledge-registrar
title: Knowledge Registrar (knowledge-registrar.yaml)
description: "The Knowledge Registrar workflow, `.github/workflows/knowledge-registrar.yaml`: the gate on every pull request that touches `.lokf/`, which validates the bundle, checks its references and conventions, and checks that each person's confirmation is backed by a review or a signed commit."
genre: reference
resource: .github/workflows/knowledge-registrar.yaml
sources:
  - id: knowledge-registrar.yaml
    resource: .github/workflows/knowledge-registrar.yaml
    title: the header comment, the on key and the jobs
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Knowledge Registrar (knowledge-registrar.yaml)

`.github/workflows/knowledge-registrar.yaml` runs on every pull request that touches `.lokf/`, `knowledge_bundle` or the workflow itself, every Monday at 06:00 UTC and by hand. It runs `lokf validate --check-refs` and the conventions script, and its `provenance` job checks that each new `human:` confirmation is backed by that person's approval or signed commit.[^knowledge-registrar.yaml]

[^knowledge-registrar.yaml]: .github/workflows/knowledge-registrar.yaml, the header comment, the on key and the jobs
