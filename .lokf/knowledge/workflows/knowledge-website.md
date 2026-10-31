---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/knowledge-website
title: Knowledge website (knowledge-website.yaml)
description: "The Knowledge website workflow, `.github/workflows/knowledge-website.yaml`: it builds and link-checks the site on every change to its inputs, and deploys it to GitHub Pages from main once `KNOWLEDGE_WEBSITE_ENABLED` is `true`."
genre: reference
resource: .github/workflows/knowledge-website.yaml
sources:
  - id: knowledge-website.yaml
    resource: .github/workflows/knowledge-website.yaml
    title: the header comment, the on key and the jobs
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Knowledge website (knowledge-website.yaml)

`.github/workflows/knowledge-website.yaml` builds the site on a pull request or a push that touches its inputs, such as `website/`, `.lokf/`, `docs/` or the README, and checks every link between its pages. Only its `deploy` job holds the Pages scopes, and it deploys from `main` once `KNOWLEDGE_WEBSITE_ENABLED` is `true`.[^knowledge-website.yaml]

[^knowledge-website.yaml]: .github/workflows/knowledge-website.yaml, the header comment, the on key and the jobs
