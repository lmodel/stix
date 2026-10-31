---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/main
title: Build and test (main.yaml)
description: "The Build and test workflow, `.github/workflows/main.yaml`: on a push to main and on every pull request, it runs `just test` on Python 3.10 to 3.14, and on 3.13 also `just lint` and `just lokf-adapt-check`."
genre: reference
resource: .github/workflows/main.yaml
sources:
  - id: main.yaml
    resource: .github/workflows/main.yaml
    title: the header comment, the on key and the jobs
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Build and test (main.yaml)

`.github/workflows/main.yaml` runs on a push to `main` and on every pull request, with `contents: read`. Its `test` job installs `just` 1.47.0 and the project with `uv sync --locked --group dev`, and runs `just test` on Python 3.10, 3.11, 3.12, 3.13 and 3.14. On 3.13 it also runs `just lint`, and syncs the sidecar's environment to run `just lokf-adapt-check`, because the adapt copy is what the bundle validates against and the release attaches.[^main.yaml]

[^main.yaml]: .github/workflows/main.yaml, the header comment, the on key and the jobs
