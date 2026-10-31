---
type: Service
id: https://w3id.org/lmodel/stix/knowledge/workflows/lint-and-docs
title: Lint and docs (lint-and-docs.yaml)
description: "The Lint & docs workflow, `.github/workflows/lint-and-docs.yaml`: ShellCheck, actionlint, the word budgets of CONTRIBUTING.md and SECURITY.md, markdownlint, lychee and codespell, on pull requests, on main and every Monday."
genre: reference
resource: .github/workflows/lint-and-docs.yaml
sources:
  - id: lint-and-docs.yaml
    resource: .github/workflows/lint-and-docs.yaml
    title: the header comment, the on key and the jobs
  - resource: .markdownlint-cli2.jsonc
    title: the markdownlint settings
  - resource: lychee.toml
    title: the link check settings
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Lint and docs (lint-and-docs.yaml)

`.github/workflows/lint-and-docs.yaml` runs on a push to `main`, on every pull request, every Monday at 06:00 UTC and by hand. Its four jobs run ShellCheck over the scripts, actionlint over the workflows, a word count that holds `CONTRIBUTING.md` to 1,000 words and `SECURITY.md` to 900, and markdownlint, lychee and codespell over the Markdown.[^lint-and-docs.yaml]

[^lint-and-docs.yaml]: .github/workflows/lint-and-docs.yaml, the header comment, the on key and the jobs
