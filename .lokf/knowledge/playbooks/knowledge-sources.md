---
type: Playbook
id: https://w3id.org/lmodel/stix/knowledge/playbooks/knowledge-sources
title: Knowledge sources
description: "The map of where this bundle's knowledge comes from: each repository path the librarian reads, the classes it yields and how to re-check it, and the paths it leaves out on purpose, with the reason."
genre: how-to
resource: .
exclusions:
  - resource: .lokf/scripts
    reason: copies of the ktl-sidecar templates, which the weekly sync replaces and the sidecar documents
  - resource: .lokf/m365
    reason: the Copilot skill builder from the ktl-sidecar templates, documented there
  - resource: .lokf/lokf.yaml
    reason: LOKF's own schema, pinned beside the bundle and documented by LOKF
  - resource: uv.lock
    reason: the root lock, which Dependabot keeps current and holds no knowledge of its own
  - resource: .lokf/uv.lock
    reason: the sidecar's lock, which Dependabot keeps current
  - resource: examples
    reason: the template's output folder, which `just test` writes and git ignores apart from its README
  - resource: .copier-answers.yml
    reason: copier's record of the template's answers, which only copier reads
  - resource: .editorconfig
    reason: editor settings for whitespace, which hold no knowledge of the schema
  - resource: .gitignore
    reason: git's list of ignored paths, which holds no knowledge of the schema
sources:
  - resource: src/stix/schema
    title: the schema and its modules
  - resource: project
    title: the generated artefacts
  - resource: src/stix/datamodel
    title: the generated Python models
  - resource: docs
    title: the website's own pages
  - resource: upstream
    title: OASIS's JSON schemas and examples
  - resource: tests
    title: the tests, the examples, the neighbours' copies and UCO's term list
  - resource: scripts
    title: the upstream watch and the UCO term extractor
  - resource: .github/workflows
    title: the nine workflows
  - resource: .github
    title: the release tools, the issue and pull request templates and Dependabot
  - resource: website
    title: the knowledge website
  - resource: README.md
    title: what the schema models, its mappings and the KTL section
  - resource: CONTRIBUTING.md
    title: the contributor checklist
  - resource: SECURITY.md
    title: the security policy
  - resource: AI_COVENANT.md
    title: the AI covenant
  - resource: NOTICE
    title: the third-party notices
  - resource: LICENSE
    title: the Apache License 2.0
  - resource: CHANGELOG.md
    title: the changelog
  - resource: justfile
    title: the recipes
  - resource: project.justfile
    title: the lokf-adapt recipes
  - resource: .lokf/stix.yaml
    title: the adapt copy
  - resource: .releaserc.json
    title: the release rules
  - resource: .linkml/generators.yaml
    title: the generators' settings
  - resource: pyproject.toml
    title: the Python project, its dependencies and the spell-check settings
  - resource: src/stix/__init__.py
    title: the Python package's version lookup
  - resource: src/stix/_version.py
    title: the version the build writes
  - resource: src/README.md
    title: the description of the source folder
  - resource: .pre-commit-config.yaml
    title: the pre-commit hooks and the files they skip
  - resource: .yamllint.yaml
    title: the YAML lint settings
  - resource: llms.txt
    title: the pointer that tells agents to read the bundle first
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Knowledge sources

Each row names a path the librarian reads, what it holds, and the classes it yields. Re-check a row by reading the path at the current commit; `bash .lokf/scripts/knowledge-report.sh worklist` names the concepts whose sources moved.

| Path | Holds | Classes |
| --- | --- | --- |
| `src/stix/schema` | the schema and its modules | Dataset |
| `project` | the generated artefacts | Dataset |
| `src/stix/datamodel` | the generated Python models | Dataset |
| `docs` | the website's own pages | Explanation, Playbook |
| `upstream` | OASIS's JSON schemas and examples | Dataset, Reference |
| `tests` | the tests, the examples, the neighbours' copies and UCO's term list | Dataset |
| `scripts` | the upstream watch and the UCO term extractor | Playbook, Dataset |
| `.github/workflows` | the nine workflows | Service |
| `.github` | the release tools, the issue and pull request templates and Dependabot | Playbook, Policy |
| `website` | the knowledge website | Service |
| `README.md` | what the schema models, its mappings and the KTL section | Explanation |
| `CONTRIBUTING.md` | the contributor checklist | Playbook |
| `SECURITY.md` | the security policy | Policy |
| `AI_COVENANT.md` | the AI covenant | Policy |
| `NOTICE` | the third-party notices | Policy |
| `LICENSE` | the Apache License 2.0 | Policy |
| `CHANGELOG.md` | the changelog | Playbook |
| `justfile` | the recipes | Playbook |
| `project.justfile` | the lokf-adapt recipes | Dataset |
| `.lokf/stix.yaml` | the adapt copy | Dataset |
| `.releaserc.json` | the release rules | Playbook |
| `.linkml/generators.yaml` | the generators' settings | Dataset |
| `pyproject.toml` | the Python project, its dependencies and the spell-check settings | Dataset |
| `src/stix/__init__.py` | the Python package's version lookup | Dataset |
| `src/stix/_version.py` | the version the build writes | Dataset |
| `src/README.md` | the description of the source folder | Dataset |
| `.pre-commit-config.yaml` | the pre-commit hooks and the files they skip | Playbook |
| `.yamllint.yaml` | the YAML lint settings | Playbook |
| `llms.txt` | the pointer that tells agents to read the bundle first | Reference |

The paths under `exclusions` are left out on purpose, each with its reason.
